// NovaWAF 管理控制台（C++17/20 + Drogon）
// 取代原 Spring Boot 管理面：规则管理 / 日志查询 / RBAC 鉴权。
// 单二进制，与检测引擎共用同一份 Redis 数据源，规则热加载零跨进程 HTTP。
//
// 编译（Linux，依赖 ~/deps 下的 drogon/jsoncpp，系统 openssl）：
//   export PATH=$HOME/cmake-3.30.5-linux-x86_64/bin:$PATH
//   cmake -B build -DCMAKE_PREFIX_PATH=$HOME/deps && cmake --build build -j
//
// 运行：./build/novawaf-console  (默认 0.0.0.0:9000)
// 环境变量：CONSOLE_PORT / NOVA_REDIS_HOST / NOVA_REDIS_PORT / NOVA_REDIS_PASS
#include <drogon/drogon.h>
#include <json/json.h>

#include "novawaf/core/redis_client.h"

#include <openssl/evp.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace drogon;

// ---------------- Redis 单例（控制台所有读写走它） ----------------
struct RedisStore {
    std::mutex mtx;
    std::unique_ptr<novawaf::RedisClient> cli;
    std::string host = "127.0.0.1";
    int port = 6379;
    std::string pass;

    void init() {
        if (auto e = std::getenv("NOVA_REDIS_HOST")) host = e;
        if (auto e = std::getenv("NOVA_REDIS_PORT")) port = std::atoi(e);
        if (auto e = std::getenv("NOVA_REDIS_PASS")) pass = e;
    }
    novawaf::RedisClient* get() {
        std::lock_guard<std::mutex> lk(mtx);
        if (!cli || !cli->connected()) {
            cli = std::make_unique<novawaf::RedisClient>();
            if (!cli->connect(host, port, pass)) {
                cli.reset();
                return nullptr;
            }
        }
        return cli.get();
    }
};
static RedisStore g_store;

static Json::Value parseJson(const std::string& s) {
    Json::Value v;
    Json::CharReaderBuilder b;
    std::string errs;
    std::unique_ptr<Json::CharReader> r(b.newCharReader());
    if (!r->parse(s.data(), s.data() + s.size(), &v, &errs)) v = Json::Value(Json::arrayValue);
    return v;
}
static std::string dumpJson(const Json::Value& v) {
    Json::StreamWriterBuilder b;
    b["indentation"] = "";
    return Json::writeString(b, v);
}

// ---------------- 鉴权：HTTP Basic + 盐化 SHA-256 + RBAC ----------------
static std::string sha256Hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t n = 0;
    EVP_Q_digest(nullptr, "SHA256", nullptr, in.data(), in.size(), md, &n);
    static const char* hx = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < n; ++i) { out += hx[md[i] >> 4]; out += hx[md[i] & 0xF]; }
    return out;
}
struct User { std::string name; std::string saltHash; std::string role; };
// 密码 = sha256(salt + ":" + plain)。生产应改为数据库/配置文件加载，勿硬编码明文。
static std::vector<User> kUsers = {
    {"admin",   sha256Hex(std::string("s$a1") + ":Admin@2026"),    "ADMIN"},
    {"operator",sha256Hex(std::string("s$op") + ":Operator@2026"), "OPERATOR"},
    {"viewer",  sha256Hex(std::string("s$vw") + ":Viewer@2026"),   "VIEWER"},
};
static const std::vector<std::string> kSaltPrefix = {"s$a1", "s$op", "s$vw"};

static std::string b64decode(const std::string& s) {
    // 简易 base64 解码（Authorization Basic 用）
    std::string out;
    std::vector<int> tbl(256, -1);
    const char* cb = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i) tbl[(unsigned char)cb[i]] = i;
    int val = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int d = tbl[(unsigned char)c];
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((char)((val >> bits) & 0xFF)); }
    }
    return out;
}

// 返回 role（空串=未认证）
static std::string authenticate(const HttpRequestPtr& req) {
    auto hdr = req->getHeader("authorization");
    if (hdr.size() < 7 || hdr.substr(0, 6) != "Basic ") return "";
    std::string decoded = b64decode(hdr.substr(6));
    auto colon = decoded.find(':');
    if (colon == std::string::npos) return "";
    std::string user = decoded.substr(0, colon);
    std::string pwd = decoded.substr(colon + 1);
    for (size_t i = 0; i < kUsers.size(); ++i) {
        if (kUsers[i].name == user &&
            sha256Hex(kSaltPrefix[i] + ":" + pwd) == kUsers[i].saltHash) {
            return kUsers[i].role;
        }
    }
    return "";
}
static bool roleAllowed(const std::string& role, const std::vector<std::string>& allow) {
    for (auto& a : allow) if (a == role) return true;
    return false;
}
static HttpResponsePtr jsonResp(Json::Value&& body, HttpStatusCode code = k200OK) {
    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(code);
    resp->setContentTypeCode(CT_APPLICATION_JSON);
    resp->setBody(dumpJson(body));
    return resp;
}
static HttpResponsePtr needAuth() {
    auto r = jsonResp(Json::Value(Json::objectValue), k401Unauthorized);
    r->addHeader("WWW-Authenticate", R"(Basic realm="NovaWAF")");
    return r;
}
static HttpResponsePtr forbidden() {
    Json::Value m; m["error"] = "forbidden";
    return jsonResp(std::move(m), k403Forbidden);
}
static HttpResponsePtr htmlResp(const std::string& body, HttpStatusCode code = k200OK) {
    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(code);
    resp->setContentTypeCode(CT_TEXT_HTML);
    resp->setBody(body);
    return resp;
}

// 可视化大屏（自包含 HTML，零外部依赖，内联 Canvas 绘图）
static const std::string kDashboardHtml = R"NOVAHTML(<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NovaWAF 安全态势大屏</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b1020;color:#e6ecff;font-family:"Segoe UI",system-ui,sans-serif;padding:18px}
h1{font-size:22px;letter-spacing:2px;color:#7fd4ff}
.sub{color:#8a9bd6;font-size:12px;margin:4px 0 16px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{background:#121a33;border:1px solid #24325a;border-radius:8px;padding:14px}
.card h3{font-size:13px;color:#9fb4ff;margin-bottom:10px;font-weight:600}
.total{grid-column:span 3}
.total .num{font-size:46px;color:#ff6b6b;font-weight:700}
.total .lbl{font-size:12px;color:#8a9bd6}
.half{grid-column:span 6}
.third{grid-column:span 4}
canvas{width:100%;height:200px;display:block}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:5px 6px;text-align:left;border-bottom:1px solid #1f2a4a}
.bar{height:10px;background:#24325a;border-radius:5px;overflow:hidden}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#7fd4ff,#b388ff)}
.muted{color:#8a9bd6}
#evt{max-height:200px;overflow:auto}
</style>
</head>
<body>
<h1>NovaWAF 安全态势大屏</h1>
<div class="sub" id="updated">加载中…</div>
<div class="grid">
  <div class="card total"><h3>总拦截数</h3><div class="num" id="total">0</div><div class="lbl">累计攻击拦截</div></div>
  <div class="card half"><h3>近 1 小时拦截趋势（按分钟）</h3><canvas id="trend"></canvas></div>
  <div class="card half"><h3>攻击类型分布</h3><canvas id="cat"></canvas></div>
  <div class="card third"><h3>TOP 攻击源 IP</h3><div id="topips"></div></div>
  <div class="card third"><h3>威胁等级分布</h3><canvas id="sev"></canvas></div>
  <div class="card third"><h3>最近事件</h3><div id="evt" class="muted"></div></div>
</div>
<script>
function fetchJ(u){return fetch(u,{credentials:'same-origin'}).then(r=>r.json())}
function drawBars(canvas,obj){
  const d=Object.entries(obj||{}); const max=Math.max(1,...d.map(x=>x[1]));
  const ctx=canvas.getContext('2d'); const w=canvas.width=canvas.clientWidth; const h=canvas.height=200;
  ctx.clearRect(0,0,w,h); if(!d.length){ctx.fillStyle='#8a9bd6';ctx.fillText('暂无数据',10,20);return}
  const bw=w/d.length; ctx.font='11px sans-serif';
  d.forEach(([k,v],i)=>{
    const bh=(v/max)*(h-24); ctx.fillStyle='#7fd4ff';
    ctx.fillRect(i*bw+4,h-bh-16,bw-8,bh);
    ctx.fillStyle='#e6ecff'; ctx.fillText(String(v),i*bw+4,h-bh-20);
    ctx.fillStyle='#9fb4ff'; ctx.fillText(k.slice(0,8),i*bw+4,h-4);
  });
}
function drawLine(canvas,arr){
  const ctx=canvas.getContext('2d'); const w=canvas.width=canvas.clientWidth; const h=canvas.height=200;
  ctx.clearRect(0,0,w,h); if(!arr||!arr.length){ctx.fillStyle='#8a9bd6';ctx.fillText('暂无数据',10,20);return}
  const max=Math.max(1,...arr.map(p=>p.count));
  ctx.strokeStyle='#24325a'; for(let i=0;i<4;i++){const y=h*i/4;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  ctx.strokeStyle='#7CFC9B'; ctx.lineWidth=2; ctx.beginPath();
  arr.forEach((p,i)=>{const x=(arr.length<2?w:i*w/(arr.length-1));const y=h-(p.count/max)*(h-10)-5;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});
  ctx.stroke();
}
async function refresh(){
  try{
    const s=await fetchJ('/api/stats/summary');
    document.getElementById('total').textContent=s.total||0;
    document.getElementById('updated').textContent='更新于 '+new Date((s.updated||0)*1000).toLocaleString();
    drawLine(document.getElementById('trend'),s.timeseries||[]);
    drawBars(document.getElementById('cat'),s.byCategory||{});
    drawBars(document.getElementById('sev'),s.bySeverity||{});
    const tips=s.topIps||[]; let h='<table>';
    tips.forEach(p=>{h+='<tr><td>'+p.ip+'</td><td><div class="bar"><i style="width:'+Math.min(100,(p.count/Math.max(1,...tips.map(x=>x.count)))*100)+'%"></i></div></td><td>'+p.count+'</td></tr>'});
    h+='</table>'; document.getElementById('topips').innerHTML=h||'<span class=muted>暂无</span>';
    const ev=await fetchJ('/api/stats/events?limit=8'); let e='';
    (ev.events||[]).slice().reverse().forEach(x=>{e+='<div>['+new Date((x.ts||0)*1000).toLocaleTimeString()+'] '+x.category+' '+x.ip+' <span class=muted>'+(x.matched||'').slice(0,30)+'</span></div>'});
    document.getElementById('evt').innerHTML=e||'<span class=muted>暂无事件</span>';
  }catch(err){document.getElementById('updated').textContent='加载失败: '+err}
}
refresh(); setInterval(refresh,5000);
</script>
</body>
</html>)NOVAHTML";

// 流量分析大屏（自包含，零 CDN）：10 指标 + 应用/时间范围切换 + 自动刷新
static const std::string kTrafficHtml = R"TRAFFIC(<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NovaWAF 流量分析</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b1020;color:#e6ecff;font-family:"Segoe UI",system-ui,sans-serif;padding:18px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
h1{font-size:20px;letter-spacing:2px;color:#7fd4ff}
.ctl select{background:#121a33;color:#e6ecff;border:1px solid #24325a;border-radius:6px;padding:6px 10px;margin-left:8px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
.card{background:#121a33;border:1px solid #24325a;border-radius:8px;padding:12px}
.card .n{font-size:26px;font-weight:700;color:#7fd4ff}
.card .l{font-size:12px;color:#8a9bd6;margin-top:4px}
.sub{color:#8a9bd6;font-size:12px;margin:10px 0}
#err{color:#ff6b6b}
</style></head><body>
<div class="top"><h1>NovaWAF 流量分析</h1>
<div class="ctl">应用 <select id="appSel"><option value="all">全部应用</option></select>
范围 <select id="rangeSel"><option value="24h">近24小时</option><option value="7d">近7天</option><option value="30d">近30天</option></select></div></div>
<div class="sub" id="updated">加载中…</div>
<div class="grid">
<div class="card"><div class="n" id="m_req">-</div><div class="l">请求次数</div></div>
<div class="card"><div class="n" id="m_pv">-</div><div class="l">访问次数 PV</div></div>
<div class="card"><div class="n" id="m_uv">-</div><div class="l">独立访客 UV</div></div>
<div class="card"><div class="n" id="m_ip">-</div><div class="l">独立 IP</div></div>
<div class="card"><div class="n" id="m_blk">-</div><div class="l">拦截次数</div></div>
<div class="card"><div class="n" id="m_atk">-</div><div class="l">攻击 IP</div></div>
<div class="card"><div class="n" id="m_e4">-</div><div class="l">4xx 错误率</div></div>
<div class="card"><div class="n" id="m_b4">-</div><div class="l">4xx 拦截率</div></div>
<div class="card"><div class="n" id="m_e5">-</div><div class="l">5xx 错误率</div></div>
<div class="card"><div class="n" id="m_qps">-</div><div class="l">实时 QPS</div></div>
</div>
<script>
function J(u){return fetch(u,{credentials:'same-origin'}).then(r=>{if(!r.ok)throw new Error(r.status);return r.json()})}
function pct(x){return (x*100).toFixed(1)+'%'}
async function loadApps(){try{const a=await J('/api/apps');const s=document.getElementById('appSel');
a.forEach(x=>{const o=document.createElement('option');o.value=x.id;o.textContent=x.name+' ('+x.host+')';s.appendChild(o)});}catch(e){}}
async function refresh(){try{
const app=document.getElementById('appSel').value, rng=document.getElementById('rangeSel').value;
const d=await J('/api/traffic/metrics?app='+encodeURIComponent(app)+'&range='+rng);
document.getElementById('m_req').textContent=d.requests;
document.getElementById('m_pv').textContent=d.pv;
document.getElementById('m_uv').textContent=d.uv;
document.getElementById('m_ip').textContent=d.uniqueIp;
document.getElementById('m_blk').textContent=d.blocked;
document.getElementById('m_atk').textContent=d.attackIp;
document.getElementById('m_e4').textContent=pct(d.err4xxRate);
document.getElementById('m_b4').textContent=pct(d.block4xxRate);
document.getElementById('m_e5').textContent=pct(d.err5xxRate);
document.getElementById('m_qps').textContent=Math.round(d.qps);
document.getElementById('updated').textContent='更新于 '+new Date().toLocaleTimeString()+' · 应用='+app+' · 范围='+rng;
document.getElementById('updated').className='sub';
}catch(e){document.getElementById('updated').textContent='加载失败: '+e;document.getElementById('updated').className='sub';}}
loadApps();refresh();setInterval(refresh,5000);
document.getElementById('appSel').onchange=refresh;
document.getElementById('rangeSel').onchange=refresh;
</script></body></html>)TRAFFIC";

// IOC 威胁情报管理页（自包含，零 CDN）：列表 + 新增 + 删除 + 手动刷新
static const std::string kIocHtml = R"IOC(<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NovaWAF 威胁情报 IOC</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b1020;color:#e6ecff;font-family:"Segoe UI",system-ui,sans-serif;padding:18px}
h1{font-size:20px;letter-spacing:2px;color:#7fd4ff;margin-bottom:12px}
.bar{display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap}
.bar input,.bar select{background:#121a33;color:#e6ecff;border:1px solid #24325a;border-radius:6px;padding:6px 10px;font-size:13px}
button{background:#2a6df4;color:#fff;border:0;border-radius:6px;padding:7px 14px;font-size:13px;cursor:pointer}
button.ghost{background:#1b2547}
button.danger{background:#b03030;padding:3px 9px;font-size:12px}
.msg{font-size:13px;color:#8a9bd6;margin-left:6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #1c2746}
th{color:#8a9bd6;font-weight:600}
.bad{color:#ff8080}
</style></head><body>
<h1>NovaWAF 威胁情报 IOC</h1>
<div class="bar">
<select id="itype"><option value="ip">ip</option><option value="cidr">cidr</option><option value="path">path</option><option value="domain">domain</option><option value="ua">ua</option><option value="signature">signature</option></select>
<input id="ivalue" placeholder="value (如 1.2.3.4 或 1.2.3.0/24)" size="26">
<select id="isev"><option value="high">high</option><option value="critical">critical</option><option value="medium">medium</option><option value="low">low</option></select>
<input id="idesc" placeholder="描述（可选）" size="20">
<button onclick="addIoc()">新增</button>
<button class="ghost" onclick="load()">刷新</button>
<span class="msg" id="msg"></span>
</div>
<table><thead><tr><th>type</th><th>value</th><th>severity</th><th>category</th><th>desc</th><th></th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
function J(u,o){return fetch(u,Object.assign({credentials:'same-origin'},o||{})).then(r=>{if(!r.ok)throw new Error(r.status);return r.json()})}
async function load(){try{const a=await J('/api/ioc');const tb=document.getElementById('rows');tb.innerHTML='';
a.forEach(x=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${x.type}</td><td>${x.value}</td><td>${x.severity}</td><td>${x.category}</td><td>${x.desc||''}</td><td><button class="danger" onclick="del('${x.type}','${x.value}')">删除</button></td>`;tb.appendChild(tr)});
document.getElementById('msg').textContent='共 '+a.length+' 条 · '+new Date().toLocaleTimeString();}catch(e){document.getElementById('msg').textContent='加载失败: '+e;document.getElementById('msg').className='msg bad';}}
async function addIoc(){const body={type:document.getElementById('itype').value,value:document.getElementById('ivalue').value.trim(),severity:document.getElementById('isev').value,desc:document.getElementById('idesc').value};
if(!body.value){alert('value 不能为空');return}
try{const r=await J('/api/ioc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
if(r.ok){document.getElementById('ivalue').value='';document.getElementById('idesc').value='';load();}else alert('新增失败: '+(r.error||JSON.stringify(r)));}catch(e){alert('请求失败: '+e);}}
async function del(t,v){if(!confirm('删除 '+t+','+v+' ?'))return;try{await J('/api/ioc?type='+encodeURIComponent(t)+'&value='+encodeURIComponent(v),{method:'DELETE'});load();}catch(e){alert('删除失败: '+e);}}
load();
</script></body></html>)IOC";


// ---------------- 规则存储（novawaf:rules = JSON 数组；id 自增） ----------------
static const char* kRulesKey = "novawaf:rules";
static const char* kRulesIdKey = "novawaf:rules:seq";

// ---------------- 应用存储（novawaf:apps = JSON 数组；id 自增） ----------------
static const char* kAppsKey = "novawaf:apps";
static const char* kAppsIdKey = "novawaf:apps:seq";
static const char* kAppsVerKey = "novawaf:apps:version";

// ---------------- IOC 存储（novawaf:ioc = 每行 type,value,severity,category,desc） ----------------
static const char* kIocKey = "novawaf:ioc";
static const char* kIocMetaKey = "novawaf:meta";
static const char* kIocSeqKey = "novawaf:ioc:seq";

// ---- IOC blob <-> JSON 辅助（每行 type,value,severity,category,desc）----
static std::string iocTrim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) a++;
    while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}
static Json::Value parseIocBlob(const std::string& blob) {
    Json::Value arr(Json::arrayValue);
    size_t i = 0;
    while (i <= blob.size()) {
        size_t j = blob.find('\n', i);
        std::string line = (j == std::string::npos) ? blob.substr(i) : blob.substr(i, j - i);
        i = (j == std::string::npos) ? blob.size() + 1 : j + 1;
        std::string t = iocTrim(line);
        if (t.empty() || t[0] == '#') continue;
        std::vector<std::string> f; std::string cur;
        for (char c : line) { if (c == ',') { f.push_back(iocTrim(cur)); cur.clear(); } else cur += c; }
        f.push_back(iocTrim(cur));
        if (f.size() < 2 || f[0].empty() || f[1].empty()) continue;
        Json::Value o(Json::objectValue);
        o["type"] = f[0]; o["value"] = f[1];
        o["severity"] = f.size() >= 3 ? f[2] : "medium";
        o["category"] = f.size() >= 4 ? f[3] : "manual";
        o["desc"] = f.size() >= 5 ? f[4] : "";
        arr.append(o);
    }
    return arr;
}
static std::string iocLine(const Json::Value& o) {
    return o.get("type","").asString() + "," + o.get("value","").asString() + "," +
           o.get("severity","medium").asString() + "," + o.get("category","manual").asString() + "," +
           o.get("desc","").asString();
}
// 写回 blob 并 bump cksum（seq 自增作版本令牌，引擎按 cksum 变化热加载）
static bool writeIocBlob(novawaf::RedisClient* r, const Json::Value& arr) {
    std::string blob;
    for (auto& o : arr) { blob += iocLine(o); blob += "\n"; }
    if (!r->set(kIocKey, blob)) return false;
    auto seq = r->incr(kIocSeqKey).value_or(1);
    return r->hset(kIocMetaKey, "ioc_cksum", std::to_string(seq));
}

int main(int argc, char* argv[]) {
    g_store.init();
    int port = 9000;
    if (auto e = std::getenv("CONSOLE_PORT")) port = std::atoi(e);

    // 健康检查
    app().registerHandler("/",
        [](const HttpRequestPtr&, std::function<void(const HttpResponsePtr&)>&& cb) {
            Json::Value m; m["service"] = "novawaf-console"; m["status"] = "ok";
            m["lang"] = "c++/drogon";
            cb(jsonResp(std::move(m)));
        }, {Get});

    // 规则列表（所有角色可看）
    app().registerHandler("/api/rules",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            Json::Value arr(Json::arrayValue);
            if (auto* r = g_store.get()) {
                if (auto blob = r->get(kRulesKey)) arr = parseJson(*blob);
            }
            cb(jsonResp(std::move(arr)));
        }, {Get});

    // 新增规则（ADMIN/OPERATOR）
    app().registerHandler("/api/rules",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            auto json = req->getJsonObject();
            if (!json) { Json::Value m; m["error"]="invalid json"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kRulesKey).value_or("[]"));
                Json::Value rule = *json;
                auto id = r->incr(kRulesIdKey).value_or(1);
                rule["id"] = (Json::Int64)id;
                if (!rule.isMember("enabled")) rule["enabled"] = true;
                arr.append(rule);
                r->set(kRulesKey, dumpJson(arr));
                r->incr("novawaf:rules:version");  // 触发引擎热加载脏检查
                cb(jsonResp(std::move(rule), k201Created));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Post});

    // 更新 / 删除规则（同一路径模式合并注册，避免 Drogon 重复路径冲突；按方法分发）
    app().registerHandler("/api/rules/{1}",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb,
           const std::string& idStr) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            bool isDelete = (req->method() == Delete);
            // DELETE 仅 ADMIN；PUT 允许 ADMIN/OPERATOR
            if (isDelete) {
                if (!roleAllowed(role, {"ADMIN"})) { cb(forbidden()); return; }
            } else {
                if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            }
            long long id = std::atoll(idStr.c_str());
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kRulesKey).value_or("[]"));
                if (isDelete) {
                    Json::Value out(Json::arrayValue);
                    bool found = false;
                    for (auto& it : arr) {
                        if (it.get("id",0).asInt64() == id) found = true;
                        else out.append(it);
                    }
                    if (!found) { Json::Value m; m["error"]="not found"; cb(jsonResp(std::move(m),k404NotFound)); return; }
                    r->set(kRulesKey, dumpJson(out));
                    r->incr("novawaf:rules:version");
                    Json::Value ok; ok["ok"]=true; ok["deleted"]=(Json::Int64)id;
                    cb(jsonResp(std::move(ok)));
                    return;
                }
                // PUT
                auto json = req->getJsonObject();
                if (!json) { Json::Value m; m["error"]="invalid json"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
                bool found = false;
                for (auto& it : arr) {
                    if (it.get("id", 0).asInt64() == id) {
                        for (auto k : json->getMemberNames()) it[k] = (*json)[k];
                        it["id"] = (Json::Int64)id;
                        found = true; break;
                    }
                }
                if (!found) { Json::Value m; m["error"]="not found"; cb(jsonResp(std::move(m),k404NotFound)); return; }
                r->set(kRulesKey, dumpJson(arr));
                r->incr("novawaf:rules:version");
                Json::Value ok; ok["ok"]=true;
                cb(jsonResp(std::move(ok)));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Put, Delete});

    // 热加载：规则写 Redis 后，引擎后台线程按 cksum 自动拾取（此处 bump 版本号触发）
    app().registerHandler("/api/rules/reload",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            if (auto* r = g_store.get()) {
                auto v = r->incr("novawaf:rules:version").value_or(0);
                // 把规则全文也写到引擎会读的位置（若引擎侧接入规则热加载）
                Json::Value m; m["reloaded"]=true; m["version"]=(Json::Int64)v;
                cb(jsonResp(std::move(m)));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Post});

    // ===== 应用管理（novawaf:apps）：列表/新增/更新/删除，RBAC 鉴权，写后 bump version 触发热加载 =====
    // 应用列表（所有角色可看）
    app().registerHandler("/api/apps",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            Json::Value arr(Json::arrayValue);
            if (auto* r = g_store.get()) if (auto blob = r->get(kAppsKey)) arr = parseJson(*blob);
            cb(jsonResp(std::move(arr)));
        }, {Get});

    // 新增应用（ADMIN/OPERATOR）；statsEnabled 默认 false（按需启用）
    app().registerHandler("/api/apps",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            auto json = req->getJsonObject();
            if (!json) { Json::Value m; m["error"]="invalid json"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kAppsKey).value_or("[]"));
                Json::Value app = *json;
                app["id"] = (Json::Int64)r->incr(kAppsIdKey).value_or(1);
                if (!app.isMember("statsEnabled")) app["statsEnabled"] = false;
                if (!app.isMember("default")) app["default"] = false;
                if (!app.isMember("name")) app["name"] = app.get("host","").asString();
                arr.append(app);
                r->set(kAppsKey, dumpJson(arr));
                r->incr(kAppsVerKey);
                cb(jsonResp(std::move(app), k201Created));
                return;
            }
            Json::Value m; m["error"]="redis unavailable"; cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Post});

    // 更新 / 删除应用（按 id 分发）
    app().registerHandler("/api/apps/{1}",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb,
           const std::string& idStr) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            bool isDelete = (req->method() == Delete);
            if (isDelete) { if (!roleAllowed(role, {"ADMIN"})) { cb(forbidden()); return; } }
            else { if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; } }
            long long id = std::atoll(idStr.c_str());
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kAppsKey).value_or("[]"));
                if (isDelete) {
                    Json::Value out(Json::arrayValue); bool found=false;
                    for (auto& it : arr) if (it.get("id",0).asInt64()==id) found=true; else out.append(it);
                    if (!found) { Json::Value m; m["error"]="not found"; cb(jsonResp(std::move(m),k404NotFound)); return; }
                    r->set(kAppsKey, dumpJson(out)); r->incr(kAppsVerKey);
                    Json::Value ok; ok["ok"]=true; ok["deleted"]=(Json::Int64)id; cb(jsonResp(std::move(ok))); return;
                }
                auto json = req->getJsonObject();
                if (!json) { Json::Value m; m["error"]="invalid json"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
                bool found=false;
                for (auto& it : arr) if (it.get("id",0).asInt64()==id) {
                    for (auto k : json->getMemberNames()) it[k] = (*json)[k];
                    it["id"]=(Json::Int64)id; found=true; break;
                }
                if (!found) { Json::Value m; m["error"]="not found"; cb(jsonResp(std::move(m),k404NotFound)); return; }
                r->set(kAppsKey, dumpJson(arr)); r->incr(kAppsVerKey);
                Json::Value ok; ok["ok"]=true; cb(jsonResp(std::move(ok))); return;
            }
            Json::Value m; m["error"]="redis unavailable"; cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Put, Delete});

    // 日志查询（分页）：引擎把命中日志写 novawaf:logs（JSON 数组），此处读取分页
    app().registerHandler("/api/logs",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            int page = req->getOptionalParameter<int>("page").value_or(0);
            int size = req->getOptionalParameter<int>("size").value_or(50);
            if (size > 500) size = 500;
            Json::Value arr(Json::arrayValue);
            if (auto* r = g_store.get())
                arr = parseJson(r->get("novawaf:logs").value_or("[]"));
            Json::Value resp(Json::objectValue);
            resp["total"] = (Json::Int64)arr.size();
            resp["page"] = page;
            resp["size"] = size;
            Json::Value items(Json::arrayValue);
            int start = page * size;
            for (int i = start; i < start + size && i < (int)arr.size(); ++i) items.append(arr[i]);
            resp["items"] = items;
            cb(jsonResp(std::move(resp)));
        }, {Get});

    // ---------------- 态势统计 API（数据来自引擎写入的 novawaf:stats 快照） ----------------
    auto loadSnapshot = []() -> Json::Value {
        Json::Value def(Json::objectValue);
        def["total"] = (Json::Int64)0;
        def["updated"] = (Json::Int64)0;
        def["byCategory"] = Json::Value(Json::objectValue);
        def["bySeverity"] = Json::Value(Json::objectValue);
        def["topIps"] = Json::Value(Json::arrayValue);
        def["timeseries"] = Json::Value(Json::arrayValue);
        if (auto* r = g_store.get()) {
            if (auto blob = r->get("novawaf:stats")) {
                Json::Value v = parseJson(*blob);
                if (v.isObject()) return v;
            }
        }
        return def;
    };
    auto statsGuard = [](const HttpRequestPtr& req,
                         std::function<void(const HttpResponsePtr&)>& cb) -> bool {
        std::string role = authenticate(req);
        if (role.empty()) { cb(needAuth()); return false; }
        if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return false; }
        return true;
    };

    app().registerHandler("/api/stats/summary",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            cb(jsonResp(loadSnapshot()));
        }, {Get});

    app().registerHandler("/api/stats/timeseries",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            Json::Value m(Json::objectValue);
            m["timeseries"] = loadSnapshot()["timeseries"];
            cb(jsonResp(std::move(m)));
        }, {Get});

    app().registerHandler("/api/stats/by-category",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            Json::Value m(Json::objectValue);
            m["byCategory"] = loadSnapshot()["byCategory"];
            cb(jsonResp(std::move(m)));
        }, {Get});

    app().registerHandler("/api/stats/by-severity",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            Json::Value m(Json::objectValue);
            m["bySeverity"] = loadSnapshot()["bySeverity"];
            cb(jsonResp(std::move(m)));
        }, {Get});

    app().registerHandler("/api/stats/top-ips",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            Json::Value m(Json::objectValue);
            m["topIps"] = loadSnapshot()["topIps"];
            cb(jsonResp(std::move(m)));
        }, {Get});

    app().registerHandler("/api/stats/events",
        [=](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            if (!statsGuard(req, cb)) return;
            int limit = req->getOptionalParameter<int>("limit").value_or(50);
            if (limit > 200) limit = 200;
            if (limit < 1) limit = 1;
            Json::Value arr(Json::arrayValue);
            if (auto* r = g_store.get()) {
                if (auto els = r->lrange("novawaf:events", -(int64_t)limit, -1)) {
                    for (auto& s : *els) {
                        Json::Value ev = parseJson(s);
                        arr.append(ev.isObject() ? ev : Json::Value(s));
                    }
                }
            }
            Json::Value m(Json::objectValue);
            m["events"] = arr;
            cb(jsonResp(std::move(m)));
        }, {Get});

    // ===== IOC 威胁情报管理（增删查改，写回 novawaf:ioc 并 bump cksum 触发热加载）=====
    app().registerHandler("/api/ioc",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            Json::Value arr(Json::arrayValue);
            if (auto* r = g_store.get()) if (auto blob = r->get(kIocKey)) arr = parseIocBlob(*blob);
            cb(jsonResp(std::move(arr)));
        }, {Get});
    app().registerHandler("/api/ioc",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            auto json = req->getJsonObject();
            if (!json || !json->isMember("type") || !json->isMember("value")) {
                Json::Value m; m["error"]="type and value required"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
            if (auto* r = g_store.get()) {
                Json::Value arr = parseIocBlob(r->get(kIocKey).value_or(""));
                std::string t = (*json)["type"].asString(), v = (*json)["value"].asString();
                bool dup = false;
                for (auto& o : arr) if (o["type"].asString() == t && o["value"].asString() == v) { dup = true; break; }
                Json::Value resp(Json::objectValue);
                if (dup) { resp["ok"] = false; resp["error"] = "duplicate"; }
                else {
                    Json::Value o = *json;
                    if (!o.isMember("severity")) o["severity"] = "high";
                    if (!o.isMember("category")) o["category"] = "manual";
                    if (!o.isMember("desc")) o["desc"] = "";
                    arr.append(o);
                    resp["ok"] = writeIocBlob(r, arr);
                }
                cb(jsonResp(std::move(resp)));
            }
        }, {Post});
    app().registerHandler("/api/ioc",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            std::string t = req->getOptionalParameter<std::string>("type").value_or("");
            std::string v = req->getOptionalParameter<std::string>("value").value_or("");
            Json::Value resp(Json::objectValue);
            if (t.empty() || v.empty()) { resp["ok"]=false; resp["error"]="type and value required"; cb(jsonResp(std::move(resp),k400BadRequest)); return; }
            if (auto* r = g_store.get()) {
                Json::Value arr = parseIocBlob(r->get(kIocKey).value_or(""));
                Json::Value kept(Json::arrayValue);
                for (auto& o : arr) if (!(o["type"].asString() == t && o["value"].asString() == v)) kept.append(o);
                resp["ok"] = writeIocBlob(r, kept);
                cb(jsonResp(std::move(resp)));
            }
        }, {Delete});

    // ===== 流量分析查询：按应用 + 时间范围聚合 10 指标 =====
    app().registerHandler("/api/traffic/metrics",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            std::string appSel = req->getOptionalParameter<std::string>("app").value_or("all");
            std::string range = req->getOptionalParameter<std::string>("range").value_or("24h");
            int rangeMin = (range == "30d") ? 43200 : (range == "7d") ? 10080 : 1440;
            int64_t nowMin = (int64_t)std::time(nullptr) / 60;
            int64_t since = nowMin - rangeMin;

            // 解析应用 id 列表
            std::vector<std::string> appIds;
            if (auto* r = g_store.get()) {
                Json::Value apps = parseJson(r->get(kAppsKey).value_or("[]"));
                for (auto& a : apps) {
                    std::string id = a.get("id","").isString() ? a["id"].asString()
                                     : std::to_string(a.get("id",0).asInt64());
                    if (appSel == "all" || appSel == id) appIds.push_back(id);
                }
            }
            if (appSel != "all" && appIds.empty()) appIds.push_back(appSel);

            uint64_t reqS=0, pv=0, blk=0, a4=0, a5=0; double qps=0;
            std::unordered_map<std::string,char> uvSet, ipSet, atkSet;
            auto mergeBucket = [&](const Json::Value& b){
                if (!b.isObject()) return;
                int64_t t = b.get("t",0).asInt64();
                if (t < since) return;
                reqS += b.get("req",0).asUInt64();
                pv   += b.get("pv",0).asUInt64();
                blk  += b.get("blk",0).asUInt64();
                a4   += b.get("a4",0).asUInt64();
                a5   += b.get("a5",0).asUInt64();
                for (auto& s : b["sess"]) uvSet[s.asString()]=1;
                for (auto& s : b["ip"]) ipSet[s.asString()]=1;
                for (auto& s : b["atk"]) atkSet[s.asString()]=1;
            };
            if (auto* r = g_store.get()) {
                for (auto& id : appIds) {
                    if (auto els = r->lrange("novawaf:traffic:" + id, -(int64_t)44640, -1))
                        for (auto& s : *els) mergeBucket(parseJson(s));
                    if (auto st = r->get("novawaf:traffic:stat:" + id)) {
                        Json::Value v = parseJson(*st);
                        qps += v.get("qps",0).asDouble();
                        if (v.isMember("cur")) mergeBucket(v["cur"]);
                    }
                }
            }
            Json::Value m(Json::objectValue);
            m["app"] = appSel; m["range"] = range;
            m["requests"] = (Json::UInt64)reqS;
            m["pv"] = (Json::UInt64)pv;
            m["uv"] = (Json::UInt64)uvSet.size();
            m["uniqueIp"] = (Json::UInt64)ipSet.size();
            m["blocked"] = (Json::UInt64)blk;
            m["attackIp"] = (Json::UInt64)atkSet.size();
            double tot = reqS > 0 ? (double)reqS : 1.0;
            m["err4xxRate"] = a4 / tot;
            m["block4xxRate"] = a4 / tot;
            m["err5xxRate"] = a5 / tot;
            m["qps"] = qps;
            cb(jsonResp(std::move(m)));
        }, {Get});

    // 可视化大屏页面（自包含 HTML，需鉴权）
    app().registerHandler("/dashboard",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            cb(htmlResp(kDashboardHtml));
        }, {Get});

    // 流量分析大屏页面（自包含 HTML，需鉴权）
    app().registerHandler("/traffic",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            cb(htmlResp(kTrafficHtml));
        }, {Get});

    // IOC 威胁情报管理页面（自包含 HTML，需鉴权）
    app().registerHandler("/ioc",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            cb(htmlResp(kIocHtml));
        }, {Get});


    app().addListener("0.0.0.0", port);
    app().run();
    return 0;
}
