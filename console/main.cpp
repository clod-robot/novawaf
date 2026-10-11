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


// ---------------- 规则存储（novawaf:rules = JSON 数组；id 自增） ----------------
static const char* kRulesKey = "novawaf:rules";
static const char* kRulesIdKey = "novawaf:rules:seq";

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

    // 可视化大屏页面（自包含 HTML，需鉴权）
    app().registerHandler("/dashboard",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR","VIEWER"})) { cb(forbidden()); return; }
            cb(htmlResp(kDashboardHtml));
        }, {Get});


    app().addListener("0.0.0.0", port);
    app().run();
    return 0;
}
