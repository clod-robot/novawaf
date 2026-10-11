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
                cb(jsonResp(std::move(rule), k201Created));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Post});

    // 更新规则
    app().registerHandler("/api/rules/([0-9]+)",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb,
           const std::string& idStr) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN","OPERATOR"})) { cb(forbidden()); return; }
            long long id = std::atoll(idStr.c_str());
            auto json = req->getJsonObject();
            if (!json) { Json::Value m; m["error"]="invalid json"; cb(jsonResp(std::move(m),k400BadRequest)); return; }
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kRulesKey).value_or("[]"));
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
                Json::Value ok; ok["ok"]=true;
                cb(jsonResp(std::move(ok)));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Put});

    // 删除规则（仅 ADMIN）
    app().registerHandler("/api/rules/([0-9]+)",
        [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb,
           const std::string& idStr) {
            std::string role = authenticate(req);
            if (role.empty()) { cb(needAuth()); return; }
            if (!roleAllowed(role, {"ADMIN"})) { cb(forbidden()); return; }
            long long id = std::atoll(idStr.c_str());
            if (auto* r = g_store.get()) {
                Json::Value arr = parseJson(r->get(kRulesKey).value_or("[]"));
                Json::Value out(Json::arrayValue);
                for (auto& it : arr) if (it.get("id",0).asInt64() != id) out.append(it);
                r->set(kRulesKey, dumpJson(out));
                Json::Value ok; ok["ok"]=true;
                cb(jsonResp(std::move(ok)));
                return;
            }
            Json::Value m; m["error"]="redis unavailable";
            cb(jsonResp(std::move(m), k503ServiceUnavailable));
        }, {Delete});

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

    LOG_INFO << "NovaWAF console (C++/Drogon) starting on port " << port;
    app().addListener("0.0.0.0", port);
    app().run();
    return 0;
}
