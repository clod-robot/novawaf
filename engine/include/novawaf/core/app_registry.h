// NovaWAF 应用（站点）注册表：从 Redis novawaf:apps (JSON 数组) 解析，
// copy-on-write 原子替换，reactor 线程无锁读。引擎无第三方 JSON 依赖，
// 这里内置一个针对固定结构的极简解析器。
#pragma once
#include <atomic>
#include <cctype>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace novawaf {

struct App {
    std::string id;
    std::string name;
    std::string host;          // 匹配的 Host 头（精确，忽略大小写）
    std::string upstreamHost;
    int         upstreamPort = 0;
    bool        isDefault    = false;
    bool        statsEnabled = false;
    // 运行模式：0=防护(拦截) 1=观察(只记录不拦截) 2=维护(全员维护页)
    int         mode         = 0;
    inline bool isObserve() const { return mode == 1; }
    inline bool isMaintenance() const { return mode == 2; }
};

using AppTable = std::vector<App>;

namespace app_reg {

inline std::mutex& mtx() { static std::mutex m; return m; }
inline std::shared_ptr<const AppTable>& store() {
    static std::shared_ptr<const AppTable> s = std::make_shared<const AppTable>();
    return s;
}

inline std::shared_ptr<const AppTable> current() {
    std::lock_guard<std::mutex> lk(mtx());
    return store();
}
inline void set(std::shared_ptr<const AppTable> t) {
    std::lock_guard<std::mutex> lk(mtx());
    store() = std::move(t);
}

// 按 Host 选应用：精确匹配优先，否则默认应用，再否则 nullptr
inline const App* select(const AppTable& apps, const std::string& host) {
    std::string lh = host; for (auto& c : lh) c = (char)tolower((unsigned char)c);
    const App* def = nullptr;
    for (auto& a : apps) {
        if (a.isDefault) def = &a;
        std::string ah = a.host; for (auto& c : ah) c = (char)tolower((unsigned char)c);
        if (!ah.empty() && ah == lh) return &a;
    }
    return def;
}

// ---- 极简 JSON 解析（仅支持本结构：数组 + 对象 + 字符串/数字/bool）----
inline void skipWs(const std::string& s, size_t& i) {
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
}
inline std::string parseStr(const std::string& s, size_t& i) {
    std::string out;
    if (i >= s.size() || s[i] != '"') return out;
    ++i;
    while (i < s.size() && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < s.size()) { ++i; char c = s[i];
            switch (c) { case 'n': out += '\n'; break; case 't': out += '\t'; break;
                case 'r': out += '\r'; break; case '"': out += '"'; break;
                case '\\': out += '\\'; break; case '/': out += '/'; break;
                default: out += c; } ++i;
        } else { out += s[i++]; }
    }
    if (i < s.size()) ++i; // closing quote
    return out;
}
// 解析一个值，写入对应字段（由 key 决定）
inline void applyField(App& a, const std::string& key, const std::string& s, size_t& i) {
    skipWs(s, i);
    if (i < s.size() && s[i] == '"') {
        std::string v = parseStr(s, i);
        if (key == "id") a.id = v; else if (key == "name") a.name = v;
        else if (key == "host") a.host = v; else if (key == "upstreamHost") a.upstreamHost = v;
        else if (key == "mode") a.mode = (v == "observe") ? 1 : (v == "maintenance" ? 2 : 0);
    } else if (i < s.size() && (s[i] == 't' || s[i] == 'f')) {
        bool v = (s[i] == 't');
        i += v ? 4 : 5; // true / false
        if (key == "default") a.isDefault = v; else if (key == "statsEnabled") a.statsEnabled = v;
    } else { // number
        size_t st = i; while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '-')) ++i;
        long long v = atoll(s.substr(st, i - st).c_str());
        if (key == "upstreamPort") a.upstreamPort = (int)v;
        else if (key == "id") a.id = s.substr(st, i - st);  // 控制台以 Int64 写 id
    }
}
inline AppTable parseApps(const std::string& json) {
    AppTable out;
    size_t i = 0; skipWs(json, i);
    if (i >= json.size() || json[i] != '[') return out;
    ++i;
    while (i < json.size()) {
        skipWs(json, i);
        if (json[i] == ']') break;
        if (json[i] == ',') { ++i; continue; }
        if (json[i] != '{') { ++i; continue; }
        ++i;
        App a;
        while (i < json.size() && json[i] != '}') {
            skipWs(json, i);
            if (json[i] == ',') { ++i; continue; }
            if (json[i] != '"') { ++i; continue; }
            std::string key = parseStr(json, i);
            skipWs(json, i);
            if (i < json.size() && json[i] == ':') ++i;
            applyField(a, key, json, i);
        }
        if (i < json.size()) ++i; // }
        if (!a.upstreamHost.empty() && a.upstreamPort > 0) out.push_back(std::move(a));
    }
    return out;
}

} // namespace app_reg
} // namespace novawaf
