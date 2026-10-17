// NovaWAF - 网页防篡改缓存（页面基线学习 + 篡改自动恢复）
// 设计：
//   * 仅缓存 GET + 200 + text/html + 未压缩(无 Content-Encoding) + 非 chunked 的响应，
//     以 host|path 为键保存「基线响应字节」（LRU，容量/单页上限/TTL 可配）。
//   * 转发路径在回写客户端前调用 process()：
//       - 无基线     → 学习（假设首次观测为正常页面），放行原响应；
//       - 与基线一致 → 放行；
//       - 不一致     → 判定篡改：返回基线响应字节保障对外展示合规，并上报告警事件
//                      （category=Tamper, action=restore, severity=high）；
//       - TTL 过期   → 以当前响应重学基线（覆盖页面正常更新场景），放行。
//   * 篡改恢复绝不覆盖基线，杜绝攻击者用篡改页面投毒缓存。
//   * 后台同步线程（仅 Linux 构建启用 Redis；Windows 仅保留内存逻辑供单元测试）：
//       - 5s 周期：热加载配置(novawaf:tamper:config + :cfgver 版本脏检查)、
//         排空管理端 purge 列表(novawaf:tamper:purge，按页面 id 或 "all")、
//         把脏基线持久化(novawaf:tamper:page:<id>，base64)、
//         重写索引(novawaf:tamper:index)、上报统计(novawaf:tamper:stats)；
//       - 启动时从索引恢复基线，引擎重启不丢。
//   * 配置来源：env NOVA_TAMPER_PROTECT=1 启用默认配置（保护全部静态 HTML）；
//     Redis 配置下发后覆盖。JSON: {"enabled":true,"ttl":3600,"maxBody":262144,
//     "maxPages":256,"prefixes":["/","/news"]}，prefixes 为空表示不限制路径。
//   * 已知边界：chunked/压缩响应字节级比较有歧义，不参与（建议源站对保护页面
//     输出 identity）；动态页面应通过 prefixes 排除，避免误报。
//   * 线程安全：std::mutex 保护全部状态；事件回调在锁外触发。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "novawaf/core/json.h"

#ifndef _WIN32
#include "novawaf/core/event_sink.h"
#include "novawaf/core/redis_client.h"
#endif

namespace novawaf {

class TamperCache {
public:
    struct Config {
        bool enabled = false;                 // 总开关（默认关，需显式启用）
        int ttlSec = 3600;                    // 基线 TTL（秒），过期以当前响应重学；0 = 每次重学
        size_t maxBody = 256 * 1024;          // 单页最大缓存字节
        size_t maxPages = 256;                // LRU 页面容量
        std::vector<std::string> prefixes;    // 保护路径前缀（空 = 不限制）
    };

    static TamperCache& instance() {
        static TamperCache inst;
        return inst;
    }

    // ---- base64（自包含精确往返，供持久化与测试）----
    static std::string b64Encode(const std::string& in) {
        static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o;
        o.reserve((in.size() + 2) / 3 * 4);
        for (size_t i = 0; i < in.size(); i += 3) {
            unsigned v = (unsigned char)in[i] << 16;
            if (i + 1 < in.size()) v |= (unsigned char)in[i + 1] << 8;
            if (i + 2 < in.size()) v |= (unsigned char)in[i + 2];
            o += T[(v >> 18) & 63];
            o += T[(v >> 12) & 63];
            o += (i + 1 < in.size()) ? T[(v >> 6) & 63] : '=';
            o += (i + 2 < in.size()) ? T[v & 63] : '=';
        }
        return o;
    }
    static std::string b64Decode(const std::string& in) {
        auto dec = [](unsigned char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        std::string o;
        o.reserve(in.size() / 4 * 3);
        unsigned v = 0;
        int n = 0;
        for (char ch : in) {
            if (ch == '=') break;                 // 填充结束
            int d = dec((unsigned char)ch);
            if (d < 0) continue;                  // 跳过空白等杂散字符
            v = (v << 6) | (unsigned)d;
            n += 6;
            if (n >= 8) {
                n -= 8;
                o += (char)((v >> n) & 0xFF);
            }
        }
        return o;
    }

    // 页面 id：fnv1a64(host|path) 的 16 位 hex（管理端索引/删除用）
    static std::string pageId(const std::string& host, const std::string& path) {
        return fnvHex(host + "|" + path);
    }

    void configure(const Config& c) {
        std::lock_guard<std::mutex> lk(mu_);
        cfg_ = c;
        if (cfg_.ttlSec < 0) cfg_.ttlSec = 0;
        if (cfg_.maxPages == 0) cfg_.maxPages = 1;
        if (cfg_.maxBody == 0) cfg_.maxBody = 1024;
    }
    Config config() const {
        std::lock_guard<std::mutex> lk(mu_);
        return cfg_;
    }

    // 测试钩子：篡改事件回调 (clientIp, host, path)。为空则走默认事件通道。
    void setEventHook(
        std::function<void(const std::string&, const std::string&, const std::string&)> h) {
        std::lock_guard<std::mutex> lk(mu_);
        hook_ = std::move(h);
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        entries_.clear();
        lru_.clear();
    }
    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return entries_.size();
    }

    uint64_t learnedCount()  const { return learned_.load(); }
    uint64_t restoredCount() const { return restored_.load(); }
    uint64_t passedCount()   const { return passed_.load(); }

    // 热路径入口：返回基线响应字节表示判定篡改（调用方用它替换原响应）；nullopt 放行。
    std::optional<std::string> process(const std::string& method, const std::string& host,
                                       const std::string& path, const std::string& resp,
                                       const std::string& clientIp) {
        Config c;
        { std::lock_guard<std::mutex> lk(mu_); c = cfg_; }
        if (!c.enabled || method != "GET") return std::nullopt;
        if (!c.prefixes.empty()) {
            bool m = false;
            for (auto& p : c.prefixes)
                if (path.size() >= p.size() && path.compare(0, p.size(), p) == 0) { m = true; break; }
            if (!m) return std::nullopt;
        }
        size_t he = resp.find("\r\n\r\n");
        if (he == std::string::npos) return std::nullopt;
        std::string head = resp.substr(0, he);
        size_t sp = head.find(' ');
        if (sp == std::string::npos || head.compare(sp + 1, 3, "200") != 0) return std::nullopt;
        std::string low = head;
        for (auto& ch : low) ch = (char)tolower((unsigned char)ch);
        // 仅 text/html
        size_t ct = low.find("\ncontent-type:");
        if (ct == std::string::npos) return std::nullopt;
        size_t ctEol = low.find('\r', ct);
        std::string ctLine =
            low.substr(ct, ctEol == std::string::npos ? std::string::npos : ctEol - ct);
        if (ctLine.find("text/html") == std::string::npos) return std::nullopt;
        // chunked / 压缩响应字节比较有歧义，跳过
        if (low.find("\ntransfer-encoding:") != std::string::npos) return std::nullopt;
        if (low.find("\ncontent-encoding:") != std::string::npos) return std::nullopt;

        std::string body = resp.substr(he + 4);
        if (body.empty() || body.size() > c.maxBody) return std::nullopt;

        const std::string key = host + "|" + path;
        const int64_t now = (int64_t)std::time(nullptr);
        std::optional<std::string> out;
        bool tampered = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = entries_.find(key);
            if (it != entries_.end() && now - it->second.learnedAt < c.ttlSec) {
                if (it->second.body == body) {
                    touch(it);  // LRU 提升
                    ++passed_;
                    return std::nullopt;
                }
                out = it->second.respBytes;  // 篡改：恢复基线（绝不覆盖）
                touch(it);
                ++restored_;
                tampered = true;
            } else {
                // 学习 / 过期重学（当前响应视为新基线）
                Entry e;
                e.body = body;
                e.respBytes = resp;
                e.learnedAt = now;
                e.dirty = true;
                if (it != entries_.end()) {
                    lru_.erase(it->second.it);
                    entries_.erase(it);
                }
                lru_.push_front(key);
                e.it = lru_.begin();
                entries_[key] = std::move(e);
                while (entries_.size() > c.maxPages) {
                    entries_.erase(lru_.back());
                    lru_.pop_back();
                }
                ++learned_;
            }
        }
        if (tampered) emitTamper(clientIp, host, path);
        return out;
    }

    // 后台同步线程：Redis 配置热加载 + 基线持久化/恢复（仅 Linux 构建生效）
    void start() {
#ifndef _WIN32
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;
        const char* e = std::getenv("NOVA_TAMPER_PROTECT");
        if (e && (*e == '1' || *e == 't' || *e == 'T' || *e == 'y' || *e == 'Y')) {
            Config c;
            c.enabled = true;
            configure(c);
        }
        loadFromRedis();  // 恢复基线 + 拉取已下发配置（尽力而为）
        th_ = std::thread([this] { loop(); });
#endif
    }
    void stop() {
#ifndef _WIN32
        running_.store(false);
        if (th_.joinable()) th_.join();
#endif
    }

private:
    TamperCache() = default;
    TamperCache(const TamperCache&) = delete;
    TamperCache& operator=(const TamperCache&) = delete;

    struct Entry {
        std::string body;        // 基线 body（比对用）
        std::string respBytes;   // 基线完整响应字节（恢复用）
        int64_t learnedAt = 0;
        bool dirty = false;      // 待持久化
        std::list<std::string>::iterator it;  // LRU 位置
    };

    static uint64_t fnv1a(const std::string& s) {
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        return h;
    }
    static std::string fnvHex(const std::string& s) {
        char buf[17];
        std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)fnv1a(s));
        return buf;
    }

    void touch(std::unordered_map<std::string, Entry>::iterator it) {  // mu_ 已持
        lru_.erase(it->second.it);
        lru_.push_front(it->first);
        it->second.it = lru_.begin();
    }

    void emitTamper(const std::string& ip, const std::string& host, const std::string& path) {
        std::function<void(const std::string&, const std::string&, const std::string&)> h;
        { std::lock_guard<std::mutex> lk(mu_); h = hook_; }
        if (h) {
            h(ip, host, path);
            return;
        }
#ifndef _WIN32
        AttackEvent e;
        e.ts = (int64_t)std::time(nullptr);
        e.ip = ip;
        e.category = "Tamper";
        e.action = "restore";
        e.ruleId = "TAMPER-01";
        e.matched = host + path;
        e.severity = "high";
        EventSink::instance().emit(std::move(e));
#endif
    }

    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 2);
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        o += buf;
                    } else {
                        o += c;
                    }
            }
        }
        return o;
    }

    // 应用 Redis 下发的 JSON 配置（缺省字段保持当前值）
    bool applyConfigJson(const std::string& s) {
        try {
            auto j = parseJson(s);
            Config c = config();
            if (j.has("enabled") && j.at("enabled").isBool()) c.enabled = j.at("enabled").b;
            if (j.has("ttl") && j.at("ttl").isNumber()) c.ttlSec = (int)j.at("ttl").num;
            if (j.has("maxBody") && j.at("maxBody").isNumber()) c.maxBody = (size_t)j.at("maxBody").num;
            if (j.has("maxPages") && j.at("maxPages").isNumber()) c.maxPages = (size_t)j.at("maxPages").num;
            if (j.has("prefixes") && j.at("prefixes").isArray()) {
                c.prefixes.clear();
                for (auto& p : j.at("prefixes").arr)
                    if (p.isString()) c.prefixes.push_back(p.str);
            }
            configure(c);
            return true;
        } catch (...) {
            return false;
        }
    }

    std::string indexJson() {
        std::string o = "[";
        std::lock_guard<std::mutex> lk(mu_);
        bool first = true;
        for (auto& kv : entries_) {
            if (!first) o += ",";
            first = false;
            auto pos = kv.first.find('|');
            std::string host = kv.first.substr(0, pos);
            std::string path = kv.first.substr(pos + 1);
            o += "{\"id\":\"" + fnvHex(kv.first) + "\",\"host\":\"" + esc(host) +
                 "\",\"path\":\"" + esc(path) + "\",\"ts\":" +
                 std::to_string(kv.second.learnedAt) +
                 ",\"size\":" + std::to_string(kv.second.respBytes.size()) + "}";
        }
        o += "]";
        return o;
    }

    std::string statsJson() {
        Config c;
        size_t n;
        { std::lock_guard<std::mutex> lk(mu_); c = cfg_; n = entries_.size(); }
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "{\"pages\":%zu,\"learned\":%llu,\"restored\":%llu,\"passed\":%llu,"
                      "\"enabled\":%s,\"updated\":%lld}",
                      n, (unsigned long long)learned_.load(),
                      (unsigned long long)restored_.load(),
                      (unsigned long long)passed_.load(),
                      c.enabled ? "true" : "false", (long long)std::time(nullptr));
        return buf;
    }

    // mu_ 已由调用方持有
    void eraseById(const std::string& id) {
        if (id == "all") {
            entries_.clear();
            lru_.clear();
            return;
        }
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (fnvHex(it->first) == id) {
                lru_.erase(it->second.it);
                entries_.erase(it);
                return;
            }
        }
    }

#ifndef _WIN32
    static bool redisConnect(RedisClient& r) {
        const char* h = std::getenv("NOVA_REDIS_HOST");
        if (!h || !*h) return false;
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        return r.connect(h, port, pass ? pass : "", db);
    }

    void loop() {
        while (running_.load()) {
            for (int i = 0; i < 50 && running_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!running_.load()) break;
            syncOnce();
        }
        syncOnce();  // 停机前把脏基线落盘
    }

    void syncOnce() {
        RedisClient r;
        if (!redisConnect(r)) return;
        // 1) 配置热加载（版本号脏检查）
        auto ver = r.get("novawaf:tamper:cfgver");
        if (ver && *ver != cfgVer_) {
            auto blob = r.get("novawaf:tamper:config");
            if (blob && applyConfigJson(*blob)) {
                cfgVer_ = *ver;
                std::fprintf(stderr, "[tamper] config hot-reloaded (ver=%s)\n", cfgVer_.c_str());
            }
        }
        // 2) 管理端 purge：删除指定页面基线（随后的首个请求自动重学）
        auto purges = r.lrange("novawaf:tamper:purge", 0, -1);
        if (purges && !purges->empty()) {
            r.del("novawaf:tamper:purge");
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& id : *purges) eraseById(id);
            indexDirty_ = true;
        }
        // 3) 脏基线持久化
        std::vector<std::pair<std::string, std::string>> dirty;
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& kv : entries_)
                if (kv.second.dirty) dirty.emplace_back(fnvHex(kv.first), kv.second.respBytes);
        }
        for (auto& d : dirty) r.set("novawaf:tamper:page:" + d.first, b64Encode(d.second));
        if (!dirty.empty()) {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& kv : entries_) kv.second.dirty = false;
            indexDirty_ = true;
        }
        // 4) 索引重写（管理端页面列表数据源）
        if (indexDirty_) {
            r.set("novawaf:tamper:index", indexJson());
            indexDirty_ = false;
        }
        // 5) 运行统计（管理端展示）
        r.set("novawaf:tamper:stats", statsJson());
    }

    void loadFromRedis() {
        RedisClient r;
        if (!redisConnect(r)) return;
        auto ver = r.get("novawaf:tamper:cfgver");
        auto blob = r.get("novawaf:tamper:config");
        if (blob && applyConfigJson(*blob)) cfgVer_ = ver.value_or("");
        auto idx = r.get("novawaf:tamper:index");
        if (!idx || idx->empty()) return;
        try {
            auto j = parseJson(*idx);
            if (!j.isArray()) return;
            Config c = config();
            for (auto& e : j.arr) {
                std::string id = e.at("id").str;
                std::string host = e.at("host").str;
                std::string path = e.at("path").str;
                int64_t ts = (int64_t)e.at("ts").num;
                if (host.empty() || id.empty()) continue;
                auto page = r.get("novawaf:tamper:page:" + id);
                if (!page) continue;
                std::string respBytes = b64Decode(*page);
                size_t he = respBytes.find("\r\n\r\n");
                if (he == std::string::npos) continue;
                std::lock_guard<std::mutex> lk(mu_);
                std::string key = host + "|" + path;
                if (entries_.find(key) != entries_.end()) continue;
                Entry ent;
                ent.body = respBytes.substr(he + 4);
                ent.respBytes = std::move(respBytes);
                ent.learnedAt = ts > 0 ? ts : (int64_t)std::time(nullptr);
                ent.dirty = false;
                lru_.push_front(key);
                ent.it = lru_.begin();
                entries_[key] = std::move(ent);
                while (entries_.size() > c.maxPages) {
                    entries_.erase(lru_.back());
                    lru_.pop_back();
                }
            }
            size_t n;
            { std::lock_guard<std::mutex> lk(mu_); n = entries_.size(); }
            std::fprintf(stderr, "[tamper] restored %zu baseline page(s) from redis\n", n);
        } catch (...) {
        }
    }
#endif

    mutable std::mutex mu_;
    Config cfg_;
    std::unordered_map<std::string, Entry> entries_;  // key = host|path
    std::list<std::string> lru_;                      // front = 最近使用
    std::function<void(const std::string&, const std::string&, const std::string&)> hook_;

    std::atomic<uint64_t> learned_{0};
    std::atomic<uint64_t> restored_{0};
    std::atomic<uint64_t> passed_{0};

    std::atomic<bool> running_{false};
    std::thread th_;
    std::string cfgVer_;
    bool indexDirty_ = false;
};

}  // namespace novawaf
