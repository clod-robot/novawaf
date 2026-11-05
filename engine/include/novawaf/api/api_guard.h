// NovaWAF - API 级防护：请求频率限制 + Token 合法性校验
// 设计：
//   * 策略表以「归一化路径模板 + 方法（可通配）+ 应用（可通配）」为键；精确键 O(1) 命中，
//     仅尾部 '*' 的少量前缀规则线性兜底，规则规模在百级时仍是常数时间。
//   * 每个 (规则, 维度键) 一只令牌桶：scope=ip 每源 IP 独立、token 每令牌独立、
//     global 全局共享；分片锁（64 片）+ 阶梯封禁（60s 内超限 N 次 → 规则级临时封禁）。
//     令牌桶补充为 O(1) 闭式结算（tokens += Δt*qps），无需滑窗队列。
//   * 桶表使用 shared_ptr 持有，后台回收过期桶时不会让并发请求持有悬垂引用。
//   * TokenGuard：JWT 结构（三段 base64url）/ alg 白名单 / exp-iat-nbf 时效 /
//     可选 HMAC-SHA256 签名校验（复用自实现 sha256，无 OpenSSL 依赖）；
//     不透明令牌走内存白名单（loader 线程整表 COW 替换，热路径零 Redis 调用）。
//   * 越权/爬取关联信号：同一令牌短窗内多 IP 复用、令牌出现在 query（易被日志/Referer 泄露）
//     → 401（可配置为仅告警）。
//   * 全部 fail-open：配置不可用即规则表为空放行，绝不影响业务可用性。
#pragma once

#include "novawaf/api/api_asset.h"
#include "novawaf/core/json.h"
#include "novawaf/util/sha256.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace novawaf {

// ---------------- Token 合法性校验 ----------------
class TokenGuard {
public:
    struct Config {
        bool enabled = false;          // 总开关（由策略表 token.enabled 控制）
        bool enforce = true;           // false=只记录不拒绝（灰度）
        std::string mode = "jwt";      // jwt | opaque | any
        std::unordered_set<std::string> algWhitelist{"HS256", "RS256", "ES256"};
        std::string secret;            // HS256 校验密钥（空则只校验结构与时效）
        int64_t maxAgeSec = 86400;
        bool requireIat = false;
        int reuseWindowSec = 60;       // 同令牌多 IP 复用检测窗口
        int reuseMaxIps = 8;           // 窗口内允许的最大独立 IP 数
        bool enforceReuse = true;
        int clockSkewSec = 60;         // 时钟偏移容差
        std::unordered_set<std::string> queryNames{"access_token", "token", "jwt", "id_token"};
    };

    struct Result {
        int status = 0;            // 0=通过；401=非法
        std::string reason;        // bad-structure / bad-alg / expired / token-reuse ...
        bool inQuery = false;
        bool reuse = false;
        int64_t expiresIn = 0;     // 剩余有效期（秒；0=未知）
    };

    static TokenGuard& instance() {
        static TokenGuard g;
        return g;
    }

    void configure(const Config& c) { cfg_.store(std::make_shared<const Config>(c)); }
    std::shared_ptr<const Config> config() const { return cfg_.load(); }

    // 白名单整表替换（opaque token / 网关签发票据），COW 无锁读
    void setWhitelist(const std::vector<std::string>& tokens) {
        auto mutableSet = std::make_shared<std::unordered_set<std::string>>();
        mutableSet->reserve(tokens.size() * 2 + 8);
        for (auto& t : tokens)
            if (!t.empty()) mutableSet->insert(t);
        whitelistSize_.store(mutableSet->size(), std::memory_order_relaxed);
        whitelist_.store(std::shared_ptr<const std::unordered_set<std::string>>(mutableSet));
    }
    size_t whitelistSize() const { return whitelistSize_.load(std::memory_order_relaxed); }

    // 校验。fromQuery=true 表示令牌出现在 URL 查询串（高危泄露信号）
    Result verify(const std::string& token, const std::string& ip, bool fromQuery) {
        Result r;
        r.inQuery = fromQuery;
        auto cfg = cfg_.load();
        if (!cfg || !cfg->enabled) return r;
        if (token.empty()) { r.status = 401; r.reason = "missing-token"; return r; }
        if (token.size() > 8192) { r.status = 401; r.reason = "token-too-long"; return r; }

        if (isJwtShape(token) && (cfg->mode == "jwt" || cfg->mode == "any")) {
            checkJwt(token, *cfg, r);
        } else if (cfg->mode == "opaque" || cfg->mode == "any") {
            auto wl = whitelist_.load();
            if (!wl || wl->count(token) == 0) { r.status = 401; r.reason = "unknown-token"; }
        } else if (cfg->mode == "jwt") {
            r.status = 401;
            r.reason = "bad-structure";
        }
        if (r.status == 0 && fromQuery) { r.status = 401; r.reason = "token-in-query"; }
        if (r.status == 0 && cfg->reuseWindowSec > 0 && !ip.empty()) {
            if (noteReuse(token, ip, *cfg)) {
                r.reuse = true;
                if (cfg->enforceReuse) { r.status = 401; r.reason = "token-reuse"; }
            }
        }
        if (!cfg->enforce) r.status = 0;   // 灰度：保留 reason 供日志，不做处置
        return r;
    }

private:
    TokenGuard() = default;

    struct ReuseRec {
        int64_t winStart = 0;
        std::unordered_set<std::string> ips;
    };
    struct ReuseShard {
        std::mutex mtx;
        std::unordered_map<uint64_t, ReuseRec> recs;
    };
    static constexpr size_t kReuseShards = 32;

    std::atomic<std::shared_ptr<const Config>> cfg_{std::make_shared<const Config>()};
    std::atomic<std::shared_ptr<const std::unordered_set<std::string>>> whitelist_{
        std::make_shared<const std::unordered_set<std::string>>()};
    std::atomic<size_t> whitelistSize_{0};
    ReuseShard reuse_[kReuseShards];

    static int64_t nowSec() { return (int64_t)std::time(nullptr); }

    static bool isJwtShape(const std::string& t) {
        size_t d1 = t.find('.');
        if (d1 == std::string::npos) return false;
        size_t d2 = t.find('.', d1 + 1);
        return d2 != std::string::npos && t.find('.', d2 + 1) == std::string::npos;
    }

    // 常数时间比较（避免签名比对时序侧信道）
    static bool constEq(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < a.size(); ++i) diff |= (unsigned char)(a[i] ^ b[i]);
        return diff == 0;
    }

    static std::string b64urlDecode(const std::string& in) {
        std::string out;
        out.reserve(in.size() * 3 / 4 + 2);
        int val = 0, bits = 0;
        for (char c : in) {
            int d;
            if (c >= 'A' && c <= 'Z') d = c - 'A';
            else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
            else if (c >= '0' && c <= '9') d = c - '0' + 52;
            else if (c == '-' || c == '+') d = 62;
            else if (c == '_' || c == '/') d = 63;
            else if (c == '=') continue;
            else return std::string();
            val = (val << 6) | d;
            bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back((char)((val >> bits) & 0xFF)); }
        }
        return out;
    }

    static std::string hexToBytes(const std::string& hex) {
        std::string out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int hi = std::isdigit((unsigned char)hex[i])
                         ? hex[i] - '0'
                         : (std::tolower((unsigned char)hex[i]) - 'a' + 10);
            int lo = std::isdigit((unsigned char)hex[i + 1])
                         ? hex[i + 1] - '0'
                         : (std::tolower((unsigned char)hex[i + 1]) - 'a' + 10);
            out.push_back((char)((hi << 4) | lo));
        }
        return out;
    }

    // HMAC-SHA256：sha256((key^opad) || sha256((key^ipad) || msg))
    static std::string hmacSha256(const std::string& key, const std::string& msg) {
        std::string k = key;
        if (k.size() > 64) k = hexToBytes(sha256::hashHex(k));
        k.resize(64, '\0');
        std::string ipad(64, '\0'), opad(64, '\0');
        for (size_t i = 0; i < 64; ++i) {
            ipad[i] = (char)((unsigned char)k[i] ^ 0x36);
            opad[i] = (char)((unsigned char)k[i] ^ 0x5C);
        }
        std::string inner = hexToBytes(sha256::hashHex(ipad + msg));
        return hexToBytes(sha256::hashHex(opad + inner));
    }

    void checkJwt(const std::string& token, const Config& cfg, Result& r) {
        size_t d1 = token.find('.');
        size_t d2 = token.find('.', d1 + 1);
        std::string h = b64urlDecode(token.substr(0, d1));
        std::string p = b64urlDecode(token.substr(d1 + 1, d2 - d1 - 1));
        std::string sig = b64urlDecode(token.substr(d2 + 1));
        if (h.empty() || p.empty()) { r.status = 401; r.reason = "bad-structure"; return; }
        JsonValue jh, jp;
        try {
            jh = parseJson(h);
            jp = parseJson(p);
        } catch (...) {
            r.status = 401;
            r.reason = "bad-structure";
            return;
        }
        const JsonValue& alg = jh.at("alg");
        if (alg.type != JsonValue::STRING) { r.status = 401; r.reason = "bad-alg"; return; }
        if (!cfg.algWhitelist.empty() && !cfg.algWhitelist.count(alg.str)) {
            r.status = 401; r.reason = "bad-alg"; return;   // 拒绝 alg=none 等
        }
        // 签名校验：HS256 且配置了密钥时启用；RS/ES 需公钥，此处只做结构+时效校验
        if (!cfg.secret.empty() && alg.str == "HS256") {
            std::string expect = hmacSha256(cfg.secret, token.substr(0, d2));
            if (!constEq(sig, expect)) { r.status = 401; r.reason = "bad-signature"; return; }
        }
        int64_t now = nowSec();
        const JsonValue& exp = jp.at("exp");
        if (exp.type == JsonValue::NUMBER) {
            int64_t e = (int64_t)exp.num;
            r.expiresIn = e - now;
            if (now > e + cfg.clockSkewSec) { r.status = 401; r.reason = "expired"; return; }
        } else {
            const JsonValue& iat = jp.at("iat");
            if (cfg.requireIat && iat.type != JsonValue::NUMBER) {
                r.status = 401; r.reason = "missing-iat"; return;
            }
            if (iat.type == JsonValue::NUMBER && now - (int64_t)iat.num > cfg.maxAgeSec + cfg.clockSkewSec) {
                r.status = 401; r.reason = "stale-token"; return;
            }
        }
        const JsonValue& nbf = jp.at("nbf");
        if (nbf.type == JsonValue::NUMBER && now + cfg.clockSkewSec < (int64_t)nbf.num) {
            r.status = 401; r.reason = "not-yet-valid"; return;
        }
    }

    // 同令牌多 IP 复用：滑动窗口内独立 IP 数超阈即判异常（令牌窃取/共享爬取的强信号）
    bool noteReuse(const std::string& token, const std::string& ip, const Config& cfg) {
        uint64_t h = std::hash<std::string>{}(token);
        ReuseShard& sh = reuse_[h & (kReuseShards - 1)];
        int64_t now = nowSec();
        std::lock_guard<std::mutex> lk(sh.mtx);
        if (sh.recs.size() > 50000) sh.recs.clear();   // 内存护栏
        auto& rec = sh.recs[h];
        if (rec.winStart == 0 || now - rec.winStart > cfg.reuseWindowSec) {
            rec.winStart = now;
            rec.ips.clear();
        }
        if ((int)rec.ips.size() < cfg.reuseMaxIps + 2) rec.ips.insert(ip);
        return (int)rec.ips.size() > cfg.reuseMaxIps;
    }
};

// ---------------- API 级频率限制 ----------------
class ApiRateGuard {
public:
    enum Scope : int { SCOPE_IP = 0, SCOPE_TOKEN = 1, SCOPE_GLOBAL = 2 };
    enum Act : int { ACT_MONITOR = 0, ACT_LIMIT = 1, ACT_BAN = 2 };

    struct Rule {
        std::string id;
        std::string appId;      // 空=全部应用
        std::string method;     // 空=任意方法
        std::string tpl;        // 归一化模板（尾部 '*' 表示前缀匹配）
        double qps = 0;
        int burst = 0;
        Scope scope = SCOPE_IP;
        Act action = ACT_LIMIT;
        int banSec = 300;
        bool tokenRequired = false;
    };

    struct Policy {
        bool enabled = true;
        int stage = 1;                     // 0=monitor：只统计超限不处置
        std::vector<Rule> rules;
        TokenGuard::Config token;
        std::unordered_map<std::string, size_t> exact;  // 键 -> 规则下标
        std::vector<size_t> prefix;        // 尾部 '*' 规则
    };

    struct Decision {
        int status = 0;              // 401 / 429；0=放行
        bool ban = false;
        bool tokenIssue = false;
        int retryAfterSec = 0;
        std::string ruleId;
        std::string reason;
        std::string detail;
    };

    static ApiRateGuard& instance() {
        static ApiRateGuard g;
        return g;
    }

    void configure(std::shared_ptr<const Policy> p) { policy_.store(std::move(p)); }
    int stage() const {
        auto p = policy_.load();
        return p ? p->stage : 0;
    }
    size_t ruleCount() const {
        auto p = policy_.load();
        return p ? p->rules.size() : 0;
    }

    // 从 Redis JSON 解析；非法 JSON 抛异常（由调用方兜底保留旧策略）
    static std::shared_ptr<const Policy> parsePolicy(const std::string& blob) {
        Policy p;
        if (!blob.empty()) {
            JsonValue root = parseJson(blob);
            if (root.type == JsonValue::OBJECT) {
                auto num = [](const JsonValue& v, double dft) {
                    return v.type == JsonValue::NUMBER ? v.num : dft;
                };
                auto boolean = [](const JsonValue& v, bool dft) {
                    return v.type == JsonValue::BOOL ? v.b : dft;
                };
                p.enabled = boolean(root.at("enabled"), p.enabled);
                p.stage = (int)num(root.at("stage"), p.stage);
                const JsonValue& tk = root.at("token");
                if (tk.type == JsonValue::OBJECT) {
                    p.token.enabled = boolean(tk.at("enabled"), p.token.enabled);
                    p.token.enforce = boolean(tk.at("enforce"), p.token.enforce);
                    if (tk.at("mode").type == JsonValue::STRING) p.token.mode = tk.at("mode").str;
                    if (tk.at("secret").type == JsonValue::STRING) p.token.secret = tk.at("secret").str;
                    p.token.maxAgeSec = (int64_t)num(tk.at("maxAgeSec"), (double)p.token.maxAgeSec);
                    p.token.requireIat = boolean(tk.at("requireIat"), p.token.requireIat);
                    p.token.reuseWindowSec = (int)num(tk.at("reuseWindowSec"), p.token.reuseWindowSec);
                    p.token.reuseMaxIps = (int)num(tk.at("reuseMaxIps"), p.token.reuseMaxIps);
                    p.token.enforceReuse = boolean(tk.at("enforceReuse"), p.token.enforceReuse);
                    const JsonValue& algs = tk.at("algWhitelist");
                    if (algs.type == JsonValue::ARRAY) {
                        p.token.algWhitelist.clear();
                        for (auto& a : algs.arr)
                            if (a.type == JsonValue::STRING) p.token.algWhitelist.insert(a.str);
                    }
                }
                const JsonValue& rs = root.at("rules");
                if (rs.type == JsonValue::ARRAY) {
                    for (auto& rj : rs.arr) {
                        if (rj.type != JsonValue::OBJECT) continue;
                        Rule r;
                        if (rj.at("id").type == JsonValue::STRING) r.id = rj.at("id").str;
                        if (rj.at("appId").type == JsonValue::STRING) r.appId = rj.at("appId").str;
                        if (rj.at("method").type == JsonValue::STRING) r.method = rj.at("method").str;
                        std::string tpl = rj.at("path").type == JsonValue::STRING ? rj.at("path").str : "";
                        if (tpl.empty()) continue;
                        bool wildcard = tpl.back() == '*';
                        if (wildcard) tpl.pop_back();
                        r.tpl = ApiAssetRegistry::normalizePath(tpl) + (wildcard ? "*" : "");
                        r.qps = num(rj.at("qps"), 0);
                        r.burst = (int)num(rj.at("burst"), 0);
                        std::string sc = rj.at("scope").type == JsonValue::STRING ? rj.at("scope").str : "ip";
                        if (sc == "token") r.scope = SCOPE_TOKEN;
                        else if (sc == "global") r.scope = SCOPE_GLOBAL;
                        std::string ac = rj.at("action").type == JsonValue::STRING ? rj.at("action").str : "429";
                        if (ac == "monitor") r.action = ACT_MONITOR;
                        else if (ac == "ban") r.action = ACT_BAN;
                        r.banSec = (int)num(rj.at("banSec"), r.banSec);
                        r.tokenRequired = boolean(rj.at("tokenRequired"), false);
                        if (r.qps <= 0 || r.burst <= 0) r.action = ACT_MONITOR;  // 无阈值只观测
                        p.rules.push_back(std::move(r));
                    }
                }
            }
        }
        for (size_t i = 0; i < p.rules.size(); ++i) {
            const Rule& r = p.rules[i];
            if (!r.tpl.empty() && r.tpl.back() == '*') { p.prefix.push_back(i); continue; }
            p.exact[ApiAssetRegistry::makeKey(r.appId, r.method, r.tpl)] = i;
        }
        return std::make_shared<const Policy>(std::move(p));
    }

    // 请求判定：先 Token 合法性，再频率限制。nullopt=放行。
    std::optional<Decision> assess(const std::string& ip, const std::string& appId,
                                   const std::string& method, const std::string& rawPath,
                                   const std::string& token, bool tokenFromQuery) {
        auto pol = policy_.load();
        if (!pol || !pol->enabled) return std::nullopt;
        std::string tpl = ApiAssetRegistry::normalizePath(rawPath);
        const Rule* rule = findRule(*pol, appId, method, tpl);

        if (pol->token.enabled) {
            if (rule && rule->tokenRequired) {
                TokenGuard::Result tr = TokenGuard::instance().verify(token, ip, tokenFromQuery);
                if (tr.status != 0) {
                    Decision d;
                    d.status = 401;
                    d.tokenIssue = true;
                    d.ruleId = rule->id.empty() ? "API-TOKEN" : (rule->id + "/TOKEN");
                    d.reason = tr.reason;
                    d.detail = "token rejected: " + tr.reason;
                    return d;
                }
            } else if (!token.empty()) {
                // 非必需路径：只做复用关联检测，不因结构问题拒绝业务请求
                TokenGuard::Result tr = TokenGuard::instance().verify(token, ip, tokenFromQuery);
                if (tr.reuse) {
                    Decision d;
                    d.status = 401;
                    d.tokenIssue = true;
                    d.ruleId = "API-TOKEN-REUSE";
                    d.reason = "token-reuse";
                    d.detail = "same token used from too many sources";
                    if (!pol->token.enforceReuse) d.status = 0;
                    return d;
                }
            }
        }
        if (!rule || rule->action == ACT_MONITOR || pol->stage <= 0) return std::nullopt;

        std::string skey;
        if (rule->scope == SCOPE_GLOBAL) skey = "G";
        else if (rule->scope == SCOPE_TOKEN) {
            if (token.empty()) return std::nullopt;
            skey = "T" + std::to_string(std::hash<std::string>{}(token));
        } else skey = "I" + ip;
        std::string bkey = std::to_string((size_t)(rule - &pol->rules[0]));
        bkey.push_back('\x1f');
        bkey += skey;

        auto b = bucketOf(bkey);
        std::lock_guard<std::mutex> lk(b->mtx);
        int64_t nowMs = nowMs_();
        if (b->banUntil > nowMs) {
            Decision d;
            d.status = 429;
            d.ban = true;
            d.ruleId = rule->id;
            d.retryAfterSec = (int)((b->banUntil - nowMs) / 1000) + 1;
            d.reason = "api-ban";
            d.detail = tpl;
            return d;
        }
        if (b->lastMs == 0) { b->lastMs = nowMs; b->tokens = (double)rule->burst; }
        if (b->cap != rule->burst) {
            b->cap = rule->burst;
            b->tokens = std::min(b->tokens, (double)rule->burst);
        }
        double dt = (double)(nowMs - b->lastMs) / 1000.0;
        if (dt > 0) {
            b->tokens = std::min((double)rule->burst, b->tokens + dt * rule->qps);
            b->lastMs = nowMs;
        }
        if (b->tokens >= 1.0) { b->tokens -= 1.0; return std::nullopt; }

        int retry = (int)std::ceil((1.0 - b->tokens) / rule->qps);
        b->tokens = 0;
        if (rule->action == ACT_BAN) {
            int64_t cutoff = nowMs - 60000;
            while (!b->strikes.empty() && b->strikes.front() < cutoff) b->strikes.pop_front();
            b->strikes.push_back(nowMs);
            if ((int)b->strikes.size() >= 3) {
                b->banUntil = nowMs + (int64_t)rule->banSec * 1000;
                b->strikes.clear();
                Decision d;
                d.status = 429;
                d.ban = true;
                d.ruleId = rule->id;
                d.retryAfterSec = rule->banSec;
                d.reason = "api-ban-escalated";
                d.detail = tpl;
                return d;
            }
        }
        Decision d;
        d.status = 429;
        d.ruleId = rule->id;
        d.retryAfterSec = std::max(1, retry);
        d.reason = "rate-exceeded";
        d.detail = tpl + " scope=" + (rule->scope == SCOPE_IP ? "ip"
                                      : rule->scope == SCOPE_TOKEN ? "token" : "global");
        return d;
    }

private:
    ApiRateGuard() = default;

    struct Bucket {
        std::mutex mtx;
        double tokens = 0;
        int cap = 0;
        int64_t lastMs = 0;
        int64_t banUntil = 0;
        std::deque<int64_t> strikes;
    };
    struct BucketShard {
        std::mutex mtx;
        std::unordered_map<std::string, std::shared_ptr<Bucket>> buckets;
    };
    static constexpr size_t kShards = 64;

    std::atomic<std::shared_ptr<const Policy>> policy_{std::make_shared<const Policy>()};
    BucketShard shards_[kShards];

    static int64_t nowMs_() {
        return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    static bool isWildcard(const std::string& tpl) {
        return !tpl.empty() && tpl.back() == '*';
    }

    const Rule* findRule(const Policy& p, const std::string& appId, const std::string& method,
                         const std::string& tpl) const {
        // 精确匹配优先级：应用+方法 > 应用+任意方法 > 任意应用+方法 > 任意应用+任意方法
        const std::string keys[4] = {
            ApiAssetRegistry::makeKey(appId, method, tpl),
            ApiAssetRegistry::makeKey(appId, "", tpl),
            ApiAssetRegistry::makeKey("", method, tpl),
            ApiAssetRegistry::makeKey("", "", tpl)};
        for (auto& k : keys) {
            auto it = p.exact.find(k);
            if (it != p.exact.end()) return &p.rules[it->second];
        }
        for (size_t idx : p.prefix) {
            const Rule& r = p.rules[idx];
            if (!r.appId.empty() && r.appId != appId) continue;
            if (!r.method.empty() && r.method != method) continue;
            std::string pre = r.tpl.substr(0, r.tpl.size() - 1);
            if (tpl.size() >= pre.size() && tpl.compare(0, pre.size(), pre) == 0) return &r;
        }
        return nullptr;
    }

    // 取桶：分片锁内查/建，返回 shared_ptr 后立刻释放分片锁（引用计数保证回收安全）
    std::shared_ptr<Bucket> bucketOf(const std::string& key) {
        size_t h = std::hash<std::string>{}(key);
        BucketShard& sh = shards_[h & (kShards - 1)];
        int64_t now = nowMs_();
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto it = sh.buckets.find(key);
        if (it != sh.buckets.end()) return it->second;
        if (sh.buckets.size() > 20000) gcBuckets(sh, now);
        auto b = std::make_shared<Bucket>();
        sh.buckets.emplace(key, b);
        return b;
    }

    // 回收 1 小时无活动且无人持有的桶（banned 桶保留到封禁结束）
    static void gcBuckets(BucketShard& sh, int64_t nowMs) {
        for (auto it = sh.buckets.begin(); it != sh.buckets.end();) {
            auto& b = it->second;
            bool idle = b->lastMs > 0 && nowMs - b->lastMs > 3600000 && b->banUntil < nowMs;
            if (idle && b.use_count() == 1) it = sh.buckets.erase(it);
            else ++it;
        }
    }
};

}  // namespace novawaf
