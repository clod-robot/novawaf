// NovaWAF - API 资产自动发现（资产目录 / 影子 API / 僵尸 API）
// 设计要点：
//   * 路径模板化（确定性 O(n)，无正则回溯）：数字 / UUID / 长十六进制 / 长随机段
//     / 带扩展名的随机文件名 统一归一为 {id}，把 /api/user/1001 与 /api/user/1002
//     收敛为同一资产 /api/user/{id}，避免按原始 URL 爆炸式建表（也天然抗扫描器
//     用随机 ID 灌爆内存）。
//   * 并发模型：64 分片锁（按 key 哈希）+ COW 已登记清单（atomic<shared_ptr<const>>），
//     热路径只在单个分片上短暂持锁，跨 reactor 无线程争用；清单热更新零拷贝。
//   * 状态判定：观测到但未登记（含方法未登记）→ 影子 API；已登记但 N 天无流量 →
//     僵尸 API。首次发现发事件（API-SHADOW），僵尸由快照线程每日发一次（API-ZOMBIE）。
//   * 独立 IP 数采用 64 位哈希位图（popcount 估计），零额外内存即可识别
//     「同一接口被大量离散源 IP 批量爬取」。
//   * 基线：参数个数与载荷熵的 EWMA（α=0.2），供 Agentic AI 引擎做「结构偏离」打分。
#pragma once

#include "novawaf/core/event_bus.h"
#include "novawaf/core/event_sink.h"
#include "novawaf/core/json.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace novawaf {

class ApiAssetRegistry {
public:
    static ApiAssetRegistry& instance() {
        static ApiAssetRegistry inst;
        return inst;
    }

    // 观测输入（由 reactor 在解析完成后填充，避免依赖 HttpRequest 结构）
    struct ObserveIn {
        std::string appId;
        std::string method;
        std::string contentType;
        bool hasAuth = false;
        bool hasCookie = false;
        const std::vector<std::pair<std::string, std::string>>* query = nullptr;
        size_t paramCount = 0;
        double entropy = 0;        // 0=未计算（由 Agentic 侧按需补算）
        uint64_t ipHash = 0;       // 源 IP 哈希（用于独立来源估计）
    };

    // 对外只读视图（管理端资产目录的数据来源）
    struct View {
        std::string appId, method, tpl, contentType, kind;
        int64_t firstSeen = 0, lastSeen = 0;
        uint64_t count = 0, errCount = 0;
        uint64_t cls[6] = {0, 0, 0, 0, 0, 0};   // 按状态码百位分桶 1xx..5xx
        bool auth = false, cookie = false, sensitive = false;
        size_t paramMax = 0;
        double avgParams = 0, avgEntropy = 0;
        int distinctSources = 0;
    };

    // ---- 路径模板化 ----
    // 归一化规则（确定性，线性扫描）：
    //   * 纯数字段、UUID、长度>=16 的纯十六进制段、长度>=20 且数字/字母混合段 → {id}
    //   * name.<ext> 形式：对主干做同样判定，扩展名保留（静态资源按扩展归类）
    //   * 其余原样保留（大小写敏感，不做小写化，避免两个真实接口被错误合并）
    static std::string normalizePath(const std::string& rawPath) {
        std::string p = rawPath.substr(0, rawPath.find('?'));
        if (p.size() > 512) p.resize(512);   // 防御性截断，正常路径远小于此
        std::string out;
        out.reserve(p.size());
        size_t i = 0;
        while (i < p.size()) {
            if (p[i] == '/') {
                if (out.empty() || out.back() != '/') out.push_back('/');
                ++i;
                continue;
            }
            size_t j = i;
            while (j < p.size() && p[j] != '/') ++j;
            out += normalizeSegment(p.substr(i, j - i));
            i = j;
        }
        if (out.empty()) out = "/";
        while (out.size() > 1 && out.back() == '/') out.pop_back();
        // 防御：路径中出现 \\x1f 会破坏内部键分隔，替换为 '?'
        for (auto& c : out) if (c == '\x1f') c = '?';
        return out;
    }

    // 资产键：appId \x1f method \x1f template（全引擎唯一标识）
    static std::string makeKey(const std::string& appId, const std::string& method,
                               const std::string& tpl) {
        return appId + '\x1f' + method + '\x1f' + tpl;
    }

    // 已登记清单热更新（JSON：{"items":[{"appId":"","method":"GET","path":"/api/x/{id}"}]}）
    void configureInventory(const std::string& blob) {
        auto inv = std::make_shared<Inventory>();
        if (!blob.empty()) {
            try {
                JsonValue root = parseJson(blob);
                const JsonValue& items = root.at("items");
                if (items.type == JsonValue::ARRAY) {
                    for (auto& it : items.arr) {
                        if (it.type != JsonValue::OBJECT) continue;
                        const JsonValue& a = it.at("appId");
                        const JsonValue& m = it.at("method");
                        const JsonValue& p = it.at("path");
                        if (p.type != JsonValue::STRING) continue;
                        std::string appId = (a.type == JsonValue::STRING) ? a.str : "";
                        std::string method = (m.type == JsonValue::STRING) ? m.str : "";
                        inv->keys.insert(makeKey(appId, method, normalizePath(p.str)));
                    }
                }
            } catch (...) {
                // 解析失败：保持旧清单（fail-safe，宁可少报影子也不误报全网）
                return;
            }
        }
        inv->loadedAt = (int64_t)std::time(nullptr);
        inventory_.store(std::move(inv));
    }

    size_t inventorySize() const {
        auto inv = inventory_.load();
        return inv ? inv->keys.size() : 0;
    }

    // 进程重启后从上次快照恢复资产目录：保留首见时间、累计计数与状态码分布，
    // 不重复发布「影子 API」发现事件（重启不是新发现）。
    // 说明：源 IP 位图不可还原，用合成位图维持 distinctSources 估计值。
    void restore(const std::string& blob) {
        if (blob.empty()) return;
        JsonValue root;
        try {
            root = parseJson(blob);
        } catch (...) {
            return;
        }
        const JsonValue& arr = root.at("assets");
        if (!arr.isArray()) return;
        int64_t now = (int64_t)std::time(nullptr);
        for (const auto& a : arr.arr) {
            if (!a.isObject()) continue;
            const JsonValue& tv = a.at("template");
            const JsonValue& mv = a.at("method");
            if (!tv.isString() || !mv.isString() || tv.str.empty()) continue;
            std::string appId = a.at("appId").isString() ? a.at("appId").str : std::string();
            std::string key = makeKey(appId, mv.str, tv.str);
            int64_t firstSeen = a.at("firstSeen").isNumber() ? (int64_t)a.at("firstSeen").num : now;
            int64_t lastSeen = a.at("lastSeen").isNumber() ? (int64_t)a.at("lastSeen").num : 0;
            if (lastSeen <= 0) continue;   // 僵尸/清单派生的占位项不还原
            Shard& sh = shardOf(key);
            std::lock_guard<std::mutex> lk(sh.mtx);
            if (sh.items.count(key)) continue;
            if (sh.items.size() >= kShardCap ||
                total_.load(std::memory_order_relaxed) >= kMaxAssets) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            Item item;
            item.key = key;
            item.appId = appId;
            item.method = mv.str;
            item.tpl = tv.str;
            item.firstSeen = firstSeen;
            item.lastSeen = lastSeen;
            item.count = a.at("count").isNumber() ? (uint64_t)a.at("count").num : 0;
            item.errCount = a.at("errCount").isNumber() ? (uint64_t)a.at("errCount").num : 0;
            const JsonValue& st = a.at("status");
            if (st.isObject()) {
                for (int i = 1; i < 6; ++i) {
                    const JsonValue& c = st.at(std::to_string(i) + "xx");
                    if (c.isNumber()) item.cls[i] = (uint64_t)c.num;
                }
            }
            const JsonValue& au = a.at("auth");
            item.auth = au.isString() ? au.str == "1" : (au.isBool() && au.b);
            const JsonValue& ck = a.at("cookie");
            item.cookie = ck.isString() ? ck.str == "1" : (ck.isBool() && ck.b);
            const JsonValue& se = a.at("sensitive");
            item.sensitive = se.isBool() && se.b;
            item.paramMax = a.at("paramMax").isNumber() ? (size_t)a.at("paramMax").num : 0;
            item.avgParams = a.at("avgParams").isNumber() ? a.at("avgParams").num : 0;
            item.avgEntropy = a.at("avgEntropy").isNumber() ? a.at("avgEntropy").num : 0;
            item.samples = item.count;
            const JsonValue& src = a.at("sources");
            if (src.isNumber() && src.num > 0) {
                int n = src.num >= 64 ? 64 : (int)src.num;
                item.ipBits = n >= 64 ? ~0ull : ((1ull << n) - 1);
            }
            if (a.at("contentType").isString()) item.contentType = a.at("contentType").str;
            sh.items.emplace(key, std::move(item));
            total_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // 请求观测：登记/累加，首次发现影子 API 时发布事件。
    // 返回资产键（供响应侧 noteStatus 使用；空串=未登记成功，调用方忽略）。
    std::string observe(const ObserveIn& in, const std::string& rawPath) {
        std::string tpl = normalizePath(rawPath);
        std::string key = makeKey(in.appId, in.method, tpl);
        int64_t now = (int64_t)std::time(nullptr);
        bool newShadow = false;
        bool sensitive = false;
        {
            Shard& sh = shardOf(key);
            std::lock_guard<std::mutex> lk(sh.mtx);
            auto it = sh.items.find(key);
            if (it == sh.items.end()) {
                // 容量护栏：单分片与全局双上限，防止随机路径扫描打爆内存
                if (sh.items.size() >= kShardCap ||
                    total_.load(std::memory_order_relaxed) >= kMaxAssets) {
                    dropped_.fetch_add(1, std::memory_order_relaxed);
                    return std::string();
                }
                Item item;
                item.key = key;
                item.appId = in.appId;
                item.method = in.method;
                item.tpl = tpl;
                item.firstSeen = now;
                item.lastSeen = now;
                item.contentType = in.contentType;
                auto res = sh.items.emplace(key, std::move(item));
                it = res.first;
                total_.fetch_add(1, std::memory_order_relaxed);
                sh.ops++;
                if (!isRegistered(key, in.method, tpl)) newShadow = true;
                lastNew_ = now;
            } else {
                // 长期静默（>7 天）后重见：视为重新出现，重置发现时间（僵尸复活）
                if (now - it->second.lastSeen > 7LL * 86400) it->second.firstSeen = now;
                it->second.lastSeen = now;
                if (it->second.contentType.empty() && !in.contentType.empty())
                    it->second.contentType = in.contentType;
            }
            Item& rec = it->second;
            rec.count++;
            rec.auth = rec.auth || in.hasAuth;
            rec.cookie = rec.cookie || in.hasCookie;
            if (in.ipHash) rec.ipBits |= in.ipHash;
            sensitive = markSensitive(rec, in);
            if (in.paramCount > rec.paramMax) rec.paramMax = in.paramCount;
            if (in.paramCount && rec.samples < 1000000) {
                // 参数个数 / 载荷熵 EWMA（α=0.2）：结构偏离检测的基线
                rec.avgParams = rec.samples == 0 ? (double)in.paramCount
                                                 : rec.avgParams * 0.8 + (double)in.paramCount * 0.2;
                if (in.entropy > 0)
                    rec.avgEntropy = rec.samples == 0 ? in.entropy
                                                      : rec.avgEntropy * 0.8 + in.entropy * 0.2;
                rec.samples++;
            }
            maybeGc(sh, now);
        }
        if (newShadow) {
            emitShadow(in.appId, in.method, tpl);
            shadowTotal_.fetch_add(1, std::memory_order_relaxed);
        }
        if (sensitive) sensitiveTotal_.fetch_add(1, std::memory_order_relaxed);
        return key;
    }

    // 响应状态码记账（同步/异步转发路径各自在响应回写前调用一次）
    void noteStatus(const std::string& key, int status) {
        if (key.empty()) return;
        int idx = (status >= 100 && status < 600) ? (status / 100) : 0;
        Shard& sh = shardOf(key);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto it = sh.items.find(key);
        if (it == sh.items.end()) return;
        it->second.cls[idx]++;
        if (idx == 5) it->second.errCount++;
        // 敏感数据实际回吐（响应侧 DLP 命中）也可在调用方置位，此处保持请求侧语义
    }

    // 基线读取（Agentic 引擎做结构偏离打分用；无记录返回 false）
    bool baseline(const std::string& appId, const std::string& method, const std::string& rawPath,
                  double& avgParams, double& avgEntropy, uint64_t& count, size_t& paramMax) {
        std::string key = makeKey(appId, method, normalizePath(rawPath));
        Shard& sh = shardOf(key);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto it = sh.items.find(key);
        if (it == sh.items.end()) return false;
        avgParams = it->second.avgParams;
        avgEntropy = it->second.avgEntropy;
        count = it->second.count;
        paramMax = it->second.paramMax;
        return true;
    }

    bool isRegisteredPath(const std::string& appId, const std::string& method,
                          const std::string& rawPath) const {
        return isRegistered(makeKey(appId, method, normalizePath(rawPath)), method,
                            normalizePath(rawPath));
    }

    size_t size() const { return total_.load(std::memory_order_relaxed); }
    uint64_t shadowTotal() const { return shadowTotal_.load(std::memory_order_relaxed); }
    int64_t lastNewAsset() const { return lastNew_.load(std::memory_order_relaxed); }

    // 资产快照 JSON（写 Redis novawaf:api:assets，管理端资产目录读取）。
    // zombieDays：已登记但连续 N 天无流量判为僵尸；emitZombie：为每个僵尸发一次事件（每日一次）。
    std::string snapshotJson(int zombieDays, bool emitZombie) {
        int64_t now = (int64_t)std::time(nullptr);
        std::vector<View> views;
        views.reserve(4096);
        for (auto& sh : shards_) {
            std::lock_guard<std::mutex> lk(sh.mtx);
            for (auto& kv : sh.items) views.push_back(toView(kv.second, now, zombieDays));
        }
        // 僵尸：清单里有、观测中无（或长期无流量）
        std::unordered_set<std::string> observed;
        observed.reserve(views.size() * 2);
        for (auto& v : views) observed.insert(makeKey(v.appId, v.method, v.tpl));

        std::vector<View> zombies;
        auto inv = inventory_.load();
        if (inv) {
            for (auto& k : inv->keys) {
                std::string appId, method, tpl;
                splitKey(k, appId, method, tpl);
                if (observed.count(k)) continue;   // 有流量（无论新旧）不算僵尸
                View v;
                v.appId = appId; v.method = method; v.tpl = tpl;
                v.kind = "zombie";
                v.lastSeen = 0; v.firstSeen = inv->loadedAt;
                zombies.push_back(std::move(v));
            }
        }
        // 三态归类：未登记=shadow；已登记且超 zombieDays 无流量=zombie；其余=registered
        size_t shadow = 0, reg = 0, zcount = 0, new24h = 0;
        for (auto& v : views) {
            bool registered = isRegistered(makeKey(v.appId, v.method, v.tpl), v.method, v.tpl);
            if (!registered) {
                v.kind = "shadow"; ++shadow;
            } else if (now - v.lastSeen > (int64_t)zombieDays * 86400) {
                v.kind = "zombie"; ++zcount;
            } else {
                v.kind = "registered"; ++reg;
            }
            if (now - v.firstSeen <= 86400) ++new24h;
        }
        zcount += zombies.size();
        // 僵尸事件：每个资产每天最多一次
        if (emitZombie) {
            std::lock_guard<std::mutex> lk(zombieMtx_);
            for (auto& z : zombies) {
                std::string k = makeKey(z.appId, z.method, z.tpl);
                auto it = zombieNotify_.find(k);
                if (it != zombieNotify_.end() && now - it->second < 86400) continue;
                zombieNotify_[k] = now;
                emitAssetEvent(z.appId, z.method, z.tpl, "API-ZOMBIE", "log", "high",
                               "registered api idle >= " + std::to_string(zombieDays) + "d");
            }
            if (zombieNotify_.size() > 20000) zombieNotify_.clear();   // 内存护栏
        }
        // 序列化
        std::ostringstream o;
        o << "{\"ts\":" << now
          << ",\"total\":" << views.size() + zombies.size()
          << ",\"observed\":" << views.size()
          << ",\"shadow\":" << shadow
          << ",\"registered\":" << reg
          << ",\"zombie\":" << zcount
          << ",\"new24h\":" << new24h
          << ",\"inventory\":" << inventorySize()
          << ",\"dropped\":" << dropped_.load(std::memory_order_relaxed)
          << ",\"assets\":[";
        bool first = true;
        for (auto& v : views) {
            if (!first) o << ",";
            first = false;
            writeView(o, v);
        }
        for (auto& z : zombies) {
            if (!first) o << ",";
            first = false;
            writeView(o, z);
        }
        o << "]}";
        return o.str();
    }

private:
    ApiAssetRegistry() = default;

    static constexpr size_t kShards = 64;
    static constexpr size_t kShardCap = 4000;      // 单分片资产上限
    static constexpr size_t kMaxAssets = 200000;   // 全局资产上限
    static constexpr int64_t kRetentionSec = 30LL * 86400;  // 非登记资产保留 30 天

    struct Item {
        std::string key, appId, method, tpl, contentType;
        int64_t firstSeen = 0, lastSeen = 0;
        uint64_t count = 0, errCount = 0;
        uint64_t cls[6] = {0, 0, 0, 0, 0, 0};
        bool auth = false, cookie = false, sensitive = false;
        size_t paramMax = 0;
        double avgParams = 0, avgEntropy = 0;
        uint64_t samples = 0;
        uint64_t ipBits = 0;
    };
    struct Inventory {
        std::unordered_set<std::string> keys;
        int64_t loadedAt = 0;
    };
    struct Shard {
        std::mutex mtx;
        std::unordered_map<std::string, Item> items;
        uint64_t ops = 0;
    };

    Shard shards_[kShards];
    std::atomic<std::shared_ptr<const Inventory>> inventory_{
        std::make_shared<const Inventory>()};
    std::atomic<size_t> total_{0};
    std::atomic<uint64_t> shadowTotal_{0};
    std::atomic<uint64_t> sensitiveTotal_{0};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<int64_t> lastNew_{0};
    std::mutex zombieMtx_;
    std::unordered_map<std::string, int64_t> zombieNotify_;

    Shard& shardOf(const std::string& key) const {
        size_t h = std::hash<std::string>{}(key);
        return const_cast<Shard&>(shards_[h & (kShards - 1)]);
    }

    static bool isExtLike(const std::string& ext) {
        if (ext.empty() || ext.size() > 6) return false;
        for (char c : ext)
            if (!std::isalnum((unsigned char)c)) return false;
        return true;
    }

    static bool isVariableToken(const std::string& s) {
        size_t n = s.size();
        if (n == 0) return false;
        bool allDigit = true, allHex = true;
        int digits = 0, alphas = 0;
        bool urlSafe = true;
        for (char c : s) {
            if (std::isdigit((unsigned char)c)) { ++digits; }
            else if (std::isalpha((unsigned char)c)) { ++alphas; allDigit = false; }
            else { allDigit = false; }
            if (!std::isxdigit((unsigned char)c)) allHex = false;
            if (!std::isalnum((unsigned char)c) && c != '-' && c != '_' && c != '.' && c != '=') urlSafe = false;
        }
        if (allDigit) return true;                                  // 纯数字 ID / 页码
        // UUID：8-4-4-4-12 十六进制
        if (n == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && allHex) return true;
        if (n >= 16 && allHex) return true;                          // 长十六进制（哈希/对象ID）
        // 长随机段：>=20 且字母数字混合（base64url token / session / slug 随机尾）
        if (n >= 20 && urlSafe && digits >= 2 && alphas >= 2) return true;
        return false;
    }

    static std::string normalizeSegment(const std::string& seg) {
        if (seg.empty()) return seg;
        size_t dot = seg.rfind('.');
        if (dot != std::string::npos && dot > 0 && isExtLike(seg.substr(dot + 1))) {
            std::string stem = seg.substr(0, dot);
            if (isVariableToken(stem)) return "{id}" + seg.substr(dot);
            return seg;
        }
        if (isVariableToken(seg)) return "{id}";
        return seg;
    }

    bool isRegistered(const std::string& key, const std::string& method,
                      const std::string& tpl) const {
        auto inv = inventory_.load();
        if (!inv) return false;
        if (inv->keys.count(key)) return true;
        // 应用级通配：已登记清单 appId="" 表示所有应用共享该模板
        return inv->keys.count(makeKey("", method, tpl)) != 0;
    }

    static void splitKey(const std::string& key, std::string& appId, std::string& method,
                         std::string& tpl) {
        size_t p1 = key.find('\x1f');
        if (p1 == std::string::npos) { appId = key; return; }
        size_t p2 = key.find('\x1f', p1 + 1);
        appId = key.substr(0, p1);
        if (p2 == std::string::npos) { method = key.substr(p1 + 1); return; }
        method = key.substr(p1 + 1, p2 - p1 - 1);
        tpl = key.substr(p2 + 1);
    }

    // 敏感参数名识别（请求侧字段名，命中即标记该资产为「处理敏感数据」）
    static bool markSensitive(Item& rec, const ObserveIn& in) {
        if (rec.sensitive || !in.query) return rec.sensitive;
        static const char* kNames[] = {"idcard", "idno", "certno", "phone", "mobile", "tel",
                                       "bank", "cardno", "password", "passwd", "pwd", "email",
                                       "token", "secret", "apikey", "api_key", "address", "sfzh"};
        for (auto& [k, v] : *in.query) {
            std::string lk;
            lk.reserve(k.size());
            for (char c : k) lk.push_back((char)std::tolower((unsigned char)c));
            for (auto* n : kNames) {
                if (lk.find(n) != std::string::npos) { rec.sensitive = true; return true; }
            }
        }
        return false;
    }

    void maybeGc(Shard& sh, int64_t now) {
        if ((sh.ops++ & 0x3FF) != 0) return;   // 每 1024 次观测（按分片）扫一次
        auto inv = inventory_.load();
        for (auto it = sh.items.begin(); it != sh.items.end();) {
            bool registered = inv && inv->keys.count(it->first);
            if (!registered && now - it->second.lastSeen > kRetentionSec) {
                it = sh.items.erase(it);
                total_.fetch_sub(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }

    static View toView(const Item& rec, int64_t now, int zombieDays) {
        View v;
        v.appId = rec.appId; v.method = rec.method; v.tpl = rec.tpl;
        v.firstSeen = rec.firstSeen; v.lastSeen = rec.lastSeen;
        v.count = rec.count; v.errCount = rec.errCount;
        std::memcpy(v.cls, rec.cls, sizeof(v.cls));
        v.auth = rec.auth; v.cookie = rec.cookie; v.sensitive = rec.sensitive;
        v.paramMax = rec.paramMax;
        v.avgParams = rec.avgParams; v.avgEntropy = rec.avgEntropy;
        v.distinctSources = __builtin_popcountll(rec.ipBits);
        v.kind = "registered";   // 由 snapshotJson 按已登记清单覆盖为 shadow / zombie
        (void)now; (void)zombieDays;
        return v;
    }

    static void writeView(std::ostringstream& o, const View& v) {
        o << "{\"appId\":\"" << esc(v.appId) << "\""
          << ",\"method\":\"" << esc(v.method) << "\""
          << ",\"template\":\"" << esc(v.tpl) << "\""
          << ",\"kind\":\"" << esc(v.kind) << "\""
          << ",\"firstSeen\":" << v.firstSeen
          << ",\"lastSeen\":" << v.lastSeen
          << ",\"count\":" << v.count
          << ",\"errCount\":" << v.errCount
          << ",\"status\":{";
        bool f = true;
        for (int i = 1; i < 6; ++i) {
            if (!v.cls[i]) continue;
            if (!f) o << ",";
            f = false;
            o << "\"" << i << "xx\":" << v.cls[i];
        }
        o << "}"
          << ",\"auth\":\"" << (v.auth ? "1" : "0") << "\""
          << ",\"cookie\":\"" << (v.cookie ? "1" : "0") << "\""
          << ",\"sensitive\":" << (v.sensitive ? "true" : "false")
          << ",\"paramMax\":" << v.paramMax
          << ",\"avgParams\":" << v.avgParams
          << ",\"avgEntropy\":" << v.avgEntropy
          << ",\"sources\":" << v.distinctSources
          << ",\"contentType\":\"" << esc(v.contentType) << "\"}";
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
                    } else o += c;
            }
        }
        return o;
    }

    static void emitAssetEvent(const std::string& appId, const std::string& method,
                               const std::string& tpl, const std::string& ruleId,
                               const std::string& action, const std::string& severity,
                               const std::string& matched) {
        AttackEvent e;
        e.ts = (int64_t)std::time(nullptr);
        e.category = "APIAsset";
        e.action = action;
        e.ruleId = ruleId;
        e.severity = severity;
        e.uri = tpl;
        e.matched = matched + " | " + method + " " + tpl +
                    (appId.empty() ? "" : (" app=" + appId));
        EventBus<AttackEvent>::instance().publish(e);
    }

    void emitShadow(const std::string& appId, const std::string& method,
                    const std::string& tpl) {
        emitAssetEvent(appId, method, tpl, "API-SHADOW", "observe", "medium",
                       "unregistered api discovered");
    }
};

}  // namespace novawaf
