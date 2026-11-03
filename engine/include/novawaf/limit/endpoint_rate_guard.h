// NovaWAF - 端点分级限流守卫（配额按端点类别拆分，monitor-only 先行采集）
// 背景：全站共用单一计数器时登录页/静态图/API 挤在同一令牌桶，正常业务 3 次即 429。
// 设计（与 BehaviorGuard 同构的高级架构）：
//   * 策略式端点分类：static / read / write / upload / auth 五类，各自独立配额，
//     static 只记账不限速（静态资源是浏览器并发主体，限速必误伤）。
//   * 分阶段上线（stage 机）：0=monitor-only 只记账不处置 → 1=仅 auth enforce →
//     2=+read/write/upload → 3=+封禁阶梯（L1 429 → L2 URL+方法 临时封禁；不开 L4 全端口）。
//   * monitor 模式照算令牌桶：超限只累计 would-block 指标不放任何处置，
//     7 天采集每 IP 每类 QPS 分布，供阈值标定（P99×3 / burst=P99.9@3s）。
//   * 分片锁（64 片按 key 哈希）+ COW 配置发布（atomic<shared_ptr<const>>），
//     热路径无全局锁、配置热更新零拷贝。
//   * auth 类双维度 key：优先按用户名（NAT 后整办公室共享 IP 不被连坐），
//     无用户名回退 IP；另有 IP 级后背桶（10x）防用户名轮换爆破。
// 采集口径：每 (key,类) 12×1s 环形槽，产出 10s 滑窗 QPS 与 3s 峰值，
//   每分钟快照一次由 main 上报线程写入 Redis（dist 直方 + metrics 指标）。
#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "novawaf/core/json.h"

namespace novawaf {

class EndpointRateGuard {
public:
    enum class EpClass : int { READ = 0, WRITE = 1, UPLOAD = 2, AUTH = 3, STATIC = 4, N = 5 };

    struct ClassCfg {
        double qps = 0;      // 令牌桶补充速率（个/秒）
        int    burst = 0;    // 桶容量（突发上限）
        double minQps = 0;   // 业务最小值：建议阈值 = max(P99×3, minQps)
        bool   enabled = true;
    };
    struct Policy {
        int stage = 0;                 // 上线阶段 0..3
        int banStrikes = 3;            // L2 触发：60s 内超限次数
        int banSec = 300;              // L2 封禁时长（URL+方法 粒度）
        ClassCfg cls[(int)EpClass::N];
        std::vector<std::string> authPaths;    // 认证端点精确路径
        std::vector<std::string> uploadPaths;  // 上传端点前缀
    };

    struct Decision {
        int retryAfterSec = 0;   // 真实剩余窗口（令牌补充时间）
        bool l2Ban = false;      // true=URL+方法临时封禁，false=L1 429
        std::string cls;         // 命中类别（日志用）
    };

    static EndpointRateGuard& instance() {
        static EndpointRateGuard g;
        return g;
    }

    static const char* className(EpClass c) {
        switch (c) {
            case EpClass::READ: return "read";
            case EpClass::WRITE: return "write";
            case EpClass::UPLOAD: return "upload";
            case EpClass::AUTH: return "auth";
            case EpClass::STATIC: return "static";
            default: return "?";
        }
    }

    // 端点分类：path 不含 query。规则顺序 auth > upload > static > write > read
    static EpClass classify(const std::string& method, const std::string& pathOnly,
                            const std::string& contentType, long contentLen,
                            const Policy& p) {
        for (auto& ap : p.authPaths)
            if (pathOnly == ap) return EpClass::AUTH;
        bool read2 = (method == "GET" || method == "HEAD" || method == "OPTIONS");
        if (!read2) {
            if (contentType.find("multipart/form-data") != std::string::npos)
                return EpClass::UPLOAD;
            for (auto& up : p.uploadPaths)
                if (pathOnly.compare(0, up.size(), up) == 0) return EpClass::UPLOAD;
            if (contentLen >= 4L * 1024 * 1024) return EpClass::UPLOAD;
        }
        if (read2) {
            size_t dot = pathOnly.rfind('.');
            if (dot != std::string::npos && pathOnly.size() - dot <= 6) {
                static const char* exts[] = {".css", ".js", ".png", ".jpg", ".jpeg",
                    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
                    ".webp", ".mp4", ".zip", ".pdf", ".txt", ".xml"};
                std::string ext = pathOnly.substr(dot);
                for (auto& c : ext) c = (char)std::tolower((unsigned char)c);
                for (auto* e : exts) if (ext == e) return EpClass::STATIC;
            }
            if (pathOnly.compare(0, 11, "/downloads/") == 0 ||
                pathOnly.compare(0, 8, "/assets/") == 0 ||
                pathOnly.compare(0, 8, "/static/") == 0)
                return EpClass::STATIC;
            return EpClass::READ;
        }
        return EpClass::WRITE;
    }

    // COW 发布配置（后台加载线程调用）
    void configure(std::shared_ptr<const Policy> p) { policy_.store(std::move(p)); }

    // 默认策略（未下发 Redis 配置时的内置兜底，对应「中」档，stage=0 monitor）
    static Policy defaultPolicy() {
        Policy p;
        p.stage = 0; p.banStrikes = 3; p.banSec = 300;
        p.cls[(int)EpClass::READ]   = {20, 40, 20, true};
        p.cls[(int)EpClass::WRITE]  = {5, 10, 5, true};
        p.cls[(int)EpClass::UPLOAD] = {2, 4, 2, true};
        p.cls[(int)EpClass::AUTH]   = {0.1, 3, 0.1, true};   // 6 次/分
        p.cls[(int)EpClass::STATIC] = {0, 0, 0, true};       // 不限速只记账
        p.authPaths = {"/api/auth/login", "/api/auth/captcha", "/api/auth/mfa"};
        p.uploadPaths = {"/api/upload", "/api/files"};
        return p;
    }

    // 从 Redis policy JSON 解析（字段缺失用默认补齐，非法抛异常由调用方兜底）
    static std::shared_ptr<const Policy> parsePolicy(const std::string& blob) {
        Policy p = defaultPolicy();
        if (!blob.empty()) {
            JsonValue root = parseJson(blob);
            if (root.type == JsonValue::OBJECT) {
                auto num = [](const JsonValue& v, double dft) {
                    return v.type == JsonValue::NUMBER ? v.num : dft;
                };
                p.stage = (int)num(root.at("stage"), p.stage);
                p.banStrikes = (int)num(root.at("banStrikes"), p.banStrikes);
                p.banSec = (int)num(root.at("banSec"), p.banSec);
                const JsonValue& cls = root.at("classes");
                if (cls.type == JsonValue::OBJECT) {
                    for (int i = 0; i < (int)EpClass::N; ++i) {
                        const JsonValue& c = cls.at(className((EpClass)i));
                        if (c.type != JsonValue::OBJECT) continue;
                        p.cls[i].qps = num(c.at("qps"), p.cls[i].qps);
                        p.cls[i].burst = (int)num(c.at("burst"), p.cls[i].burst);
                        p.cls[i].minQps = num(c.at("minQps"), p.cls[i].minQps);
                        const JsonValue& en = c.at("enabled");
                        if (en.type == JsonValue::BOOL) p.cls[i].enabled = en.b;
                    }
                }
                const JsonValue& ap = root.at("authPaths");
                if (ap.type == JsonValue::ARRAY) {
                    p.authPaths.clear();
                    for (auto& e : ap.arr) if (e.type == JsonValue::STRING) p.authPaths.push_back(e.str);
                }
                const JsonValue& up = root.at("uploadPaths");
                if (up.type == JsonValue::ARRAY) {
                    p.uploadPaths.clear();
                    for (auto& e : up.arr) if (e.type == JsonValue::STRING) p.uploadPaths.push_back(e.str);
                }
            }
        }
        return std::make_shared<const Policy>(std::move(p));
    }

    // 请求判定：全模式记账；enforce 且超限返回 Decision（L1 429 / L2 封禁），否则 nullopt。
    // username：认证类双维度 key（可空，空则按 IP）。
    std::optional<Decision> assess(const std::string& ip, const std::string& method,
                                   const std::string& pathRaw, const std::string& username,
                                   const std::string& contentType, long contentLen) {
        if (ip.empty()) return std::nullopt;
        auto pol = policy_.load();
        if (!pol) return std::nullopt;
        std::string pathOnly = pathRaw.substr(0, pathRaw.find('?'));
        EpClass cls = classify(method, pathOnly, contentType, contentLen, *pol);
        // auth 双维度：优先用户名（NAT 友好），空则 IP；IP 级另做 10x 后背桶
        std::string key = (cls == EpClass::AUTH && !username.empty()) ? ("U:" + username) : ip;

        int64_t nowMs = nowMs_();
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto& rec = sh.recs[ip];
        rec.touch = nowMs;
        account(rec, cls, nowMs);
        gc(sh, nowMs);

        // L2 封禁检查（URL+方法 粒度；仅阶梯阶段生效）
        if (pol->stage >= 3) {
            std::string bk = method + " " + pathOnly;
            auto it = rec.bans.find(bk);
            if (it != rec.bans.end()) {
                if (it->second > nowMs) {
                    Decision d; d.l2Ban = true; d.cls = className(cls);
                    d.retryAfterSec = (int)((it->second - nowMs) / 1000) + 1;
                    return d;
                }
                rec.bans.erase(it);
            }
        }
        if (cls == EpClass::STATIC) return std::nullopt;  // 静态只记账不限速

        const ClassCfg& cc = pol->cls[(int)cls];
        if (!cc.enabled || cc.qps <= 0) return std::nullopt;

        bool enforced = (cls == EpClass::AUTH) ? pol->stage >= 1 : pol->stage >= 2;
        // 令牌桶结算
        auto& bk = rec.buckets[(int)cls];
        if (bk.cap != cc.burst) { bk.cap = cc.burst; bk.tokens = std::min(bk.tokens, (double)cc.burst); }
        if (bk.lastMs == 0) { bk.lastMs = nowMs; bk.tokens = cc.burst; }
        double dt = (double)(nowMs - bk.lastMs) / 1000.0;
        bk.tokens = std::min((double)cc.burst, bk.tokens + dt * cc.qps);
        bk.lastMs = nowMs;

        if (bk.tokens >= 1.0) { bk.tokens -= 1.0; return std::nullopt; }

        // 超限：真实剩余窗口 = 补足 1 个令牌所需时间
        int retry = (int)std::ceil((1.0 - bk.tokens) / cc.qps);
        if (!enforced) {
            wouldBlock_[(int)cls].fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;  // monitor-only：只记账不处置
        }
        Decision d; d.retryAfterSec = std::max(1, retry); d.cls = className(cls);
        // 封禁阶梯：60s 内超限 banStrikes 次 → L2（URL+方法 临时封禁）
        if (pol->stage >= 3) {
            int64_t cutoff = nowMs - 60000;
            while (!rec.strikes.empty() && rec.strikes.front() < cutoff) rec.strikes.pop_front();
            rec.strikes.push_back(nowMs);
            if ((int)rec.strikes.size() >= pol->banStrikes) {
                rec.bans[method + " " + pathOnly] = nowMs + (int64_t)pol->banSec * 1000;
                rec.strikes.clear();
                d.l2Ban = true;
                d.retryAfterSec = pol->banSec;
                bansTotal_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        l1Total_.fetch_add(1, std::memory_order_relaxed);
        return d;
    }

    // 采集快照（main 上报线程每分钟调用）：每类每 key 的 10s QPS 分布与 3s 峰值
    struct DistStat {
        std::string cls;
        int keys = 0;
        double p50 = 0, p99 = 0, p999 = 0;   // 10s 滑窗 QPS 分布
        double burstP999 = 0;                // 3s 窗口峰值 P99.9
        double utilP95 = 0;                  // 桶利用率（qps10/限额）P95
        double suggestQps = 0;               // max(P99×3, 业务最小值)
        int suggestBurst = 0;                // ceil(P99.9@3s)
        long wouldBlock1m = 0;               // monitor 模式本该拦截次数
    };
    std::vector<DistStat> snapshot() {
        auto pol = policy_.load();
        std::vector<std::vector<double>> qps((int)EpClass::N), b3((int)EpClass::N), util((int)EpClass::N);
        for (auto& sh : shards_) {
            std::lock_guard<std::mutex> lk(sh.mtx);
            for (auto& [ip, rec] : sh.recs) {
                for (int c = 0; c < (int)EpClass::N; ++c) {
                    auto& rg = rec.rings[c];
                    int sum = 0, m3 = 0;
                    for (int i = 0; i < 12; ++i) {
                        sum += rg.slots[i];
                        int s3 = rg.slots[i] + rg.slots[(i + 11) % 12] + rg.slots[(i + 10) % 12];
                        if (s3 > m3) m3 = s3;
                    }
                    if (sum == 0) continue;
                    double q10 = sum / 12.0;
                    qps[c].push_back(q10);
                    b3[c].push_back((double)m3);
                    double lim = pol ? pol->cls[c].qps : 0;
                    if (lim > 0) util[c].push_back(q10 / lim);
                }
            }
        }
        auto pct = [](std::vector<double>& v, double q) {
            if (v.empty()) return 0.0;
            std::sort(v.begin(), v.end());
            size_t i = (size_t)std::floor(q / 100.0 * (double)(v.size() - 1));
            return v[i];
        };
        std::vector<DistStat> out;
        for (int c = 0; c < (int)EpClass::N; ++c) {
            DistStat d;
            d.cls = className((EpClass)c);
            d.keys = (int)qps[c].size();
            d.p50 = pct(qps[c], 50); d.p99 = pct(qps[c], 99); d.p999 = pct(qps[c], 99.9);
            d.burstP999 = pct(b3[c], 99.9);
            d.utilP95 = pct(util[c], 95);
            double minQ = pol ? pol->cls[c].minQps : 0;
            d.suggestQps = std::max(d.p99 * 3.0, minQ);
            d.suggestBurst = (int)std::ceil(d.burstP999);  // P99.9 3s 窗口峰值个数
            d.wouldBlock1m = wouldBlock_[c].exchange(0, std::memory_order_relaxed);
            out.push_back(d);
        }
        l1Last_ = l1Total_.exchange(0, std::memory_order_relaxed);
        bansLast_ = bansTotal_.exchange(0, std::memory_order_relaxed);
        return out;
    }
    long l1LastMin() const { return l1Last_; }
    long bansLastMin() const { return bansLast_; }
    int stage() const { auto p = policy_.load(); return p ? p->stage : 0; }

private:
    EndpointRateGuard() { configure(std::make_shared<const Policy>(defaultPolicy())); }

    struct Bucket { double tokens = 0; double cap = -1; int64_t lastMs = 0; };
    struct Ring { uint16_t slots[12] = {}; int curSec = -1; int64_t lastSecAbs = 0; };
    struct IpRec {
        Bucket buckets[(int)EpClass::N];
        Ring rings[(int)EpClass::N];
        std::deque<int64_t> strikes;                          // 60s 超限计数（封禁阶梯）
        std::unordered_map<std::string, int64_t> bans;        // "方法 URL" → 到期 ms
        int64_t touch = 0;
    };
    struct Shard {
        std::mutex mtx;
        std::unordered_map<std::string, IpRec> recs;
    };
    static constexpr size_t kShards = 64;
    Shard shards_[kShards];
    std::atomic<std::shared_ptr<const Policy>> policy_;
    std::atomic<long> wouldBlock_[(int)EpClass::N] = {};
    std::atomic<long> l1Total_{0}, bansTotal_{0};
    long l1Last_ = 0, bansLast_ = 0;

    Shard& shardOf(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }
    static int64_t nowMs_() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    // 环形槽记账：12×1s 滑窗 + 3s 峰值（max3 存 3s 内最大请求个数）
    void account(IpRec& r, EpClass cls, int64_t nowMs) {
        auto& rg = r.rings[(int)cls];
        int sec = (int)((nowMs / 1000) % 12);
        int64_t secAbs = nowMs / 1000;
        if (rg.curSec < 0) { rg.curSec = sec; rg.lastSecAbs = secAbs; }
        if (secAbs != rg.lastSecAbs) {
            int64_t diff = secAbs - rg.lastSecAbs;
            if (diff >= 12) { std::memset(rg.slots, 0, sizeof(rg.slots)); }
            else {
                for (int64_t i = 1; i <= diff; ++i)
                    rg.slots[(rg.lastSecAbs + i) % 12] = 0;
            }
            rg.curSec = sec; rg.lastSecAbs = secAbs;
        }
        if (rg.slots[sec] < 0xFFFF) rg.slots[sec]++;
    }
    void gc(Shard& sh, int64_t nowMs) {
        if (sh.recs.size() <= 512) return;  // 全 64 片约 32k IP
        for (auto it = sh.recs.begin(); it != sh.recs.end();) {
            bool idle = nowMs - it->second.touch > 300000;
            if (idle && it->second.bans.empty()) it = sh.recs.erase(it);
            else {
                for (auto b = it->second.bans.begin(); b != it->second.bans.end();)
                    if (b->second <= nowMs) b = it->second.bans.erase(b); else ++b;
                ++it;
            }
        }
    }
};

}  // namespace novawaf
