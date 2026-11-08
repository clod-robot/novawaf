// NovaWAF - 洪泛攻击防护（ICMP/SYN/ACK/DNS/UDP/HTTP 统一检测）
// 背景：DdosGuard 采用固定阈值（单 IP 200 并发 / 50 连接每秒 / 100 请求每秒），
//       固定阈值在真实业务里必然二选一：调松则漏报，调紧则误杀；且"整秒计数"
//       在窗口边界可被瞬时打成 2 倍速率（末尾灌满 + 下窗口开端再灌满）。
//
// 本模块用工业界常用的算法组合替代固定阈值：
//   1) 1s 桶环形滑窗      —— O(1) 写入、无窗口边界突刺，得到真实的每秒速率；
//   2) 令牌桶             —— 平滑限速并允许配置内突发，不整秒硬截断；
//   3) EWMA 均值 + EWMA 方差 —— 自适应基线，阈值 = μ + k·σ，随业务潮汐自动漂移；
//                            冷启动 warm-up + 绝对地板（floor）防止低流量下 σ→0
//                            导致"1 pps 也报警"；
//   4) CUSUM 累积和       —— 捕捉"每帧都不超阈值、但持续缓慢抬升"的低强度洪泛
//                            （固定阈值对此完全失效）；
//   5) 源分布香农熵/top1  —— 区分单源集中攻击（熵低、top1 高）、多源分布式攻击
//                            （熵高）与伪造源（速率高但顶级源占比低）；
//   6) 攻击期冻结基线学习 —— 防训练污染：否则持续洪泛几秒后基线被抬高，
//                            形成"自适应放行"；
//   7) 半开连接（握手完成/无请求）速率 —— SYN/ACK 洪泛在代理层唯一的可观测量，
//                            与内核 SYN 计数交叉判定后区分 SYN 与 ACK 洪泛；
//   8) 分片锁（64 片）+ 原子计数 —— 热路径无全局锁，1 核也能线性扩展。
//
// 处置：只产出 Verdict（类型/等级/置信度/观测量/阈值/建议），不直接封禁；
//       由 main 决定 429、DdosGuard 拉黑、还是联动 fw_enforcer 下发协议级限速。
#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {
// 独立子命名空间：避免与 limit/rate_limiter.h 中已有的 TokenBucket 等同名类型冲突
namespace flood_detail {

// ============================== 1s 桶环形滑窗 ==============================
class SecWindow {
public:
    explicit SecWindow(int secs = 60)
        : secs_(secs < 2 ? 2 : secs), bucket_((size_t)secs_, 0), stamp_((size_t)secs_, -1) {}

    void add(int64_t nowSec, uint64_t v = 1) {
        size_t i = (size_t)((uint64_t)nowSec % (uint64_t)secs_);
        if (stamp_[i] != nowSec) { stamp_[i] = nowSec; bucket_[i] = 0; }
        bucket_[i] += v;
    }
    uint64_t sum(int64_t nowSec) const {
        const int64_t lo = nowSec - secs_ + 1;
        uint64_t s = 0;
        for (size_t i = 0; i < bucket_.size(); ++i)
            if (stamp_[i] >= lo) s += bucket_[i];
        return s;
    }
    double ratePerSec(int64_t nowSec) const { return (double)sum(nowSec) / (double)secs_; }

private:
    int secs_;
    std::vector<uint64_t> bucket_;
    std::vector<int64_t> stamp_;
};

// ================================ 令牌桶 ================================
// 平滑限速：容量 burst 允许短突发，之后按 ratePerSec 匀速回充。
// 与"整秒计数器"相比不会在秒边界放行 2 倍流量，也不会把正常的瞬时并发判成攻击。
class TokenBucket {
public:
    void configure(double ratePerSec, double burst) {
        rate_ = ratePerSec > 0 ? ratePerSec : 1.0;
        cap_ = burst > 0 ? burst : 1.0;
        if (tokens_ > cap_) tokens_ = cap_;
        if (lastMs_ == 0) tokens_ = cap_;
    }
    bool take(int64_t nowMs) {
        if (lastMs_ == 0) { lastMs_ = nowMs; tokens_ = cap_; }
        double dt = (double)(nowMs - lastMs_) / 1000.0;
        if (dt > 0) {
            tokens_ = std::min(cap_, tokens_ + dt * rate_);
            lastMs_ = nowMs;
        }
        if (tokens_ >= 1.0) { tokens_ -= 1.0; return true; }
        return false;
    }
    double tokens() const { return tokens_; }

private:
    double rate_ = 10.0, cap_ = 20.0, tokens_ = 0.0;
    int64_t lastMs_ = 0;
};

// ========================== 自适应异常检测器 ==========================
// EWMA(μ, σ²) 建立基线，阈值 μ+kσ；CUSUM 检测持续性微小偏移；连续确认后报警。
class AdaptiveDetector {
public:
    struct Params {
        double alpha = 0.05;      // EWMA 平滑系数（越大越灵敏、越易抖动）
        double k = 4.0;           // 阈值倍数：μ + k·σ
        double floor = 20.0;      // 绝对地板：低流量时避免 σ→0 导致的过敏感
        int    warmup = 30;       // 学习样本数（秒），期间不报警
        double cusumSlack = 0.5;  // CUSUM 允许的漂移（以 σ 为单位）
        double cusumH = 6.0;      // CUSUM 报警门限
        int    confirm = 3;       // 连续异常秒数确认，抗单点毛刺
    };

    AdaptiveDetector() = default;
    explicit AdaptiveDetector(const Params& p) : p_(p) {}
    void params(const Params& p) { p_ = p; }

    // 每 1s 喂入一个样本；返回 true 表示当前处于持续异常态
    bool observe(double x) {
        lastX_ = x;
        if (n_ < (int64_t)p_.warmup) {
            update(x);
            ++n_;
            streak_ = 0;
            alarm_ = false;
            lastThr_ = std::max(p_.floor, mean_ + p_.k * sigma());
            return false;
        }
        const double sd = sigma();
        const double thr = std::max(p_.floor, mean_ + p_.k * sd);
        lastThr_ = thr;
        const bool inst = x > thr;
        double z = (x - mean_) / sd;
        if (z < 0) z = 0;
        cusum_ = std::max(0.0, cusum_ + z - p_.cusumSlack);
        // 封顶：爆发期 z 可达数百，若不封顶，攻击停止后需数百秒才能衰减回门限以下，
        // 形成"报警卡死"（误杀 IP 后长时间不放行）。封顶到门限即满足"持续抬升"的语义。
        if (cusum_ > p_.cusumH) cusum_ = p_.cusumH;
        // CUSUM 只在"样本仍高于基线"且"达到绝对地板"时才成立：攻击刚结束时 cusum
        // 还停在门限上，若不加 x > mean 的约束，回落的首秒会误判为另一类洪泛；
        // 若不加 x >= floor 的约束，生产环境的正常低速背景流量（如常驻 50pps 的 ACK）
        // 相对"近似零"的学习基线会被 CUSUM 缓慢累积成"持续抬升"，误报低速洪泛。
        // 低于地板速率的抬升不是洪泛（地板可用 NOVA_FLOOD_FLOOR 调整）。
        const bool suspect = inst || (cusum_ >= p_.cusumH && x > mean_ && x >= p_.floor);
        streak_ = suspect ? streak_ + 1 : 0;
        if (!suspect) cusum_ *= 0.5;          // 恢复期自然衰减
        alarm_ = streak_ >= p_.confirm;
        if (!suspect) update(x);              // 攻击期冻结学习，避免基线被污染
        return alarm_;
    }

    bool alarm() const { return alarm_; }
    double mean() const { return mean_; }
    double sigma() const { return std::sqrt(var_ < 1e-6 ? 1e-6 : var_); }
    double threshold() const { return lastThr_; }
    double lastSample() const { return lastX_; }
    double cusum() const { return cusum_; }
    int64_t samples() const { return n_; }
    // 相对超出倍数（用于置信度；1.0 表示未超阈值）
    double exceedRatio() const {
        const double t = lastThr_ > 1e-9 ? lastThr_ : 1.0;
        return lastX_ > 0 ? lastX_ / t : 1.0;
    }

private:
    void update(double x) {
        if (n_ == 0) { mean_ = x; var_ = 0; return; }
        const double d = x - mean_;
        mean_ += p_.alpha * d;
        var_ = (1.0 - p_.alpha) * var_ + p_.alpha * d * d;
        if (var_ < 1e-6) var_ = 1e-6;
    }

    Params p_{};
    int64_t n_ = 0;
    double mean_ = 0, var_ = 0, cusum_ = 0, lastThr_ = 0, lastX_ = 0;
    int streak_ = 0;
    bool alarm_ = false;
};

}  // namespace flood_detail

// ============================== 洪泛统一判定 ==============================
class FloodGuard {
public:
    using SecWindow = flood_detail::SecWindow;
    using TokenBucket = flood_detail::TokenBucket;
    using AdaptiveDetector = flood_detail::AdaptiveDetector;

    // 攻击类型：与产品验收口径一致（ICMP/SYN/ACK/DNS/UDP/HTTP）
    enum class Kind : int { NONE = 0, ICMP, SYN, ACK, DNS, UDP, HTTP, N };
    static const char* kindName(Kind k) {
        switch (k) {
            case Kind::ICMP: return "ICMPFLOOD";
            case Kind::SYN:  return "SYNFLOOD";
            case Kind::ACK:  return "ACKFLOOD";
            case Kind::DNS:  return "DNSFLOOD";
            case Kind::UDP:  return "UDPFLOOD";
            case Kind::HTTP: return "HTTPFLOOD";
            default:         return "NONE";
        }
    }

    struct Config {
        bool enabled = true;
        // 单 IP 令牌桶（平滑；替代 DdosGuard 的整秒硬阈值）
        double connRatePerSec = 30.0, connBurst = 60.0;
        double reqRatePerSec  = 50.0, reqBurst  = 100.0;
        // 半开连接：accept 后多久没收到完整请求判为可疑
        int    halfOpenMs = 3000;
        // 判定确认后，对已锁定单源的硬拒时长（秒）——仅用于"源高度集中"的 HTTP 洪泛
        int    confirmBanSec = 90;
        // 自适应检测器参数（可按业务形态覆盖）
        double kSigma = 4.0;
        double floorQps = 20.0;
        int    warmupSec = 30;
        // 熵阈值：低于该值判为"源高度集中"（单机/单隧道攻击）
        double entropyConcentrated = 2.0;
        // 每秒种最大评估的 IP 条目（防超大表拖慢 tick）
        int    maxScanEntries = 200000;
    };

    struct Verdict {
        Kind kind = Kind::NONE;
        int level = 0;            // 0=正常 1=可疑 2=确认攻击 3=严重
        double confidence = 0;    // 0..1
        double observed = 0;      // 观测速率
        double threshold = 0;     // 当时阈值
        double entropy = 0;       // 源分布熵（bit）
        double topShare = 0;      // 最大单源占比
        std::string detail;       // 人类可读说明（日志/上报）
    };

    struct Stats {
        double connPerSec = 0, halfOpenPerSec = 0, reqPerSec = 0, errPerSec = 0;
        double connMean = 0, connThreshold = 0;
        double reqMean = 0, reqThreshold = 0;
        double entropy = 0, topShare = 0;
        double uniqueSources = 0;
        int64_t trackedIps = 0;
        Verdict verdict;
    };

    // 进程级单例：多 reactor 共享同一份基线与计数（否则每个 reactor 各自学习，
    // 阈值被稀释 N 倍、源分布熵也只剩局部视图）。首次调用读取 NOVA_FLOOD_* 覆盖。
    // 定义放在类外：嵌套 Config 的默认成员初始化器不能在类内提前使用（GCC 约束）。
    static FloodGuard& instance();
    static Config makeEnvConfig();

    // 构造函数体放在类外（见文件末尾）：Config 的默认成员初始化器不能在
    // 外层类定义内被引用（即使只是作为默认实参），否则 GCC 报
    // "default member initializer required before the end of its enclosing class"。
    FloodGuard();
    explicit FloodGuard(const Config& c);

    // ---------------- 连接层 ----------------
    // accept 后调用。令牌桶只作为"违规证据"累计，不自行封禁——否则第一个被
    // 秒级硬限速拦下的源就再也进不到请求层，自适应检测器看不到真实速率，
    // 只会得到"连接被拒"的假象（既无法判类型，也无法给出置信度）。
    // 真正硬拒仅针对已被判定确认的攻击源（lockedUntilMs，由 tick 依据判定写入）。
    bool allowConnect(const std::string& ip, int64_t nowMs) {
        if (!cfg_.enabled || ip.empty()) return true;
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto& st = sh.ips[ip];
        touch(st, nowMs);
        if (st.lockedUntilMs > nowMs) return false;   // 已确认攻击源：硬拒
        st.conn.configure(cfg_.connRatePerSec, cfg_.connBurst);
        if (!st.conn.take(nowMs)) ++st.overConnect;   // 仅记录平滑限速违规次数
        ++st.connThisSec;
        ++acceptedThisSec_;
        return true;
    }

    // 连接关闭：hadRequest=false 表示握手完成但整条连接没发出完整请求（半开/ACK 洪泛特征）
    void noteConnectClosed(const std::string& ip, int64_t nowMs, bool hadRequest) {
        if (!cfg_.enabled || ip.empty()) return;
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto it = sh.ips.find(ip);
        if (it != sh.ips.end()) touch(it->second, nowMs);
        if (!hadRequest) ++halfOpenThisSec_;
    }

    // ---------------- 请求层 ----------------
    bool allowRequest(const std::string& ip, int64_t nowMs, bool* overLimit = nullptr) {
        if (!cfg_.enabled || ip.empty()) return true;
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto& st = sh.ips[ip];
        touch(st, nowMs);
        if (st.lockedUntilMs > nowMs) return false;
        st.req.configure(cfg_.reqRatePerSec, cfg_.reqBurst);
        if (!st.req.take(nowMs)) {
            ++st.overReq;
            if (overLimit) *overLimit = true;   // 交上层决定 429（本模块不擅自动作）
        }
        ++reqThisSec_;
        ++st.reqThisSec;
        return true;
    }

    void noteStatus(int status) {
        if (status >= 400 && status < 500) ++errThisSec_;
    }

    // 内核计数器喂入（ICMP/UDP/DNS 由 fw_enforcer 用 nft counter 采集，SYN 同源）
    void observeL4(Kind k, double pps) {
        const int i = (int)k;
        if (i <= 0 || i >= (int)Kind::N) return;
        l4Pps_[i].store(pps, std::memory_order_relaxed);
    }

    // ---------------- 每秒评估 ----------------
    void tick(int64_t nowSec) {
        if (!cfg_.enabled) return;
        const double acc   = (double)acceptedThisSec_.exchange(0, std::memory_order_relaxed);
        const double half  = (double)halfOpenThisSec_.exchange(0, std::memory_order_relaxed);
        const double req   = (double)reqThisSec_.exchange(0, std::memory_order_relaxed);
        const double err   = (double)errThisSec_.exchange(0, std::memory_order_relaxed);
        chosenTopIp_.clear();
        chosenShare_ = 0;

        // 源分布：请求维与连接维各自统计。连接维不可省——当前置固定阈值限速
        // 先把请求挡掉时，请求维为空，但"连接尝试速率+其源分布"仍是真实观测量，
        // 否则连接型洪泛（新建连接灌满）在检测器眼里就是一片空白。
        // 香农熵单趟可得：H = log2(N) - (1/N)·Σ c·log2(c)，Σc·log2(c) 可加。
        double unique = 0;
        double reqTotal = 0, reqTop1 = 0, reqClogC = 0;
        double connTotal = 0, connTop1 = 0, connClogC = 0;
        std::string reqTopIp, connTopIp;
        const int64_t idleCutoff = nowSec - 120;
        for (size_t si = 0; si < kShards; ++si) {
            Shard& sh = shards_[si];
            std::lock_guard<std::mutex> lk(sh.mtx);
            for (auto it = sh.ips.begin(); it != sh.ips.end();) {
                auto& st = it->second;
                const double cr = (double)st.reqThisSec;
                const double cc = (double)st.connThisSec;
                if (cr > 0) {
                    ++unique;
                    reqTotal += cr; reqClogC += cr * std::log2(cr);
                    if (cr > reqTop1) { reqTop1 = cr; reqTopIp = it->first; }
                }
                if (cc > 0) {
                    connTotal += cc; connClogC += cc * std::log2(cc);
                    if (cc > connTop1) { connTop1 = cc; connTopIp = it->first; }
                }
                st.reqThisSec = 0;
                st.connThisSec = 0;
                if (st.lockedUntilMs <= nowSec * 1000 &&
                    (int64_t)(st.lastSeenMs / 1000) < idleCutoff) {
                    it = sh.ips.erase(it);
                } else {
                    ++it;
                }
            }
            sh.tracked = sh.ips.size();
        }
        auto entropyOf = [](double t, double sc) {
            return t > 1 ? std::max(0.0, std::log2(t) - sc / t) : 0.0;
        };
        // 请求维有样本时用它（更贴近用户视角），否则退回连接维
        const bool useReqDim = reqTotal > 0;
        entropy_ = useReqDim ? entropyOf(reqTotal, reqClogC) : entropyOf(connTotal, connClogC);
        topShare_ = useReqDim ? (reqTotal > 0 ? reqTop1 / reqTotal : 0.0)
                              : (connTotal > 0 ? connTop1 / connTotal : 0.0);
        uniqueSrc_ = unique;

        // 半开估计：本秒"建连数 - 完成请求数"的差额（代理层看不到 SYN 时的主要特征）。
        // 与关闭事件计数取大值，避免 DdosGuard 提前 close 导致关闭钩子没机会执行。
        const double halfOpenEst = std::max(half, std::max(0.0, acc - req));

        detConn_.observe(acc);
        detHalf_.observe(halfOpenEst);
        detReq_.observe(req);
        detErr_.observe(err);
        connPerSec_ = acc; halfPerSec_ = halfOpenEst; reqPerSec_ = req; errPerSec_ = err;

        Verdict v;
        // 1) L7：请求速率异常 / 4xx 放大 / 连接尝试速率异常
        const bool reqBad = detReq_.alarm() ||
                            (detErr_.alarm() && err > 0 && err / std::max(1.0, req) > 0.5);
        const bool connBad = detConn_.alarm();
        // 绝对地板二次把关：CUSUM 在"基线≈0"时对 1~2 个残留样本也会累积，
        // 攻击刚结束的回尾会被误判成新攻击类型。低于地板速率的"异常"不是洪泛。
        const double minRate = std::max(1.0, cfg_.floorQps);
        if ((reqBad && req >= minRate) || (connBad && acc >= minRate)) {
            const bool useReq = reqBad && req >= minRate;
            // 维度与判定一致：请求维异常看请求源分布，连接维异常看连接源分布
            const double dimTotal = useReq ? reqTotal : connTotal;
            const double dimEntropy = useReq ? entropyOf(reqTotal, reqClogC)
                                             : entropyOf(connTotal, connClogC);
            const double dimShare = useReq ? (reqTotal > 0 ? reqTop1 / reqTotal : 0.0)
                                           : (connTotal > 0 ? connTop1 / connTotal : 0.0);
            v.kind = Kind::HTTP;
            v.level = 2;
            v.observed = useReq ? req : acc;
            v.threshold = useReq ? detReq_.threshold() : detConn_.threshold();
            v.entropy = dimEntropy;
            v.topShare = dimShare;
            v.confidence = std::min(1.0, std::max(detReq_.exceedRatio(), detConn_.exceedRatio()) / 4.0);
            if (dimTotal > 0 && dimEntropy < cfg_.entropyConcentrated) {
                v.level = 3;
                v.detail = "HTTPFLOOD single-source";
            } else {
                v.detail = "HTTPFLOOD distributed";
            }
            // 记录当次判定所用的维度，tick 末尾据此选择需锁定的最大单源
            chosenTopIp_ = useReq ? reqTopIp : connTopIp;
            chosenShare_ = dimShare;
        }
        // 2) L3/L4：内核/联动计数器异常（ICMP/UDP/DNS/SYN/ACK 精确 pps）
        if (v.kind == Kind::NONE) {
            for (int i = 1; i < (int)Kind::N; ++i) {
                if (i == (int)Kind::HTTP) continue;
                const double pps = l4Pps_[i].load(std::memory_order_relaxed);
                // 零值也喂入：否则空闲期基线停在旧值，一次小突发就会误报
                detL4_[i].observe(pps);
                if (pps >= minRate * 0.5 && detL4_[i].alarm()) {
                    v.kind = (Kind)i;
                    v.level = 2;
                    v.observed = pps;
                    v.threshold = detL4_[i].threshold();
                    v.confidence = std::min(1.0, detL4_[i].exceedRatio() / 4.0);
                    v.detail = std::string(kindName((Kind)i)) + " protocol-rate anomaly";
                    if (detL4_[i].exceedRatio() > 4.0) v.level = 3;
                    break;
                }
            }
        }
        // 3) 半开连接异常（无内核计数时的兜底，例如纯 ACK 洪泛）
        if (v.kind == Kind::NONE && detHalf_.alarm() && acc >= minRate &&
            halfOpenEst >= minRate * 0.5 && halfOpenEst / acc > 0.5) {
            v.kind = Kind::ACK;
            v.level = 2;
            v.observed = halfOpenEst;
            v.threshold = detHalf_.threshold();
            v.entropy = entropy_;
            v.topShare = topShare_;
            v.confidence = std::min(1.0, detHalf_.exceedRatio() / 4.0);
            v.detail = "ACK/half-open flood (handshake done, no request)";
        }
        // 证据驱动的定向处置：只有"判定已确认"且源分布确实集中（topShare 高）时，
        // 才把最大单源锁定一段时间硬拒。分布式/伪造源攻击不锁定任何单 IP——
        // 锁错一个正常用户比不锁更糟，这类攻击交给内核侧限速（fw_enforcer）。
        if (v.level >= 2 && v.kind == Kind::HTTP && !chosenTopIp_.empty() && chosenShare_ >= 0.2) {
            Shard& sh = shardOf(chosenTopIp_);
            std::lock_guard<std::mutex> lk(sh.mtx);
            auto it = sh.ips.find(chosenTopIp_);
            if (it != sh.ips.end())
                it->second.lockedUntilMs = std::max(it->second.lockedUntilMs,
                                                    nowSec * 1000 + (int64_t)cfg_.confirmBanSec * 1000);
        }
        {
            std::lock_guard<std::mutex> lk(vMtx_);
            verdict_ = v;
        }
    }

    // ---------------- 输出 ----------------
    bool enabled() const { return cfg_.enabled; }

    Verdict verdict() const {
        std::lock_guard<std::mutex> lk(vMtx_);
        return verdict_;
    }

    // 取走"已确认、需要联动封禁"的 IP（调用后清空），由 main 投递 FwBanPoster
    std::vector<std::string> takeOffenders(int64_t nowMs) {
        std::vector<std::string> out;
        for (size_t si = 0; si < kShards; ++si) {
            Shard& sh = shards_[si];
            std::lock_guard<std::mutex> lk(sh.mtx);
            for (auto it = sh.ips.begin(); it != sh.ips.end(); ++it) {
                if (it->second.lockedUntilMs > nowMs && !it->second.reported) {
                    it->second.reported = true;
                    out.push_back(it->first);
                }
            }
        }
        return out;
    }

    Stats stats() {
        Stats s;
        s.connPerSec = connPerSec_; s.halfOpenPerSec = halfPerSec_;
        s.reqPerSec = reqPerSec_; s.errPerSec = errPerSec_;
        s.connMean = detConn_.mean(); s.connThreshold = detConn_.threshold();
        s.reqMean = detReq_.mean(); s.reqThreshold = detReq_.threshold();
        s.entropy = entropy_; s.topShare = topShare_; s.uniqueSources = uniqueSrc_;
        for (size_t si = 0; si < kShards; ++si) {
            Shard& sh = shards_[si];
            std::lock_guard<std::mutex> lk(sh.mtx);
            s.trackedIps += (int64_t)sh.ips.size();
        }
        s.verdict = verdict();
        return s;
    }

    // 处理名单中的 IP 剩余锁定时长（ms），供上层决定封禁 TTL
    static constexpr int lockSec() { return 300; }

private:
    static constexpr size_t kShards = 64;

    struct IpState {
        TokenBucket conn, req;
        int64_t lastSeenMs = 0;
        int64_t lockedUntilMs = 0;   // >now 表示"判定已确认"的攻击源，直接硬拒
        uint32_t reqThisSec = 0;
        uint32_t connThisSec = 0;               // 本秒建连次数（连接型洪泛的源分布依据）
        uint32_t overConnect = 0, overReq = 0;  // 令牌桶违规证据（不据此封禁）
        bool reported = false;
    };
    struct Shard {
        std::mutex mtx;
        std::unordered_map<std::string, IpState> ips;
        size_t tracked = 0;
    };

    void touch(IpState& st, int64_t nowMs) const { st.lastSeenMs = nowMs; }

    Shard& shardOf(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }

    Config cfg_;
    std::unique_ptr<Shard[]> shards_;  // 分片含 mutex，不可 move，故用定长数组

    std::atomic<uint32_t> acceptedThisSec_{0};
    std::atomic<uint32_t> halfOpenThisSec_{0};
    std::atomic<uint32_t> reqThisSec_{0};
    std::atomic<uint32_t> errThisSec_{0};

    AdaptiveDetector detConn_, detHalf_, detReq_, detErr_;
    AdaptiveDetector detL4_[(int)Kind::N];
    std::atomic<double> l4Pps_[(int)Kind::N] = {};

    mutable std::mutex vMtx_;
    Verdict verdict_{};
    double connPerSec_ = 0, halfPerSec_ = 0, reqPerSec_ = 0, errPerSec_ = 0;
    double entropy_ = 0, topShare_ = 0, uniqueSrc_ = 0;
    std::string chosenTopIp_;     // 本次判定维度下的最大单源
    double chosenShare_ = 0;      // 其在同维度中的占比
};

inline FloodGuard::FloodGuard() : FloodGuard(Config{}) {}

inline FloodGuard::FloodGuard(const Config& c) : cfg_(c), shards_(std::make_unique<Shard[]>(kShards)) {
    auto mk = [this](double floor) {
        AdaptiveDetector::Params p;
        p.k = cfg_.kSigma;
        p.floor = floor;
        p.warmup = cfg_.warmupSec;
        return AdaptiveDetector(p);
    };
    detConn_ = mk(cfg_.floorQps);
    detHalf_ = mk(cfg_.floorQps * 0.5);
    detReq_  = mk(cfg_.floorQps * 2.0);
    detErr_  = mk(cfg_.floorQps * 0.5);
    for (int i = 0; i < (int)Kind::N; ++i) detL4_[i] = mk(cfg_.floorQps * 5.0);
}

inline FloodGuard& FloodGuard::instance() {
    static FloodGuard inst(makeEnvConfig());
    return inst;
}

inline FloodGuard::Config FloodGuard::makeEnvConfig() {
    Config c;
    auto envD = [](const char* k, double d) {
        const char* e = std::getenv(k);
        return (e && *e) ? std::atof(e) : d;
    };
    auto envI = [](const char* k, int d) {
        const char* e = std::getenv(k);
        return (e && *e) ? std::atoi(e) : d;
    };
    const char* dis = std::getenv("NOVA_FLOOD_DISABLE");
    c.enabled = !(dis && *dis == '1');
    c.connRatePerSec = envD("NOVA_FLOOD_CONN_RATE", c.connRatePerSec);
    c.connBurst      = envD("NOVA_FLOOD_CONN_BURST", c.connBurst);
    c.reqRatePerSec  = envD("NOVA_FLOOD_REQ_RATE", c.reqRatePerSec);
    c.reqBurst       = envD("NOVA_FLOOD_REQ_BURST", c.reqBurst);
    c.confirmBanSec  = envI("NOVA_FLOOD_CONFIRM_BAN", c.confirmBanSec);
    c.kSigma         = envD("NOVA_FLOOD_KSIGMA", c.kSigma);
    c.floorQps       = envD("NOVA_FLOOD_FLOOR", c.floorQps);
    c.warmupSec      = envI("NOVA_FLOOD_WARMUP", c.warmupSec);
    c.entropyConcentrated = envD("NOVA_FLOOD_ENTROPY", c.entropyConcentrated);
    return c;
}

}  // namespace novawaf
