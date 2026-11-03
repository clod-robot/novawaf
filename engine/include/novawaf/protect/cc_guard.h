// NovaWAF - CC（Challenge Collapsar / HTTP 应用层洪水）防护
// 能力：
//   1) 单 IP 滑动窗口请求速率限制（比固定 1 秒桶更平滑，抗突刺）
//   2) 热点 URL 检测（某 URL 被高频访问 → 整体加压）
//   3) 单 IP+URL 突发（CC 典型特征：少数 IP 狂刷同一 URL）
// 设计：策略模式（各检测维度独立评分后汇总）+ 分片锁降并发竞争 + 纯逻辑平台无关。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "novawaf/detect/http_model.h"

namespace novawaf {

class CcGuard {
public:
    struct Config {
        int windowMs = 10000;          // 滑动窗口长度（毫秒）
        int maxReqPerWindow = 200;     // 单 IP 窗口内请求上限
        int burstPerUrl = 60;          // 单 IP 对同一 URL 窗口内次数上限（CC 突刺）
        int hotUrlGlobal = 500;        // 某 URL 全局窗口内访问上限（热点保护）
        int scoreToBlock = 100;        // 累计评分达此值 → 拦截
        int scoreToChallenge = 40;     // 达此值 → 人机挑战
    };

    explicit CcGuard(const Config& cfg) : cfg_(cfg), shards_(kShards) {}

    // 动态防护回调：态势升级时按比例收紧阈值（观察者）
    void applyThreatLevel(int lvl) {
        // NORMAL=0 → factor 1.0；每升一级阈值 ×0.6（更严）
        double f = 1.0;
        for (int i = 0; i < lvl; ++i) f *= 0.6;
        factor_.store(f, std::memory_order_release);
    }

    // 评估请求，返回处置结果（PASS/CHALLENGE/BLOCK）。
    // quotaFactor：外部维度（如 Bot 指纹可信度）折算的配额系数 [0,1]——
    // 可疑客户端获得收紧但非零的配额，避免"裸头首请求即 429"的 0 容忍
    // （复测 P0：判定全压指纹上，复制一套浏览器头即可拿 38 倍配额）。
    // 命中限流时 retryAfterSec 填真实恢复秒数（窗口内最早过量请求的老化时间），
    // 取代硬编码 Retry-After（复测 P0：恒 30 与真实恢复 210-469s 偏差 7-16 倍）。
    DetectionResult assess(const std::string& ip, const std::string& path,
                           double quotaFactor = 1.0) {
        int64_t now = nowMs();
        double f = factor_.load(std::memory_order_acquire) * quotaFactor;
        int baseMax = (int)(cfg_.maxReqPerWindow * f);
        int baseBurst = (int)(cfg_.burstPerUrl * f);
        int hot = (int)(cfg_.hotUrlGlobal * factor_.load(std::memory_order_acquire));
        // 阈值抖动：按 IP 生成稳定的 ±15% 偏移（进程启动种子固定），
        // 使攻击者无法通过探测摸清统一阈值，而正常用户阈值稳定不影响体验。
        int maxReq = jitterFor(ip, baseMax);
        int burst = jitterFor(ip, baseBurst);
        if (maxReq < 5) maxReq = 5;
        if (burst < 3) burst = 3;
        int score = 0;
        std::string reason;
        int64_t retryMs = 0;  // 真实恢复耗时（各触发维度取最大——瓶颈维度决定恢复期）

        // 维度1+3：单 IP 速率 & 单 IP+URL 突刺（按 IP 分片，锁粒度小）
        {
            auto& s = shard(ip);
            std::lock_guard<std::mutex> lk(s.mtx);
            IpState& st = s.states[ip];
            evict(st, now);
            st.hits.push_back(now);
            st.urlHits[path]++;
            // 单 IP 总量
            int total = (int)st.hits.size();
            if (total > maxReq) {
                score += 40 + (total - maxReq);
                reason = "ip-rate";
                // 恢复点：最旧的 (total-maxReq) 条老化出窗后计数回落到阈值
                int64_t t = st.hits[total - maxReq - 1] + cfg_.windowMs - now;
                if (t > retryMs) retryMs = t;
            }
            // 单 IP 刷同一 URL
            int urlc = st.urlHits[path];
            if (urlc > burst) {
                score += 35 + (urlc - burst);
                if (reason.empty()) reason = "ip-url-burst";
                // urlHits 随窗口起点整体重置，恢复点即窗口翻页时刻
                int64_t t = st.windowStart + cfg_.windowMs - now;
                if (t > retryMs) retryMs = t;
            }
        }

        // 维度2：全局热点 URL（按 path 分片，消除全局单锁串行化）
        {
            size_t hi = std::hash<std::string>{}(path) & (kHotShards - 1);
            auto& hs = hotShards_[hi];
            std::lock_guard<std::mutex> lk(hs.mtx);
            evictHot(hs, now);
            auto& v = hs.urls[path];
            v.push_back(now);
            int g = (int)v.size();
            if (g > hot) {
                score += 25;
                if (reason.empty()) reason = "hot-url";
                int64_t t = v[g - hot - 1] + cfg_.windowMs - now;
                if (t > retryMs) retryMs = t;
            }
        }

        Action a = Action::PASS;
        if (score >= cfg_.scoreToBlock) a = Action::BLOCK;
        else if (score >= cfg_.scoreToChallenge) a = Action::CHALLENGE;
        DetectionResult r{a, "CC-001", "CC", "HTTP flood / application-layer abuse", reason};
        if (a != Action::PASS && retryMs > 0)
            r.retryAfterSec = (int)((retryMs + 999) / 1000);  // 向上取整，宁多不少
        r.score = score;
        return r;
    }

private:
    struct IpState {
        std::deque<int64_t> hits;                 // 窗口内所有请求时间戳
        std::unordered_map<std::string, int> urlHits;  // path -> 次数（粗粒度，随窗口重置）
        int64_t windowStart = 0;
    };
    struct Shard {
        mutable std::mutex mtx;
        std::unordered_map<std::string, IpState> states;
    };

    static constexpr size_t kShards = 64;
    Config cfg_;
    std::vector<Shard> shards_;
    std::atomic<double> factor_{1.0};

    struct HotShard {
        mutable std::mutex mtx;
        std::unordered_map<std::string, std::deque<int64_t>> urls;
        int64_t lastEvict = 0;
    };
    static constexpr size_t kHotShards = 32;
    std::vector<HotShard> hotShards_{kHotShards};

    Shard& shard(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }

    // 驱逐窗口外的时间戳；URL 计数也按窗口重置
    void evict(IpState& st, int64_t now) {
        int64_t cutoff = now - cfg_.windowMs;
        while (!st.hits.empty() && st.hits.front() < cutoff) st.hits.pop_front();
        if (now - st.windowStart >= cfg_.windowMs) {
            st.windowStart = now;
            st.urlHits.clear();
        }
    }
    void evictHot(HotShard& hs, int64_t now) {
        if (now - hs.lastEvict < 2000) return;  // 每 2s 才清理一次，降开销
        hs.lastEvict = now;
        int64_t cutoff = now - cfg_.windowMs;
        for (auto it = hs.urls.begin(); it != hs.urls.end();) {
            auto& d = it->second;
            while (!d.empty() && d.front() < cutoff) d.pop_front();
            if (d.empty()) it = hs.urls.erase(it); else ++it;
        }
    }

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // 按 IP 生成稳定的 ±15% 阈值抖动：同一 IP 阈值恒定（不影响正常体验），
    // 不同 IP 阈值不同（攻击者无法跨源归纳统一阈值）。进程启动种子固定。
    static int jitterFor(const std::string& ip, int base) {
        static const uint64_t seed =
            (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
        uint64_t h = std::hash<std::string>{}(ip) ^ seed;
        int delta = base * 15 / 100;
        if (delta < 1) delta = 1;
        int off = (int)(h % (uint64_t)(delta * 2 + 1)) - delta;
        int r = base + off;
        return r < 1 ? 1 : r;
    }
};

}  // namespace novawaf
