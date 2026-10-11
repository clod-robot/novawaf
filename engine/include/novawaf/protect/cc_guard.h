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

    // 评估请求，返回处置结果（PASS/CHALLENGE/BLOCK）
    DetectionResult assess(const std::string& ip, const std::string& path) {
        int64_t now = nowMs();
        double f = factor_.load(std::memory_order_acquire);
        int maxReq = (int)(cfg_.maxReqPerWindow * f);
        int burst = (int)(cfg_.burstPerUrl * f);
        int hot = (int)(cfg_.hotUrlGlobal * f);
        if (maxReq < 5) maxReq = 5;
        if (burst < 3) burst = 3;
        int score = 0;
        std::string reason;

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
            }
            // 单 IP 刷同一 URL
            int urlc = st.urlHits[path];
            if (urlc > burst) {
                score += 35 + (urlc - burst);
                if (reason.empty()) reason = "ip-url-burst";
            }
        }

        // 维度2：全局热点 URL（单独锁，路径较短）
        {
            std::lock_guard<std::mutex> lk(hotMtx_);
            evictHot(now);
            auto& v = hotUrl_[path];
            v.push_back(now);
            int g = (int)v.size();
            if (g > hot) {
                score += 25;
                if (reason.empty()) reason = "hot-url";
            }
        }

        Action a = Action::PASS;
        if (score >= cfg_.scoreToBlock) a = Action::BLOCK;
        else if (score >= cfg_.scoreToChallenge) a = Action::CHALLENGE;
        return {a, "CC-001", "CC", "HTTP flood / application-layer abuse", reason};
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

    std::mutex hotMtx_;
    std::unordered_map<std::string, std::deque<int64_t>> hotUrl_;
    int64_t lastHotEvict_ = 0;

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
    void evictHot(int64_t now) {
        if (now - lastHotEvict_ < 2000) return;  // 每 2s 才清理一次，降开销
        lastHotEvict_ = now;
        int64_t cutoff = now - cfg_.windowMs;
        for (auto it = hotUrl_.begin(); it != hotUrl_.end();) {
            auto& d = it->second;
            while (!d.empty() && d.front() < cutoff) d.pop_front();
            if (d.empty()) it = hotUrl_.erase(it); else ++it;
        }
    }

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

}  // namespace novawaf
