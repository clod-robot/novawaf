// NovaWaf - 动态防护（自适应）
// 能力：后台线程持续采样全局流量态势（总 QPS、拦截率、来源 IP 离散度），
//       当判定为"正在遭受攻击"时自动收紧防护阈值，攻击消退后自动恢复。
// 设计：观察者模式（订阅者在态势变更时被通知）+ 原子态势级别（无锁读）。
//       其它防护模块可注册回调，根据 level 动态调整自身阈值。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace novawaf {

enum class ThreatLevel { NORMAL = 0, ELEVATED = 1, HIGH = 2, SEVERE = 3 };

inline const char* levelName(ThreatLevel l) {
    switch (l) {
        case ThreatLevel::NORMAL:   return "NORMAL";
        case ThreatLevel::ELEVATED: return "ELEVATED";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::SEVERE:   return "SEVERE";
    }
    return "?";
}

// 态势回调：level 变化时触发（观察者）
using ThreatObserver = std::function<void(ThreatLevel)>;

class DynamicShield {
public:
    struct Config {
        int sampleMs = 1000;            // 采样间隔
        int elevatedQps = 2000;         // 全局 QPS 超此 → ELEVATED
        int highQps = 8000;             // → HIGH
        int severeQps = 20000;          // → SEVERE
        double blockRateElevated = 0.15;// 拦截率超此也升级
        int ipSpreadElevated = 1000;    // 窗口内独立 IP 数（CC 常来自大量 IP）
    };

    explicit DynamicShield(const Config& cfg) : cfg_(cfg) {}

    void observe(ThreatObserver cb) {
        std::lock_guard<std::mutex> lk(cbMtx_);
        observers_.push_back(std::move(cb));
    }

    // 由请求路径调用：记录一次请求/拦截（极轻量，原子累加）
    void recordRequest() { reqCount_.fetch_add(1, std::memory_order_relaxed); }
    void recordBlock()   { blkCount_.fetch_add(1, std::memory_order_relaxed); }
    void recordIp(const std::string& ip) {
        // 独立 IP 用分片集合（采样线程负责读取后清空）
        size_t idx = std::hash<std::string>{}(ip) & (kIpShards - 1);
        auto& s = ipShards_[idx];
        std::lock_guard<std::mutex> lk(s.mtx);
        s.ips.insert(ip);
        if (s.ips.size() > 100000) s.ips.clear();  // 防内存爆炸
    }

    ThreatLevel level() const { return level_.load(std::memory_order_acquire); }

    // 启动后台采样线程；返回后线程运行，stop() 可退出
    void start() {
        running_.store(true, std::memory_order_release);
        worker_ = std::thread([this] { this->loop(); });
    }
    void stop() {
        running_.store(false, std::memory_order_release);
        if (worker_.joinable()) worker_.join();
    }
    ~DynamicShield() { stop(); }

private:
    Config cfg_;
    std::atomic<ThreatLevel> level_{ThreatLevel::NORMAL};
    std::atomic<uint64_t> reqCount_{0};
    std::atomic<uint64_t> blkCount_{0};
    std::atomic<bool> running_{false};
    std::thread worker_;

    struct IpShard { mutable std::mutex mtx; std::unordered_set<std::string> ips; };
    static constexpr size_t kIpShards = 16;
    IpShard ipShards_[kIpShards];

    std::mutex cbMtx_;
    std::vector<ThreatObserver> observers_;

    void loop() {
        uint64_t lastReq = 0, lastBlk = 0;
        while (running_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.sampleMs));
            uint64_t req = reqCount_.load(std::memory_order_relaxed);
            uint64_t blk = blkCount_.load(std::memory_order_relaxed);
            uint64_t dReq = req - lastReq;
            uint64_t dBlk = blk - lastBlk;
            lastReq = req; lastBlk = blk;

            double qps = dReq * 1000.0 / cfg_.sampleMs;
            double blockRate = dReq > 0 ? (double)dBlk / dReq : 0.0;

            // 独立 IP 数
            size_t ips = 0;
            for (auto& s : ipShards_) {
                std::lock_guard<std::mutex> lk(s.mtx);
                ips += s.ips.size();
                s.ips.clear();  // 每个采样窗口重置
            }

            ThreatLevel nl = ThreatLevel::NORMAL;
            if (qps >= cfg_.severeQps || blockRate >= 0.5) nl = ThreatLevel::SEVERE;
            else if (qps >= cfg_.highQps) nl = ThreatLevel::HIGH;
            else if (qps >= cfg_.elevatedQps || blockRate >= cfg_.blockRateElevated ||
                     ips >= (size_t)cfg_.ipSpreadElevated) nl = ThreatLevel::ELEVATED;

            ThreatLevel old = level_.exchange(nl, std::memory_order_acq_rel);
            if (old != nl) {
                std::lock_guard<std::mutex> lk(cbMtx_);
                for (auto& cb : observers_) {
                    if (cb) cb(nl);
                }
            }
        }
    }
};

}  // namespace novawaf
