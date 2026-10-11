// NovaWAF - DDoS 防护与常见网络攻击拦截
// 能力：每IP并发连接上限、新建连接速率限制、慢速攻击(Slowloris)检测、
//       动态自动封禁(命中阈值→黑名单TTL→到期自动解封)。
// 设计：分片锁降低并发竞争；所有计数原子化；纯逻辑平台无关。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {

class DdosGuard {
public:
    struct Config {
        int maxConcurrentPerIp = 200;      // 单 IP 并发连接上限（防连接耗尽）
        int newConnPerSec = 50;            // 单 IP 每秒新建连接上限（防 SYN/连接洪水）
        int reqPerSec = 100;               // 单 IP 每秒请求上限（防 CC/HTTP Flood）
        int slowTimeoutMs = 5000;          // 慢速攻击超时：连接建立后多少 ms 未发完请求算攻击
        int banThreshold = 5;              // 累计违规多少次触发封禁
        int banSeconds = 300;              // 封禁时长（秒），到期自动解封
    };

    explicit DdosGuard(const Config& cfg) : cfg_(cfg), shards_(kShards) {}

    // 连接建立时调用，返回 true=放行，false=拒绝
    bool onConnect(const std::string& ip) {
        if (isBanned(ip)) return false;
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        ConnInfo& ci = s.conns[ip];
        // 并发连接上限
        if (ci.concurrent >= cfg_.maxConcurrentPerIp) {
            penalize(s, ip);
            return false;
        }
        // 新建连接速率
        int64_t now = nowMs();
        if (now - ci.windowStart >= 1000) {
            ci.windowStart = now;
            ci.newConnInWindow = 0;
        }
        if (ci.newConnInWindow >= cfg_.newConnPerSec) {
            penalize(s, ip);
            return false;
        }
        ci.newConnInWindow++;
        ci.concurrent++;
        ci.lastConnectMs = now;
        return true;
    }

    // 请求到达时调用（含速率限制），返回 true=放行
    bool onRequest(const std::string& ip) {
        if (isBanned(ip)) return false;
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        ConnInfo& ci = s.conns[ip];
        int64_t now = nowMs();
        if (now - ci.reqWindowStart >= 1000) {
            ci.reqWindowStart = now;
            ci.reqInWindow = 0;
        }
        if (ci.reqInWindow >= cfg_.reqPerSec) {
            penalize(s, ip);
            return false;
        }
        ci.reqInWindow++;
        return true;
    }

    // 慢速攻击检测：连接建立后是否超时未完成请求
    bool isSlowloris(const std::string& ip) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.conns.find(ip);
        if (it == s.conns.end()) return false;
        if (nowMs() - it->second.lastConnectMs > cfg_.slowTimeoutMs) {
            penalize(s, ip);
            return true;
        }
        return false;
    }

    // 连接关闭时调用，释放并发计数
    void onDisconnect(const std::string& ip) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.conns.find(ip);
        if (it != s.conns.end() && it->second.concurrent > 0)
            it->second.concurrent--;
    }

    bool isBanned(const std::string& ip) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.banned.find(ip);
        if (it == s.banned.end()) return false;
        if (nowMs() >= it->second) {      // 到期自动解封
            s.banned.erase(it);
            return false;
        }
        return true;
    }

    // 手动封禁/解封（管理面调用）
    void ban(const std::string& ip, int seconds) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        s.banned[ip] = nowMs() + seconds * 1000;
    }
    void unban(const std::string& ip) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        s.banned.erase(ip);
    }

    size_t bannedCount() const {
        size_t n = 0;
        for (auto& s : shards_) { std::lock_guard<std::mutex> lk(s.mtx); n += s.banned.size(); }
        return n;
    }

private:
    struct ConnInfo {
        int concurrent = 0;
        int newConnInWindow = 0;
        int reqInWindow = 0;
        int64_t windowStart = 0;
        int64_t reqWindowStart = 0;
        int64_t lastConnectMs = 0;
        int violations = 0;
    };

    struct Shard {
        mutable std::mutex mtx;
        std::unordered_map<std::string, ConnInfo> conns;
        std::unordered_map<std::string, int64_t> banned;  // ip -> 解禁时间戳
    };

    static constexpr size_t kShards = 64;

    Shard& shard(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }

    // 违规累计，达阈值自动封禁
    void penalize(Shard& s, const std::string& ip) {
        ConnInfo& ci = s.conns[ip];
        if (++ci.violations >= cfg_.banThreshold) {
            s.banned[ip] = nowMs() + cfg_.banSeconds * 1000;
            ci.violations = 0;
        }
    }

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    Config cfg_;
    std::vector<Shard> shards_;
};

}  // namespace novawaf
