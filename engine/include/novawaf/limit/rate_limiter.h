// NovaWAF - 令牌桶限流器（线程安全，无锁原子实现）
// 用于 CC 攻击防护、暴力破解防护、基于源 IP 的速率限制。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <mutex>

namespace novawaf {

class TokenBucket {
public:
    // capacity: 桶容量（突发上限）; refillPerSec: 每秒补充令牌数
    TokenBucket(int64_t capacity, int64_t refillPerSec)
        : capacity_(capacity), tokens_(capacity),
          refillPerSec_(refillPerSec),
          lastRefill_(nowMs()) {}

    // 尝试取 1 个令牌，成功返回 true（放行），失败返回 false（限流）
    bool tryConsume() {
        refill();
        int64_t t = tokens_.load(std::memory_order_relaxed);
        while (t > 0) {
            if (tokens_.compare_exchange_weak(t, t - 1,
                    std::memory_order_acq_rel))
                return true;
        }
        return false;
    }

private:
    void refill() {
        int64_t now = nowMs();
        int64_t last = lastRefill_.load(std::memory_order_relaxed);
        if (now <= last) return;
        // CAS 更新时间戳，只有一个线程执行补充
        if (lastRefill_.compare_exchange_strong(last, now,
                std::memory_order_acq_rel)) {
            int64_t elapsed = now - last;
            int64_t add = (elapsed * refillPerSec_) / 1000;
            if (add > 0) {
                int64_t t = tokens_.load(std::memory_order_relaxed);
                int64_t nt;
                do {
                    nt = (t + add > capacity_) ? capacity_ : t + add;
                } while (!tokens_.compare_exchange_weak(t, nt,
                        std::memory_order_acq_rel));
            }
        }
    }

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    const int64_t capacity_;
    std::atomic<int64_t> tokens_;
    const int64_t refillPerSec_;
    std::atomic<int64_t> lastRefill_;
};

// 按 key（IP/UID）分桶的限流器
class RateLimiter {
public:
    RateLimiter(int64_t capacity, int64_t refillPerSec)
        : capacity_(capacity), refillPerSec_(refillPerSec) {}

    bool allow(const std::string& key) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = buckets_.find(key);
        if (it == buckets_.end()) {
            it = buckets_.emplace(key,
                std::make_unique<TokenBucket>(capacity_, refillPerSec_)).first;
        }
        return it->second->tryConsume();
    }

private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::unique_ptr<TokenBucket>> buckets_;
    int64_t capacity_;
    int64_t refillPerSec_;
};

}  // namespace novawaf
