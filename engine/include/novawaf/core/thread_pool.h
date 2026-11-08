// NovaWAF - 线程池 (提交检测任务，工作线程从 MPMC 队列取任务)
#pragma once

#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/noncopyable.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace novawaf {

class ThreadPool : public NonCopyable {
public:
    using Task = std::function<void()>;

    explicit ThreadPool(size_t numThreads = 0, size_t queueSize = 1 << 16)
        : queue_(queueSize), running_(false) {
        if (numThreads == 0)
            numThreads = std::thread::hardware_concurrency();
        threads_.reserve(numThreads);
    }

    ~ThreadPool() { stop(); }

    void start() {
        running_ = true;
        for (size_t i = 0; i < threads_.capacity(); ++i)
            threads_.emplace_back([this] { runInThread(); });
    }

    void stop() {
        if (!running_) return;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            running_ = false;
        }
        cv_.notify_all();  // 唤醒所有空闲 worker 退出
        for (auto& t : threads_)
            if (t.joinable()) t.join();
        threads_.clear();
    }

    // 提交任务，队列满时返回 false（调用方决定丢弃或阻塞）
    bool submit(Task task) {
        if (!running_.load(std::memory_order_acquire)) return false;
        {
            // 记账与入队放在同一把锁内，与等待线程的谓词检查互斥，杜绝
            // "notify 早于 wait" 的丢失唤醒；先自增再入队，保证 worker 的递减
            // 一定晚于自增，计数不会无符号下溢（下溢会让谓词恒真→忙等）。
            std::lock_guard<std::mutex> lk(mtx_);
            pending_.fetch_add(1, std::memory_order_release);
            if (!queue_.enqueue(std::move(task))) {
                pending_.fetch_sub(1, std::memory_order_release);
                return false;
            }
        }
        cv_.notify_one();  // 唤醒一个空闲 worker（无 worker 空闲时为廉价空操作）
        return true;
    }

    size_t size() const { return threads_.capacity(); }

private:
    // 空闲退避参数（进程内只读，环境变量可调；默认值按 1C2G 场景取低功耗档）：
    //   NOVA_POOL_SPINS  队列空后先自旋次数（保突发转发低延迟），默认 32
    //   NOVA_POOL_WAIT_MS 自旋耗尽后的条件变量等待上限(ms)，默认 200
    // 等待由 submit/stop 的 notify 立即唤醒，超时仅作兜底，不产生周期性空转。
    static int envInt(const char* k, int dflt) {
        const char* v = std::getenv(k);
        return (v && *v) ? std::atoi(v) : dflt;
    }
    static int idleSpinLimit() {
        static const int v = envInt("NOVA_POOL_SPINS", 32);
        return v < 0 ? 0 : v;
    }
    static std::chrono::milliseconds idleWait() {
        static const int v = envInt("NOVA_POOL_WAIT_MS", 200);
        return std::chrono::milliseconds(v > 0 ? v : 200);
    }

    void runInThread() {
        const int spinLimit = idleSpinLimit();
        const auto waitMs = idleWait();
        int idleSpins = 0;
        while (running_.load(std::memory_order_acquire)) {
            Task task;
            if (queue_.dequeue(task)) {
                idleSpins = 0;
                pending_.fetch_sub(1, std::memory_order_release);
                try { task(); }
                catch (const std::exception& e) { std::fprintf(stderr, "[pool] task exception: %s\n", e.what()); }
                catch (...) { std::fprintf(stderr, "[pool] task unknown exception\n"); }
            } else {
                // 先短暂自旋（保转发低延迟），仍无任务则阻塞等待，杜绝 yield 空转白烧 CPU
                if (idleSpins < spinLimit) {
                    ++idleSpins;
                    std::this_thread::yield();
                    continue;
                }
                {
                    std::unique_lock<std::mutex> lk(mtx_);
                    cv_.wait_for(lk, waitMs, [this] {
                        return pending_.load(std::memory_order_acquire) > 0 ||
                               !running_.load(std::memory_order_acquire);
                    });
                }
                idleSpins = 0;  // 被唤醒后重新给出一小段自旋预算
            }
        }
        // 退出前兜底排空队列中剩余任务（避免 stop 时丢弃已入队任务）
        Task task;
        while (queue_.dequeue(task)) task();
    }

    MpmcQueue<Task> queue_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_;
    std::atomic<long long> pending_{0};
    std::mutex mtx_;
    std::condition_variable cv_;
};

}  // namespace novawaf
