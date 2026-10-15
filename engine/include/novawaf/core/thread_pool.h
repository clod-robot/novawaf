// NovaWAF - 线程池 (提交检测任务，工作线程从 MPMC 队列取任务)
#pragma once

#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/noncopyable.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
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
        if (!running_) return false;
        if (!queue_.enqueue(std::move(task))) return false;
        pending_.fetch_add(1, std::memory_order_release);
        cv_.notify_one();  // 唤醒一个空闲 worker（无 worker 空闲时为廉价空操作）
        return true;
    }

    size_t size() const { return threads_.capacity(); }

private:
    void runInThread() {
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
                // 先短暂自旋（保转发低延迟），仍无任务则阻塞睡眠，杜绝 yield 空转白烧 CPU
                if (idleSpins < 128) {
                    ++idleSpins;
                    std::this_thread::yield();
                    continue;
                }
                std::unique_lock<std::mutex> lk(mtx_);
                cv_.wait_for(lk, std::chrono::milliseconds(1),
                             [this] { return pending_.load(std::memory_order_acquire) > 0 ||
                                             !running_.load(std::memory_order_acquire); });
            }
        }
        // 退出前兜底排空队列中剩余任务（避免 stop 时丢弃已入队任务）
        Task task;
        while (queue_.dequeue(task)) task();
    }

    MpmcQueue<Task> queue_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_;
    std::atomic<size_t> pending_{0};
    std::mutex mtx_;
    std::condition_variable cv_;
};

}  // namespace novawaf
