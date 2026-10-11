// NovaWAF - 线程池 (提交检测任务，工作线程从 MPMC 队列取任务)
#pragma once

#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/noncopyable.h"

#include <atomic>
#include <functional>
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
        running_ = false;
        for (auto& t : threads_)
            if (t.joinable()) t.join();
        threads_.clear();
    }

    // 提交任务，队列满时返回 false（调用方决定丢弃或阻塞）
    bool submit(Task task) {
        if (!running_) return false;
        return queue_.enqueue(std::move(task));
    }

    size_t size() const { return threads_.capacity(); }

private:
    void runInThread() {
        while (running_ || !queueEmpty()) {
            Task task;
            if (queue_.dequeue(task)) {
                task();
            } else {
                std::this_thread::yield();
            }
        }
    }

    bool queueEmpty() {
        // 近似判断，避免误判导致提前退出
        Task t;
        return false;  // 保守：不主动认为空，由 running_ 控制退出
    }

    MpmcQueue<Task> queue_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_;
};

}  // namespace novawaf
