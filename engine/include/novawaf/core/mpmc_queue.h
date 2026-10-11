// NovaWAF - 无锁 MPMC 环形队列 (bounded, cache-line friendly)
// 用于检测任务在线程间传递，避免锁竞争。基于 Dmitry Vyukov 的设计。
#pragma once

#include "novawaf/core/noncopyable.h"

#include <atomic>
#include <cstddef>
#include <new>
#include <vector>

namespace novawaf {

template <typename T>
class MpmcQueue : public NonCopyable {
public:
    // capacity 必须是 2 的幂
    explicit MpmcQueue(size_t capacity)
        : capacity_(capacity), mask_(capacity - 1), buffer_(capacity) {
        for (size_t i = 0; i < capacity_; ++i)
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        enqueue_pos_.store(0, std::memory_order_relaxed);
        dequeue_pos_.store(0, std::memory_order_relaxed);
    }

    bool enqueue(const T& data) {
        Cell* cell;
        size_t pos = enqueue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &buffer_[pos & mask_];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);
            if (diff == 0) {
                if (enqueue_pos_.compare_exchange_weak(pos, pos + 1,
                        std::memory_order_relaxed))
                    break;
            } else if (diff < 0) {
                return false;  // 队列满
            } else {
                pos = enqueue_pos_.load(std::memory_order_relaxed);
            }
        }
        cell->data = data;
        cell->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

    bool dequeue(T& data) {
        Cell* cell;
        size_t pos = dequeue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &buffer_[pos & mask_];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
            if (diff == 0) {
                if (dequeue_pos_.compare_exchange_weak(pos, pos + 1,
                        std::memory_order_relaxed))
                    break;
            } else if (diff < 0) {
                return false;  // 队列空
            } else {
                pos = dequeue_pos_.load(std::memory_order_relaxed);
            }
        }
        data = cell->data;
        cell->sequence.store(pos + mask_ + 1, std::memory_order_release);
        return true;
    }

    size_t capacity() const { return capacity_; }

private:
    struct Cell {
        std::atomic<size_t> sequence;
        T data;
    };

    const size_t capacity_;
    const size_t mask_;
    std::vector<Cell> buffer_;
    char pad0_[64];
    std::atomic<size_t> enqueue_pos_;
    char pad1_[64];
    std::atomic<size_t> dequeue_pos_;
};

}  // namespace novawaf
