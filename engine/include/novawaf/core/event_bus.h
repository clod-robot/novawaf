// NovaWAF - 事件总线（观察者模式）
// 发布者 publish，订阅者 subscribe 回调。用于跨模块解耦：
// 攻击命中事件由总线统一分发，态势落库/防火墙联动/告警/SIEM 等各自订阅，
// 新增消费者无需改动发布方，满足后续扩展的开闭原则。
#pragma once

#include <cstddef>
#include <functional>
#include <mutex>
#include <vector>

namespace novawaf {

template <typename Event>
class EventBus {
public:
    using Handler = std::function<void(const Event&)>;

    static EventBus& instance() {
        static EventBus bus;
        return bus;
    }

    // 订阅，返回订阅 id（可用于取消）
    size_t subscribe(Handler h) {
        std::lock_guard<std::mutex> lk(mtx_);
        size_t id = nextId_++;
        subs_.push_back({id, std::move(h)});
        return id;
    }

    void unsubscribe(size_t id) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto it = subs_.begin(); it != subs_.end(); ++it) {
            if (it->id == id) { subs_.erase(it); break; }
        }
    }

    // 发布：先快照订阅者再加锁外回调，避免回调内重入导致死锁
    void publish(const Event& e) {
        std::vector<Handler> snapshot;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            snapshot.reserve(subs_.size());
            for (auto& s : subs_) snapshot.push_back(s.handler);
        }
        for (auto& h : snapshot) h(e);
    }

private:
    struct Sub { size_t id; Handler handler; };
    std::mutex mtx_;
    std::vector<Sub> subs_;
    size_t nextId_ = 1;
};

}  // namespace novawaf
