// NovaWAF - 全局防护模式（WAF 指纹三态，管理控制台热切换）
// 三态语义：
//   HIDDEN  开启且隐藏（默认）：全量检测+拦截，但对外不暴露任何产品指纹
//           （无品牌拦截页、无 X-WAF 头、会话 cookie 用通用名 sid）
//   PUBLIC  开启且公开：全量检测+拦截，对外明示 WAF 存在
//           （品牌拦截页、X-WAF 头、novasid cookie，wafw00f 可识别）
//   OFF     关闭（旁路）：检测照常运行并记录事件，但一律放行不拦截不封禁
//           （等价于全站观察模式，用于排障与灰度）
// 实现：Redis STRING novawaf:wafmode = hidden|public|off，引擎热路径每 2s 刷新一次
// 缓存（原子读），Redis 不可达时保持上次值，初始默认 HIDDEN，fail-safe 不回退 OFF。
#pragma once

#include "novawaf/core/redis_client.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>

namespace novawaf {

class WafMode {
public:
    enum Mode : int { OFF = 0, HIDDEN = 1, PUBLIC = 2 };

    static WafMode& instance() {
        static WafMode inst;
        return inst;
    }

    // 热路径：原子读缓存；缓存超 2s 才同步刷新一次（单线程生效，惊群无害）
    Mode current() {
        int64_t now = nowMs();
        int64_t last = lastRefresh_.load(std::memory_order_acquire);
        if (now - last > 2000 &&
            lastRefresh_.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
            refresh();
        }
        return (Mode)mode_.load(std::memory_order_acquire);
    }

    static bool isOff(Mode m)    { return m == OFF; }
    static bool isPublic(Mode m) { return m == PUBLIC; }

    // 管理面/测试用：立即刷新
    void forceRefresh() { refresh(); }

private:
    WafMode() = default;

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    void refresh() {
        const char* rh = std::getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db, 300)) return;  // 300ms 超时，绝不拖累热路径
        auto v = r.get("novawaf:wafmode");
        if (!v) return;  // 键不存在：保持当前（默认 HIDDEN）
        int m = HIDDEN;
        if (*v == "off") m = OFF;
        else if (*v == "public") m = PUBLIC;
        mode_.store(m, std::memory_order_release);
    }

    std::atomic<int> mode_{HIDDEN};
    std::atomic<int64_t> lastRefresh_{0};
};

}  // namespace novawaf
