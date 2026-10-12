// NovaWAF - 防火墙联动封禁投递（与 Linux netfilter 联动防外部连接/端口攻击）
// 热路径零阻塞：攻击命中时仅把源 IP 压入内存队列，后台线程批量 RPUSH 到 Redis
// 队列 novawaf:fw:ban，由 root 运行的 fw_enforcer.py 消费并下发 iptables/nftables 封禁。
// 引擎不持 root、不直接操作防火墙，全程 fail-open（Redis 不可用不影响检测）。
#pragma once

#include "novawaf/core/redis_client.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace novawaf {

class FwBanPoster {
public:
    static std::shared_ptr<FwBanPoster> instance() {
        static std::shared_ptr<FwBanPoster> inst = std::make_shared<FwBanPoster>();
        return inst;
    }

    FwBanPoster() {
        const char* dis = std::getenv("NOVA_FW_BAN_DISABLE");
        disabled_ = dis && *dis == '1';
        if (disabled_) return;
        thread_ = std::thread([this] { run(); });
    }
    ~FwBanPoster() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    bool disabled() const { return disabled_; }

    // 热路径：投递一个待封禁 IP（同 IP 在去重窗口内只投一次，避免刷屏）
    void enqueue(const std::string& ip, const std::string& category, const std::string& ruleId) {
        if (disabled_ || ip.empty()) return;
        if (ip == "127.0.0.1" || ip == "::1") return;  // 绝不封本机
        std::lock_guard<std::mutex> lk(mtx_);
        int64_t now = std::time(nullptr);
        auto it = lastSent_.find(ip);
        if (it != lastSent_.end() && now - it->second < kDedupSec) return;  // 去重窗口
        lastSent_[ip] = now;
        queue_.push_back(ip + "|" + std::to_string(now) + "|" + category + "|" + ruleId);
    }

private:
    static constexpr int kDedupSec = 60;
    void run() {
        RedisClient r;
        bool connected = false;
        auto ensureConn = [&]() -> bool {
            if (connected && r.connected()) return true;
            const char* rh = std::getenv("NOVA_REDIS_HOST");
            if (!rh || !*rh) return false;
            int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
            const char* pass = std::getenv("NOVA_REDIS_PASS");
            int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
            connected = r.connect(rh, port, pass ? pass : "", db, 1000);
            return connected;
        };
        while (running_) {
            std::vector<std::string> batch;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (!queue_.empty()) { batch.swap(queue_); }
            }
            if (!batch.empty() && ensureConn()) {
                r.rpushMulti("novawaf:fw:ban", batch);
            }
            for (int i = 0; i < 5 && running_; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::atomic<bool> running_{true};
    bool disabled_ = false;
    std::thread thread_;
    std::mutex mtx_;
    std::vector<std::string> queue_;
    std::unordered_map<std::string, int64_t> lastSent_;  // IP -> 上次投递时间，去重
};

}  // namespace novawaf
