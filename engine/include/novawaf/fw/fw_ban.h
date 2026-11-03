// NovaWAF - 防火墙联动封禁投递（与 Linux netfilter 联动防外部连接/端口攻击）
// 热路径零阻塞：攻击命中时仅把源 IP 压入内存队列，后台线程批量 RPUSH 到 Redis
// 队列 novawaf:fw:ban，由 root 运行的 fw_enforcer.py 消费并下发 iptables/nftables 封禁。
// 引擎不持 root、不直接操作防火墙，全程 fail-open（Redis 不可用不影响检测）。
#pragma once

#include "novawaf/core/redis_client.h"

#include <atomic>
#include <chrono>
#include <cmath>
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
        const char* hl = std::getenv("NOVA_REP_HALFLIFE_SEC");
        halfLifeSec_ = (hl && *hl) ? std::atof(hl) : 300.0;  // 信誉半衰期（秒）
        const char* fb = std::getenv("NOVA_FW_FIRST_BAN");
        firstBanSec_ = (fb && *fb) ? std::atoi(fb) : 120;    // 首封时长（秒）
        if (disabled_) return;
        thread_ = std::thread([this] { run(); });
    }
    ~FwBanPoster() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    bool disabled() const { return disabled_; }

    // 热路径：投递一个待封禁 IP（同 IP 在去重窗口内只投一次，避免刷屏）。
    // 信誉分模型（取代旧的 1h 扁平计数——旧模型无衰减，解封后信誉不清，
    // "解封即再封"死循环）：每次违规先按半衰期指数衰减再 +1，
    // 封禁时长 = 首封 × 2^(n-1) 且封顶 2×半衰期——解封时刻信誉必然已衰减
    // ≥2 个半衰期至 ≤1/4，累犯加重有界、初犯快速回归。
    void enqueue(const std::string& ip, const std::string& category, const std::string& ruleId) {
        if (disabled_ || ip.empty()) return;
        if (ip == "127.0.0.1" || ip == "::1") return;  // 绝不封本机
        std::lock_guard<std::mutex> lk(mtx_);
        double now = (double)std::time(nullptr);
        auto it = lastSent_.find(ip);
        if (it != lastSent_.end() && now - it->second < kDedupSec) return;  // 去重窗口
        lastSent_[ip] = now;
        double sc = 1.0;
        auto rit = rep_.find(ip);
        if (rit != rep_.end()) {
            double dt = now - rit->second.last;
            if (dt < 0) dt = 0;
            sc = rit->second.score * std::pow(0.5, dt / halfLifeSec_) + 1.0;
            if (sc > 64) sc = 64;  // 数值保险
        }
        rep_[ip] = {sc, now};
        int count = (int)std::ceil(sc);
        // 时长阶梯：首封 × 2^(n-1)，硬顶 2×半衰期（用户公式：封禁时长 ≤ 2×信誉半衰期）
        int cap = (int)(2.0 * halfLifeSec_);
        int ttl = firstBanSec_;
        for (int i = 1; i < count && ttl < cap; ++i) ttl *= 2;
        if (ttl > cap) ttl = cap;
        queue_.push_back(ip + "|" + std::to_string((int64_t)now) + "|" + category + "|" + ruleId +
                           "|" + std::to_string(count) + "|" + std::to_string(ttl));
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
            // 清理信誉衰减殆尽（<0.25 ≈ 2 个半衰期无违规）的记录，防内存增长
            {
                std::lock_guard<std::mutex> lk(mtx_);
                double now = (double)std::time(nullptr);
                for (auto it = rep_.begin(); it != rep_.end();) {
                    double dt = now - it->second.last;
                    if (dt > 0 && it->second.score * std::pow(0.5, dt / halfLifeSec_) < 0.25)
                        it = rep_.erase(it);
                    else ++it;
                }
                for (auto it = lastSent_.begin(); it != lastSent_.end();) {
                    if (now - it->second > 3600) it = lastSent_.erase(it); else ++it;
                }
            }
            for (int i = 0; i < 5 && running_; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::atomic<bool> running_{true};
    bool disabled_ = false;
    double halfLifeSec_ = 300.0;
    int firstBanSec_ = 120;
    std::thread thread_;
    std::mutex mtx_;
    std::vector<std::string> queue_;
    std::unordered_map<std::string, int64_t> lastSent_;  // IP -> 上次投递时间，去重
    struct Rep { double score; double last; };
    std::unordered_map<std::string, Rep> rep_;  // IP -> 信誉分（指数半衰期衰减）
};

}  // namespace novawaf
