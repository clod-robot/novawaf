// NovaWAF - 攻击事件汇聚与态势统计落库（可视化大屏的数据地基）
// 设计：
//   * 检测热路径只调用 emit() 把事件丢进无锁队列（队列满则丢弃，绝不阻塞）。
//   * 单后台线程批量出队：内存聚合计数（总量/类型/等级/源IP/分时桶），
//     周期性把「原始事件列表」+「一份 JSON 统计快照」写入 Redis。
//   * Redis 不可用时降级为仅 stdout，不影响引擎拦截。
// 零第三方依赖（JSON 序列化手写）。
#pragma once

#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/redis_client.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace novawaf {

struct AttackEvent {
    int64_t ts = 0;          //  epoch 秒
    std::string ip;
    std::string action;      //  block / challenge / log
    std::string category;    //  SQLi / XSS / Geo / CC / Bot / Custom / ...
    std::string ruleId;
    std::string matched;
    std::string severity;    //  high / medium / low / info（可为空）
};

class EventSink {
public:
    static EventSink& instance() {
        static EventSink inst;
        return inst;
    }

    // 热路径：入队，失败（队列满）静默丢弃
    void emit(AttackEvent e) {
        if (!running_.load(std::memory_order_acquire)) return;
        queue_.enqueue(e);  // 满则返回 false，忽略
    }

    void start() {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;
        // 配置
        eventsCap_ = envInt("NOVA_EVENTS_CAP", 1000);
        flushMs_ = envInt("NOVA_STATS_FLUSH_MS", 1000);
        topN_ = envInt("NOVA_STATS_TOPN", 10);
        buckets_ = envInt("NOVA_STATS_BUCKETS", 60);
        enabled_ = redisConfigured();
        thread_ = std::thread([this] { loop(); });
    }

    void stop() {
        running_.store(false, std::memory_order_release);
        if (thread_.joinable()) thread_.join();
    }

    // 测试用：同步刷写一次（把队列排空并写 Redis）
    void flushNow() {
        drainQueue();
        writeToRedis();
    }

private:
    EventSink() : queue_(4096) {}
    EventSink(const EventSink&) = delete;
    EventSink& operator=(const EventSink&) = delete;

    static int envInt(const char* k, int def) {
        const char* v = std::getenv(k);
        return (v && *v) ? std::atoi(v) : def;
    }
    static bool redisConfigured() {
        const char* h = std::getenv("NOVA_REDIS_HOST");
        return h && *h;
    }

    void loop() {
        auto last = std::chrono::steady_clock::now();
        while (running_.load(std::memory_order_acquire)) {
            drainQueue();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() >= flushMs_) {
                writeToRedis();
                last = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        drainQueue();
        writeToRedis();
    }

    void drainQueue() {
        AttackEvent e;
        int n = 0;
        while (queue_.dequeue(e) && n < 5000) {
            ++n;
            total_++;
            byCategory_[e.category]++;
            if (!e.severity.empty()) bySeverity_[e.severity]++;
            if (!e.ip.empty()) byIp_[e.ip]++;
            if (!e.ip.empty()) perIpDelta_[e.ip]++;      // 溯源分桶增量(写失败保留重试)
            if (!e.category.empty()) perCatDelta_[e.category]++;
            int64_t bucket = e.ts > 0 ? e.ts / 60 : (int64_t)(std::time(nullptr) / 60);
            tsBuckets_[bucket]++;
            pendingEvents_.push_back(e);
        }
    }

    void writeToRedis() {
        if (!enabled_) {
            if (!pendingEvents_.empty()) {
                std::fprintf(stderr, "[stats] %zu events (redis disabled, stdout only)\n",
                             pendingEvents_.size());
            }
            pendingEvents_.clear();
            return;
        }
        RedisClient r;
        const char* h = std::getenv("NOVA_REDIS_HOST");
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        if (!r.connect(h ? h : "", port, pass ? pass : "", db)) {
            // 连接失败：保留事件与增量到下次重试，不崩溃
            return;
        }
        // 1) 原始事件批量 RPUSH + LTRIM（近期明细窗口，供时间线展示）
        if (!pendingEvents_.empty()) {
            std::vector<std::string> jsons;
            std::unordered_map<std::string, std::vector<std::string>> byIp;
            jsons.reserve(pendingEvents_.size());
            for (auto& e : pendingEvents_) {
                std::string j = eventJson(e);
                if (!e.ip.empty()) byIp[e.ip].push_back(j);  // 按 IP 分桶（引用同一条 JSON）
                jsons.push_back(std::move(j));
            }
            r.rpushMulti("novawaf:events", jsons);
            r.ltrim("novawaf:events", -(int64_t)eventsCap_, -1);
            flushPerIp(r, byIp);
            pendingEvents_.clear();
        }
        // 2) 溯源真实计数（按天分桶 Hash，与明细窗口无关：不封顶、不被洪水挤占、
        //    引擎重启不丢；跨天自然开新桶，EXPIRE 48h 自动回收）
        if (!perIpDelta_.empty() || !perCatDelta_.empty()) {
            char day[16];
            std::time_t t = std::time(nullptr);
            std::tm lt{};
            localtime_r(&t, &lt);
            std::strftime(day, sizeof(day), "%Y%m%d", &lt);
            std::string cntKey = std::string("novawaf:trace:cnt:") + day;
            std::string catKey = std::string("novawaf:trace:cat:") + day;
            for (auto& kv : perIpDelta_) r.hincrby(cntKey, kv.first, (int64_t)kv.second);
            for (auto& kv : perCatDelta_) r.hincrby(catKey, kv.first, (int64_t)kv.second);
            r.expire(cntKey, 172800);
            r.expire(catKey, 172800);
            perIpDelta_.clear();
            perCatDelta_.clear();
        }
        // 3) 统计快照
        r.set("novawaf:stats", snapshotJson());
    }

    // 按 IP 分桶保留攻击明细：novawaf:ev:{ip}，每 IP 最近 PER_IP_CAP 条、TTL 24h。
    // 全局 novawaf:events 是固定长度环形窗口，高频源会在秒级把低频源的明细挤掉；
    // 分桶后任何 IP 都能回看自己的完整攻击链（溯源抽屉/攻击日志用）。
    void flushPerIp(RedisClient& r, const std::unordered_map<std::string, std::vector<std::string>>& byIp) {
        if (byIp.empty()) return;
        int64_t now = (int64_t)std::time(nullptr);
        for (auto& kv : byIp) {
            bool known = ttlMark_.count(kv.first) > 0;
            // 分桶数量上限保护：避免海量离散源 IP 撑爆 Redis 内存
            if (!known && ttlMark_.size() >= MAX_IP_BUCKETS) continue;
            const std::string key = "novawaf:ev:" + kv.first;
            r.rpushMulti(key, kv.second);
            r.ltrim(key, -(int64_t)PER_IP_CAP, -1);
            auto it = ttlMark_.find(kv.first);
            if (it == ttlMark_.end() || now - it->second >= 60) {  // 每 60s 刷一次 TTL，省命令
                r.expire(key, 86400);
                ttlMark_[kv.first] = now;
            }
        }
        if (ttlMark_.size() > MAX_IP_BUCKETS) {
            for (auto it = ttlMark_.begin(); it != ttlMark_.end();) {
                if (now - it->second > 3600) it = ttlMark_.erase(it); else ++it;
            }
        }
    }

    // ---- JSON 序列化（手写，零依赖）----
    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 2);
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        o += buf;
                    } else o += c;
            }
        }
        return o;
    }

    static std::string eventJson(const AttackEvent& e) {
        std::ostringstream o;
        o << "{\"ts\":" << e.ts
          << ",\"ip\":\"" << esc(e.ip) << "\""
          << ",\"action\":\"" << esc(e.action) << "\""
          << ",\"category\":\"" << esc(e.category) << "\""
          << ",\"ruleId\":\"" << esc(e.ruleId) << "\""
          << ",\"matched\":\"" << esc(e.matched) << "\""
          << ",\"severity\":\"" << esc(e.severity) << "\"}";
        return o.str();
    }

    std::string snapshotJson() {
        std::ostringstream o;
        o << "{\"total\":" << total_
          << ",\"updated\":" << (int64_t)std::time(nullptr);
        // byCategory
        o << ",\"byCategory\":{";
        bool first = true;
        for (auto& kv : byCategory_) {
            if (!first) o << ",";
            first = false;
            o << "\"" << esc(kv.first) << "\":" << kv.second;
        }
        o << "}";
        // bySeverity
        o << ",\"bySeverity\":{";
        first = true;
        for (auto& kv : bySeverity_) {
            if (!first) o << ",";
            first = false;
            o << "\"" << esc(kv.first) << "\":" << kv.second;
        }
        o << "}";
        // topIps：排序取前 topN
        std::vector<std::pair<std::string, uint64_t>> ips(byIp_.begin(), byIp_.end());
        std::sort(ips.begin(), ips.end(),
                  [](auto& a, auto& b) { return a.second > b.second; });
        o << ",\"topIps\":[";
        first = true;
        int cnt = 0;
        for (auto& kv : ips) {
            if (cnt++ >= topN_) break;
            if (!first) o << ",";
            first = false;
            o << "{\"ip\":\"" << esc(kv.first) << "\",\"count\":" << kv.second << "}";
        }
        o << "]";
        // timeseries：最近 buckets_ 个分钟桶
        o << ",\"timeseries\":[";
        first = true;
        // 修剪过老桶
        int64_t nowBucket = (int64_t)(std::time(nullptr) / 60);
        int64_t minBucket = nowBucket - buckets_ + 1;
        for (auto it = tsBuckets_.begin(); it != tsBuckets_.end();) {
            if (it->first < minBucket) it = tsBuckets_.erase(it);
            else ++it;
        }
        for (auto& kv : tsBuckets_) {
            if (!first) o << ",";
            first = false;
            o << "{\"bucket\":" << kv.first << ",\"count\":" << kv.second << "}";
        }
        o << "]}";
        return o.str();
    }

    MpmcQueue<AttackEvent> queue_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    bool enabled_ = false;
    int eventsCap_ = 1000;
    int flushMs_ = 1000;
    int topN_ = 10;
    int buckets_ = 60;

    // 以下仅后台线程访问，无需加锁
    uint64_t total_ = 0;
    std::map<std::string, uint64_t> byCategory_;
    std::map<std::string, uint64_t> bySeverity_;
    std::unordered_map<std::string, uint64_t> byIp_;
    std::map<int64_t, uint64_t> tsBuckets_;
    std::vector<AttackEvent> pendingEvents_;
    // 溯源分桶增量（自上次成功写入 Redis 的累计；写失败保留，成功后清零）
    std::unordered_map<std::string, uint64_t> perIpDelta_;
    std::unordered_map<std::string, uint64_t> perCatDelta_;
    std::unordered_map<std::string, int64_t> ttlMark_;  // ip -> 最近刷 TTL 的秒
    static constexpr int64_t PER_IP_CAP = 200;       // 每 IP 保留的攻击明细条数
    static constexpr size_t MAX_IP_BUCKETS = 20000;  // 分桶数量上限（内存保护）
};

}  // namespace novawaf
