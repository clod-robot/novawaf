// NovaWAF - 流量全量统计（按应用、分钟桶、去重）落库
// 设计同 EventSink：热路径 emit() 入队不阻塞；单后台线程聚合并写 Redis。
// 存储：
//   novawaf:traffic:{appId}      LIST，每完成分钟一个桶 JSON（保留 44640 ≈ 31 天）
//   novawaf:traffic:stat:{appId} STRING，每秒覆写：实时 QPS + 当前进行中分钟桶
// 桶 JSON：{"t":分钟epoch,"req":N,"pv":N,"blk":N,"a4":N,"a5":N,"sess":[..],"ip":[..],"atk":[..]}
#pragma once
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/redis_client.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace novawaf {

struct TrafficReq {
    int64_t ts = 0;
    std::string appId;
    int status = 0;     // 最终返回给客户端的状态码
    bool blocked = false;
    bool attack = false; // 命中攻击防护/黑名单（区别于纯限流）
    std::string ip;
    std::string sid;
    // 访问明细（用于可视化：客户端/状态/地理/来源域名/受访页面 分布）
    std::string ua;       // User-Agent
    std::string host;     // 受访域名（Host 头）
    std::string path;     // 受访页面 path（含 query）
    std::string referer;  // 来源域名（Referer 头）
    std::string country;  // GeoIP 国家代码
};

class TrafficSink {
public:
    static TrafficSink& instance() { static TrafficSink i; return i; }

    void emit(TrafficReq e) {
        if (!running_.load(std::memory_order_acquire)) return;
        queue_.enqueue(std::move(e));
    }
    void start() {
        bool e = false;
        if (!running_.compare_exchange_strong(e, true)) return;
        const char* h = std::getenv("NOVA_REDIS_HOST");
        enabled_ = h && *h;
        thread_ = std::thread([this] { loop(); });
    }
    void stop() {
        running_.store(false);
        if (thread_.joinable()) thread_.join();
    }

private:
    TrafficSink() : queue_(8192) {}
    TrafficSink(const TrafficSink&) = delete;
    TrafficSink& operator=(const TrafficSink&) = delete;

    struct MinBucket {
        int64_t t = 0;
        uint64_t req = 0, blk = 0, a4 = 0, a5 = 0;
        std::unordered_set<std::string> sess, ip, atk;
    };

    void loop() {
        auto lastSnap = std::chrono::steady_clock::now();
        while (running_.load(std::memory_order_acquire)) {
            drain();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSnap).count() >= 1000) {
                rollAndWrite();
                lastSnap = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        drain(); rollAndWrite();
    }

    void drain() {
        TrafficReq e; int n = 0;
        while (queue_.dequeue(e) && n < 20000) {
            ++n;
            if (e.appId.empty()) continue;
            int64_t minute = e.ts / 60;
            auto& b = cur_[e.appId];
            if (b.t != minute) {
                if (b.t != 0) flushBucket(e.appId, b);  // 分钟切换：先把上一分钟落库
                b = MinBucket{}; b.t = minute;
            }
            b.req++;
            if (e.blocked) b.blk++;
            if (e.status >= 400 && e.status < 500) b.a4++;
            else if (e.status >= 500 && e.status < 600) b.a5++;
            if (b.sess.size() < 200 && !e.sid.empty()) b.sess.insert(e.sid);
            if (b.ip.size() < 200 && !e.ip.empty()) b.ip.insert(e.ip);
            if (e.attack && b.atk.size() < 200 && !e.ip.empty()) b.atk.insert(e.ip);
            // 访问明细：攒批后落 novawaf:access（供可视化聚合）
            if (enabled_) accessBuf_.push_back(accessJson(e));
            // QPS：按秒计数
            int64_t sec = e.ts;
            auto& dq = qps_[e.appId];
            if (!dq.empty() && dq.back().first == sec) dq.back().second++;
            else { dq.push_back({sec, 1}); while (dq.size() > 6) dq.pop_front(); }
        }
    }

    // 把已完成分钟桶落库；每秒也把进行中桶 + qps 写入 stat 键
    void rollAndWrite() {
        int64_t nowMin = (int64_t)std::time(nullptr) / 60;
        for (auto it = cur_.begin(); it != cur_.end(); ) {
            if (it->second.t != 0 && it->second.t < nowMin) {
                flushBucket(it->first, it->second);
                it = cur_.erase(it);
            } else ++it;
        }
        if (!enabled_) return;
        RedisClient r;
        const char* h = std::getenv("NOVA_REDIS_HOST");
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        if (!r.connect(h ? h : "", port, pass ? pass : "", db)) return;
        int64_t nowSec = (int64_t)std::time(nullptr);
        for (auto& kv : cur_) {
            uint64_t qps = 0;
            for (auto& sc : qps_[kv.first]) if (sc.first >= nowSec - 4) qps += sc.second;
            std::ostringstream o;
            o << "{\"qps\":" << qps << ",\"updated\":" << nowSec << ",\"cur\":" << bucketJson(kv.second) << "}";
            r.set("novawaf:traffic:stat:" + kv.first, o.str());
        }
        // 访问明细批量落库（环形上限，避免无限增长）
        flushAccess(r);
    }

    void flushAccess(RedisClient& r) {
        if (accessBuf_.empty()) return;
        r.rpushMulti("novawaf:access", accessBuf_);
        r.ltrim("novawaf:access", -(int64_t)20000, -1);
        accessBuf_.clear();
    }

    void flushBucket(const std::string& appId, const MinBucket& b) {
        if (!enabled_) return;
        RedisClient r;
        const char* h = std::getenv("NOVA_REDIS_HOST");
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        if (!r.connect(h ? h : "", port, pass ? pass : "", db)) return;
        r.rpush("novawaf:traffic:" + appId, bucketJson(b));
        r.ltrim("novawaf:traffic:" + appId, -(int64_t)44640, -1);
    }

    static std::string esc(const std::string& s) {
        std::string o; o.reserve(s.size()+2);
        for (char c : s) {
            switch(c){case '"':o+="\\\"";break;case '\\':o+="\\\\";break;case '\n':o+="\\n";break;
                case '\r':o+="\\r";break;case '\t':o+="\\t";break;default:
                if((unsigned char)c<0x20){char buf[8];std::snprintf(buf,sizeof(buf),"\\u%04x",(unsigned char)c);o+=buf;}else o+=c;}
        } return o;
    }
    static void arr(std::ostringstream& o, const std::unordered_set<std::string>& s) {
        o << "["; bool first = true;
        for (auto& v : s) { if (!first) o << ","; first = false; o << "\"" << esc(v) << "\""; }
        o << "]";
    }
    static std::string bucketJson(const MinBucket& b) {
        std::ostringstream o;
        o << "{\"t\":" << b.t << ",\"req\":" << b.req << ",\"pv\":" << b.req
          << ",\"blk\":" << b.blk << ",\"a4\":" << b.a4 << ",\"a5\":" << b.a5;
        o << ",\"sess\":"; arr(o, b.sess);
        o << ",\"ip\":"; arr(o, b.ip);
        o << ",\"atk\":"; arr(o, b.atk);
        o << "}";
        return o.str();
    }
    // 单条访问明细 JSON（短键省内存；长字段截断防异常大包）
    static std::string trunc(const std::string& s, size_t n) {
        return s.size() > n ? s.substr(0, n) : s;
    }
    static std::string accessJson(const TrafficReq& e) {
        std::ostringstream o;
        o << "{\"t\":" << e.ts << ",\"a\":\"" << esc(e.appId) << "\""
          << ",\"ip\":\"" << esc(e.ip) << "\",\"st\":" << e.status
          << ",\"ua\":\"" << esc(trunc(e.ua, 192)) << "\""
          << ",\"host\":\"" << esc(trunc(e.host, 128)) << "\""
          << ",\"p\":\"" << esc(trunc(e.path, 192)) << "\""
          << ",\"ref\":\"" << esc(trunc(e.referer, 192)) << "\""
          << ",\"cty\":\"" << esc(e.country) << "\""
          << ",\"blk\":" << (e.blocked ? 1 : 0) << ",\"atk\":" << (e.attack ? 1 : 0) << "}";
        return o.str();
    }

    MpmcQueue<TrafficReq> queue_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    bool enabled_ = false;
    std::unordered_map<std::string, MinBucket> cur_;
    std::unordered_map<std::string, std::deque<std::pair<int64_t,uint64_t>>> qps_;
    std::vector<std::string> accessBuf_;  // 访问明细攒批
};

} // namespace novawaf
