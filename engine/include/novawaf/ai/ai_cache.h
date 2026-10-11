// NovaWAF - AI 判定结果缓存
// 以「归一化 payload 哈希」为 key，缓存 AI 判定结论，避免相同 payload 重复调用大模型。
// 特性：TTL 过期、容量上限（FIFO 淘汰）、分片锁降低并发竞争。
#pragma once

#include "novawaf/detect/http_model.h"
#include "novawaf/detect/decoder.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {

class AiCache {
public:
    // ttlSeconds: 缓存有效期；maxEntries: 最大条目数（超出淘汰最旧）
    explicit AiCache(int ttlSeconds = 300, size_t maxEntries = 10000)
        : ttlMs_(int64_t(ttlSeconds) * 1000), max_(maxEntries), shards_(kShards) {}

    // 由请求生成稳定缓存 key：归一化各 payload 后拼接哈希
    static std::string makeKey(const HttpRequest& req) {
        std::string raw;
        raw += req.method; raw += '\n';
        raw += Decoder::normalize(req.path); raw += '\n';
        raw += Decoder::normalize(req.query); raw += '\n';
        raw += Decoder::normalize(req.body); raw += '\n';
        for (auto& kv : req.queryParams) {
            raw += Decoder::normalize(kv.first); raw += '=';
            raw += Decoder::normalize(kv.second); raw += '\n';
        }
        // 简单 FNV-1a 64 位哈希 → 短 key
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : raw) { h ^= c; h *= 1099511628211ULL; }
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
        return std::string(buf);
    }

    // 命中返回判定；未命中或过期返回空
    std::optional<DetectionResult> get(const std::string& key) {
        auto& s = shard(key);
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.map.find(key);
        if (it == s.map.end()) return std::nullopt;
        if (nowMs() >= it->second.expireAt) { s.map.erase(it); count_--; return std::nullopt; }
        return it->second.result;
    }

    // 写入缓存；超容量则淘汰一个（跨分片查找 victim）
    void put(const std::string& key, const DetectionResult& r) {
        // 先淘汰（在持有任何分片锁之前，避免自锁）
        while (count_.load() >= max_) {
            if (!evictOne()) break;
        }
        auto& s = shard(key);
        std::lock_guard<std::mutex> lk(s.mtx);
        Entry e{r, nowMs() + ttlMs_};
        auto it = s.map.find(key);
        if (it != s.map.end()) { it->second = e; return; }
        if (count_.load() < max_) {
            s.map.emplace(key, e);
            count_++;
        }
    }

    // 跨分片淘汰一个最旧条目；返回是否淘汰成功。调用方不应持分片锁。
    bool evictOne() {
        for (auto& sh : shards_) {
            std::lock_guard<std::mutex> lk(sh.mtx);
            if (!sh.map.empty()) { sh.map.erase(sh.map.begin()); count_--; return true; }
        }
        return false;
    }

    size_t totalSize() const { return count_.load(); }

    size_t size() const {
        size_t n = 0;
        for (auto& s : shards_) { std::lock_guard<std::mutex> lk(s.mtx); n += s.map.size(); }
        return n;
    }

    void clear() {
        for (auto& s : shards_) { std::lock_guard<std::mutex> lk(s.mtx); s.map.clear(); }
    }

private:
    struct Entry {
        DetectionResult result;
        int64_t expireAt;
    };
    struct Shard {
        mutable std::mutex mtx;
        std::unordered_map<std::string, Entry> map;
    };
    static constexpr size_t kShards = 64;

    Shard& shard(const std::string& key) {
        return shards_[std::hash<std::string>{}(key) & (kShards - 1)];
    }
    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    int64_t ttlMs_;
    size_t max_;
    std::atomic<size_t> count_{0};
    std::vector<Shard> shards_;
};

}  // namespace novawaf
