// NovaWAF - 行为维度统计评分（跨请求关联，补单条规则匹配的盲区）
// 背景：枚举/爬站/低速 CC/路径扫描类攻击"每条请求单独看都合法"，规则引擎无感。
// 设计（评分制取代硬阈值——攻击者压单一阈值绕过的空间被多信号叠加压缩）：
//   * 策略式信号源：404/301 响应、同前缀数字 ID 枚举、/api/ 路径枚举、请求流速，
//     各信号独立加权加分；扫描器通常同时命中多信号，分数快速饱和越限。
//   * 漏桶衰减（Leaky Bucket）：分数按 decayPerSec 匀速泄漏，低速散布的正常行为
//     被衰减吸收（防误报）；持续恶意的累积速率超过泄漏速率，必然越限。
//   * 长窗硬信号（低速 CC 专杀）：0.5 req/s 级低速攻击在漏桶中数学上不可达
//     （累积恒小于泄漏），由 300s 长窗请求总量独立直判。
//   * 分片锁（Striped Lock，64 片按 IP 哈希）：多 reactor 并发记账免全局锁竞争。
// 触发：score >= threshold → 锁定 lockSec，assess 返回 CHALLENGE（上层 429 语义）。
#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "novawaf/detect/http_model.h"

namespace novawaf {

class BehaviorGuard {
public:
    struct Config {
        double scoreThreshold = 100.0;  // 评分越限阈值（NOVA_BEH_SCORE）
        double decayPerSec    = 0.5;    // 漏桶泄漏速率 分/秒（NOVA_BEH_DECAY）
        double wNotFound      = 6.0;    // 每次 404/301 响应加分（NOVA_BEH_W_404）
        double wEnumId        = 5.0;    // 同前缀每个新数字末段加分（NOVA_BEH_W_ENUM）
        double wApiEnum       = 5.0;    // /api/ 同前缀每个新路径加分（NOVA_BEH_W_APIENUM）
        double wRequest       = 0.2;    // 每请求流速加分（高速兜底，NOVA_BEH_W_REQ）
        int    enumWinSec     = 60;     // 枚举去重滑窗秒（NOVA_BEH_ENUM_WIN）
        int    slowMax        = 150;    // 长窗低速持续访问上限（NOVA_BEH_SLOW_MAX）
        int    slowWinSec     = 300;    // 长窗秒（NOVA_BEH_SLOW_WIN）
        int    lockSec        = 120;    // 触发后挑战锁定时长（NOVA_BEH_LOCK）
    };

    static BehaviorGuard& instance() {
        static BehaviorGuard g;
        return g;
    }
    void configure(const Config& c) { cfg_ = c; }

    // 请求准入判定：锁定期内 → CHALLENGE（上层统一出 429 + Retry-After）
    DetectionResult assess(const std::string& ip) {
        if (ip.empty()) return {};
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto it = sh.locked.find(ip);
        if (it == sh.locked.end()) return {};
        if (it->second.first > nowSec())
            return {Action::CHALLENGE, "BEH-001", "Behavior",
                    "abnormal behavior pattern", it->second.second};
        sh.locked.erase(it);  // 锁定到期
        return {};
    }

    // 请求侧记账（每请求调用）：流速分 + 低速 CC 长窗 + 枚举信号
    void noteRequest(const std::string& ip, const std::string& path) {
        if (ip.empty()) return;
        int64_t now = nowSec();
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        if (sh.locked.count(ip)) { gc(sh, now); return; }
        auto& st = sh.states[ip];
        st.touch = now;
        settle(st, now);
        // 信号4：流速分（每请求微量；高速场景与 CC 层叠加，低速由长窗专杀）
        st.score += cfg_.wRequest;
        if (st.score >= cfg_.scoreThreshold) { lock(sh, ip, now, "flow-rate"); return; }
        // 信号5：低速 CC 硬信号 —— 长窗内持续访问总量（0.5 req/s × 300s 即越限；
        // 漏桶对该速率数学上不可达，必须独立长窗直判）
        st.all.push_back(now);
        evict(st.all, now - cfg_.slowWinSec);
        if ((int)st.all.size() > cfg_.slowMax) { lock(sh, ip, now, "slow-cc"); return; }
        // 信号2/3：同前缀枚举（60s 滑窗去重，仅新成员加分）
        //   /api/ 前缀：任意不同末段计数（API 路径探测，如 /api/admin/xxx）
        //   其他前缀：仅末段纯数字计数（ID 枚举特征；翻页 60s 内难超窗口免误报）
        std::string pfx = prefixOf(path);
        if (!pfx.empty()) {
            std::string seg = path.substr(pfx.size());
            if (path.compare(0, 5, "/api/") == 0) {
                if (enumRecord(st.enumApi[pfx], seg, now)) {
                    st.score += cfg_.wApiEnum;
                    if (st.score >= cfg_.scoreThreshold) { lock(sh, ip, now, "api-enum"); return; }
                }
            } else if (isAllDigits(seg)) {
                if (enumRecord(st.enumId[pfx], seg, now)) {
                    st.score += cfg_.wEnumId;
                    if (st.score >= cfg_.scoreThreshold) { lock(sh, ip, now, "id-enum"); return; }
                }
            }
        }
        gc(sh, now);
    }

    // 响应侧记账（转发完成调用）：404/301 频次（路径扫描）
    void noteStatus(const std::string& ip, int status) {
        if (ip.empty()) return;
        if (status != 404 && status != 301) return;
        int64_t now = nowSec();
        Shard& sh = shardOf(ip);
        std::lock_guard<std::mutex> lk(sh.mtx);
        if (sh.locked.count(ip)) { gc(sh, now); return; }
        auto& st = sh.states[ip];
        st.touch = now;
        settle(st, now);
        st.score += cfg_.wNotFound;
        if (st.score >= cfg_.scoreThreshold) { lock(sh, ip, now, "notfound-scan"); return; }
        gc(sh, now);
    }

private:
    BehaviorGuard() = default;

    // 枚举滑窗：order 存（首见时间, 成员），seen 去重；重复成员不进 order，
    // 保证弹出时 seen.erase 不误删仍在窗口内的同名成员
    struct EnumWin {
        std::deque<std::pair<int64_t, std::string>> order;
        std::unordered_set<std::string> seen;
    };
    struct IpState {
        double score = 0;
        int64_t lastSettle = 0;   // 上次漏桶结算时间
        std::deque<int64_t> all;  // 低速 CC 长窗
        std::unordered_map<std::string, EnumWin> enumApi;  // /api/ 前缀 → 滑窗
        std::unordered_map<std::string, EnumWin> enumId;   // 数字末段前缀 → 滑窗
        int64_t touch = 0;
    };
    struct Shard {
        std::mutex mtx;
        std::unordered_map<std::string, IpState> states;
        std::unordered_map<std::string, std::pair<int64_t, std::string>> locked;  // ip → (到期, 原因)
    };

    static constexpr size_t kShards = 64;
    Shard shards_[kShards];

    Shard& shardOf(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }
    static int64_t nowSec() { return (int64_t)time(nullptr); }
    static void evict(std::deque<int64_t>& q, int64_t cutoff) {
        while (!q.empty() && q.front() < cutoff) q.pop_front();
    }
    // 漏桶结算：距上次结算按 decayPerSec 泄漏（粒度 1s，足够行为维度）
    void settle(IpState& st, int64_t now) const {
        if (st.lastSettle == 0) { st.lastSettle = now; return; }
        int64_t dt = now - st.lastSettle;
        if (dt > 0) {
            st.score -= cfg_.decayPerSec * (double)dt;
            if (st.score < 0) st.score = 0;
            st.lastSettle = now;
        }
    }
    // 枚举滑窗记账：淘汰窗口外成员后插入；返回是否为新成员（新成员才应加分）
    bool enumRecord(EnumWin& w, const std::string& key, int64_t now) const {
        int64_t cutoff = now - cfg_.enumWinSec;
        while (!w.order.empty() && w.order.front().first < cutoff) {
            w.seen.erase(w.order.front().second);
            w.order.pop_front();
        }
        if (w.seen.insert(key).second) {
            w.order.push_back({now, key});
            return true;
        }
        return false;
    }
    // /api/user/15 → /api/user/（去掉末段）；无可截段返回空
    static std::string prefixOf(const std::string& path) {
        size_t s = path.rfind('/');
        if (s == std::string::npos || s == 0 || s + 1 >= path.size()) return {};
        return path.substr(0, s + 1);
    }
    static bool isAllDigits(const std::string& s) {
        if (s.empty()) return false;
        for (char c : s) if (c < '0' || c > '9') return false;
        return true;
    }
    void lock(Shard& sh, const std::string& ip, int64_t now, const char* reason) {
        sh.locked[ip] = {now + cfg_.lockSec, reason};
        sh.states.erase(ip);
    }
    // 惰性回收：单片状态超 256（全 64 片约 16k IP）时清理长窗内无活动的 IP
    void gc(Shard& sh, int64_t now) {
        if (sh.states.size() <= 256) return;
        for (auto it = sh.states.begin(); it != sh.states.end();) {
            if (now - it->second.touch > cfg_.slowWinSec) it = sh.states.erase(it);
            else ++it;
        }
        for (auto it = sh.locked.begin(); it != sh.locked.end();) {
            if (it->second.first <= now) it = sh.locked.erase(it);
            else ++it;
        }
    }

    Config cfg_;
};

}  // namespace novawaf
