// NovaWAF - 行为维度异常识别（跨请求关联，补单条规则匹配的盲区）
// 背景：枚举/爬站/低速 CC/路径扫描类攻击"每条请求单独看都合法"，规则引擎无感。
// 设计：策略式信号源（404频次 / 同前缀枚举 / 低速持续访问）+ 滑窗统计 + 挑战锁定。
// 线程安全：单例 + 分片锁思路简化为单互斥（记账为 O(1)  amortized，非热瓶颈）。
#pragma once

#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "novawaf/detect/http_model.h"

namespace novawaf {

class BehaviorGuard {
public:
    struct Config {
        int notFoundMax = 20;      // 窗口内 301/404 上限（路径扫描探测，NOVA_BEH_404_MAX）
        int notFoundWinSec = 60;   // NOVA_BEH_404_WIN
        int enumMax = 15;          // 窗口内同 API 前缀不同路径上限（ID 枚举，NOVA_BEH_ENUM_MAX）
        int enumWinSec = 60;       // NOVA_BEH_ENUM_WIN
        int slowCcMax = 200;       // 长窗低速持续访问上限（低速 CC，NOVA_BEH_SLOW_MAX）
        int slowCcWinSec = 300;    // NOVA_BEH_SLOW_WIN
        int lockSec = 120;         // 触发后挑战锁定时长（NOVA_BEH_LOCK）
    };

    static BehaviorGuard& instance() {
        static BehaviorGuard g;
        return g;
    }
    void configure(const Config& c) { cfg_ = c; }

    // 请求准入判定：锁定期内 → CHALLENGE（上层统一出 429 + Retry-After）
    DetectionResult assess(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = locked_.find(ip);
        if (it == locked_.end()) return {};
        if (it->second > nowSec())
            return {Action::CHALLENGE, "BEH-001", "Behavior",
                    "abnormal behavior pattern", "window-locked"};
        locked_.erase(it);  // 锁定到期
        return {};
    }

    // 请求侧记账（每请求调用）：低速 CC 长窗 + 同前缀枚举
    void noteRequest(const std::string& ip, const std::string& path) {
        if (ip.empty()) return;
        int64_t now = nowSec();
        std::lock_guard<std::mutex> lk(mtx_);
        if (locked_.count(ip)) { gc(now); return; }
        auto& st = states_[ip];
        st.touch = now;
        // 信号3：低速 CC —— 长窗内持续访问总量（正常浏览 5 分钟远低于 200 次）
        st.all.push_back(now);
        evict(st.all, now - cfg_.slowCcWinSec);
        if ((int)st.all.size() > cfg_.slowCcMax) { lock(ip, now); return; }
        // 信号2：同前缀枚举 —— 仅对 /api/ 路径（静态资源同前缀翻页属正常浏览）
        if (path.compare(0, 5, "/api/") == 0) {
            std::string pfx = prefixOf(path);
            if (!pfx.empty()) {
                auto& q = st.enumWin[pfx];
                q.push_back({now, path});
                while (!q.empty() && q.front().first < now - cfg_.enumWinSec) q.pop_front();
                std::unordered_set<std::string> uniq;
                for (auto& [t, p] : q) uniq.insert(p);
                if ((int)uniq.size() > cfg_.enumMax) { lock(ip, now); return; }
            }
        }
        gc(now);
    }

    // 响应侧记账（转发完成调用）：404/301 频次（路径扫描）
    void noteStatus(const std::string& ip, int status) {
        if (ip.empty()) return;
        if (status != 404 && status != 301) return;
        int64_t now = nowSec();
        std::lock_guard<std::mutex> lk(mtx_);
        if (locked_.count(ip)) { gc(now); return; }
        auto& st = states_[ip];
        st.touch = now;
        st.notFound.push_back(now);
        evict(st.notFound, now - cfg_.notFoundWinSec);
        if ((int)st.notFound.size() > cfg_.notFoundMax) lock(ip, now);
        gc(now);
    }

private:
    BehaviorGuard() = default;

    struct IpState {
        std::deque<int64_t> all;                                   // 低速 CC 长窗
        std::deque<int64_t> notFound;                              // 404/301 窗
        std::unordered_map<std::string, std::deque<std::pair<int64_t, std::string>>> enumWin;
        int64_t touch = 0;
    };

    static int64_t nowSec() { return (int64_t)time(nullptr); }
    static void evict(std::deque<int64_t>& q, int64_t cutoff) {
        while (!q.empty() && q.front() < cutoff) q.pop_front();
    }
    // /api/user/15 → /api/user/（去掉末段数字/短 id）；无可截段返回空
    static std::string prefixOf(const std::string& path) {
        size_t s = path.rfind('/');
        if (s == std::string::npos || s == 0 || s + 1 >= path.size()) return {};
        return path.substr(0, s + 1);
    }
    void lock(const std::string& ip, int64_t now) {
        locked_[ip] = now + cfg_.lockSec;
        states_.erase(ip);
    }
    // 惰性回收：状态表超 4096 时清理长窗内无活动的 IP（防内存无界增长）
    void gc(int64_t now) {
        if (states_.size() <= 4096) return;
        for (auto it = states_.begin(); it != states_.end();) {
            if (now - it->second.touch > cfg_.slowCcWinSec) it = states_.erase(it);
            else ++it;
        }
        for (auto it = locked_.begin(); it != locked_.end();) {
            if (it->second <= now) it = locked_.erase(it);
            else ++it;
        }
    }

    Config cfg_;
    std::mutex mtx_;
    std::unordered_map<std::string, IpState> states_;
    std::unordered_map<std::string, int64_t> locked_;  // ip → 锁定到期时间
};

}  // namespace novawaf
