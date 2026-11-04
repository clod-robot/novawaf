// NovaWAF - 认证爆破防护（登录/验证码等认证接口的独立限流与源 IP 锁定）
// 背景：复测确认对认证接口连发错误凭证零防护（15 次全放行）。由于业务失败响应
// 与成功响应同为 200（错误信息在 body），无法按状态码区分成败，因此对认证接口
// 采用「尝试计数 + 滑动窗口 + 两级冷却」的独立限流：
//   * 窗口内尝试超过软阈值（默认 5 次/60s）→ 每次尝试仅回 10s 短冷却（429 +
//     Retry-After），不累计长锁——正常用户记错密码反复尝试不会被长锁误伤；
//   * 窗口内尝试超过硬阈值（默认 20 次）→ 源 IP 长锁 600s——脚本化爆破在
//     21 次内被切断；
//   * 冷却/锁定期间直接 429，不进入上游，不消耗后端资源。
// 设计：分片锁降低并发竞争；配置走环境变量（热更由 PathPolicy/名单体系承担，
// 本组件为冷启动常量，变更需重启——阈值类配置低频，可接受）。
// 环境变量：
//   NOVA_BRUTE_PATHS    逗号分隔的认证接口前缀（默认见 kDefaultPaths）
//   NOVA_BRUTE_MAX      窗口内软阈值（默认 5，超过进入 10s 短冷却）
//   NOVA_BRUTE_HARD     窗口内硬阈值（默认 20，超过长锁 NOVA_BRUTE_LOCK 秒）
//   NOVA_BRUTE_COOLDOWN 软阈值后的单次冷却秒数（默认 10）
//   NOVA_BRUTE_WIN      统计窗口秒数（默认 60）
//   NOVA_BRUTE_LOCK     硬阈值锁定时长秒数（默认 600）
#pragma once

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {

class BruteGuard {
public:
    static BruteGuard& instance() {
        static BruteGuard inst;
        return inst;
    }

    // 请求前调用：返回剩余冷却/锁定秒数（>0 表示应 429 拒绝）；
    // 返回 0 表示未限制且本次尝试已计入。非认证路径恒返回 0 且不计数。
    // 仅改写型方法（POST/PUT/DELETE/PATCH）计入：GET 验证码/会话查询等读取型
    // 请求永不计数、永不被限（此前 GET /api/auth/captcha 也占窗口，用户刷新
    // 几次页面就占满软阈值，验证码接口连带被 429，正常用户被锁在门外）。
    int hit(const std::string& ip, const std::string& path, const std::string& method) {
        if (!isAuthPath(path)) return 0;
        if (!isWriteMethod(method)) return 0;
        int64_t now = nowSec();
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        IpState& st = s.states[ip];
        if (st.lockUntil > now) return (int)(st.lockUntil - now);
        // 驱逐窗口外尝试
        while (!st.hits.empty() && st.hits.front() <= now - winSec_) st.hits.pop_front();
        st.hits.push_back(now);
        int n = (int)st.hits.size();
        // 硬阈值：长锁（脚本化爆破特征——持续高频尝试）
        if (n > hardMax_) {
            st.lockUntil = now + lockSec_;
            st.hits.clear();
            return (int)lockSec_;
        }
        // 软阈值：每次尝试仅回短冷却，不设长锁（正常用户误输密码可 10s 后重试，
        // 尝试仍计入窗口，持续超窗尝试会触达硬阈值被长锁）
        if (n > maxAttempts_) return cooldownSec_;
        return 0;
    }

    // 管理台/排障用：某 IP 当前剩余锁定秒数（不产生副作用）
    int lockedRemain(const std::string& ip) {
        auto& s = shard(ip);
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.states.find(ip);
        if (it == s.states.end()) return 0;
        int64_t r = it->second.lockUntil - nowSec();
        return r > 0 ? (int)r : 0;
    }

private:
    BruteGuard() {
        // 认证接口默认前缀：登录、验证码、注册、找回密码等凭证相关端点。
        // 注意不含 /api/auth/me 等高频会话查询，避免正常浏览触发计数。
        const char* defPaths = "/api/auth/login,/api/auth/captcha,"
                               "/api/auth/register,/api/auth/sendcode,"
                               "/api/auth/reset,/api/auth/forgot";
        const char* p = std::getenv("NOVA_BRUTE_PATHS");
        std::string csv = (p && *p) ? p : defPaths;
        std::string cur;
        for (char c : csv) {
            if (c == ',') { if (!cur.empty()) paths_.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) paths_.push_back(cur);
        if (const char* e = std::getenv("NOVA_BRUTE_MAX")) { int v = std::atoi(e); if (v >= 1) maxAttempts_ = v; }
        if (const char* e = std::getenv("NOVA_BRUTE_HARD")) { int v = std::atoi(e); if (v > maxAttempts_) hardMax_ = v; }
        if (const char* e = std::getenv("NOVA_BRUTE_COOLDOWN")) { int v = std::atoi(e); if (v >= 1) cooldownSec_ = v; }
        if (const char* e = std::getenv("NOVA_BRUTE_WIN")) { int64_t v = std::atoll(e); if (v >= 1) winSec_ = v; }
        if (const char* e = std::getenv("NOVA_BRUTE_LOCK")) { int64_t v = std::atoll(e); if (v >= 10) lockSec_ = v; }
    }

    bool isAuthPath(const std::string& path) const {
        for (auto& p : paths_)
            if (path.compare(0, p.size(), p) == 0) return true;
        return false;
    }

    // 改写型方法判定：只有会真正提交凭证的写操作才可能是爆破尝试。
    // 请求行方法标准客户端恒大写，此处做大小写归一兜底。
    static bool isWriteMethod(const std::string& m) {
        std::string u;
        u.reserve(m.size());
        for (char c : m) u += (char)std::toupper((unsigned char)c);
        return u == "POST" || u == "PUT" || u == "DELETE" || u == "PATCH";
    }

    static int64_t nowSec() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    struct IpState {
        std::deque<int64_t> hits;   // 窗口内尝试时间戳
        int64_t lockUntil = 0;      // 长锁截止
    };
    struct Shard {
        mutable std::mutex mtx;
        std::unordered_map<std::string, IpState> states;
    };
    static constexpr size_t kShards = 32;
    Shard& shard(const std::string& ip) {
        return shards_[std::hash<std::string>{}(ip) & (kShards - 1)];
    }

    std::vector<std::string> paths_;
    int maxAttempts_ = 5;        // 软阈值：窗口内尝试超过则进入短冷却
    int hardMax_ = 20;           // 硬阈值：窗口内尝试超过则长锁
    int cooldownSec_ = 10;       // 软阈值后的单次冷却（秒）
    int64_t winSec_ = 60;        // 统计窗口（秒）
    int64_t lockSec_ = 600;      // 硬阈值锁定时长（秒）
    Shard shards_[kShards];
};

}  // namespace novawaf
