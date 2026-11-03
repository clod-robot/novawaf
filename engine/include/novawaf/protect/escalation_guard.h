// NovaWAF - 攻击升级计数器（分级处置）
// 背景：此前规则命中即 fw L3 封禁全站，处置粒度太粗——一次误报或单次探测
// 就剥夺该 IP 的全部访问权。改为分级：命中只阻断当次请求（403 单笔），
// 同一 IP 在滑窗内累计命中 N 次才升级 fw 封禁（持续攻击者才付出代价）。
// 与蜜罐观察模式同构：16 分片锁滑窗计数，惰性回收，热路径低竞争。
// 阈值可由环境变量调整：NOVA_ATTACK_ESCALATE_N（默认 3）、NOVA_ATTACK_WIN_SEC（默认 600）。
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>

namespace novawaf {

class EscalationGuard {
public:
    static EscalationGuard& instance() {
        static EscalationGuard g;
        return g;
    }

    // 记录一次规则命中，返回该 IP 窗口内累计命中次数（含本次）
    int noteHit(const std::string& ip) {
        if (ip.empty()) return 0;
        Shard& sh = shards_[hash(ip) & 15];
        std::lock_guard<std::mutex> lk(sh.mtx);
        int64_t now = nowSec();
        auto& st = sh.hits[ip];
        if (st.winStart == 0 || now - st.winStart >= winSec_) {
            st.winStart = now;
            st.count = 0;
        }
        int n = ++st.count;
        if (sh.hits.size() > 512) {  // 惰性回收，防内存膨胀
            for (auto it = sh.hits.begin(); it != sh.hits.end();) {
                if (now - it->second.winStart >= winSec_) it = sh.hits.erase(it);
                else ++it;
            }
        }
        return n;
    }

    // 升级阈值：达到该命中次数后允许 fw 封禁
    static int escalateN() {
        const char* e = std::getenv("NOVA_ATTACK_ESCALATE_N");
        int v = e ? std::atoi(e) : 0;
        return v > 0 ? v : 3;
    }

private:
    EscalationGuard() : winSec_([] {
        const char* e = std::getenv("NOVA_ATTACK_WIN_SEC");
        int v = e ? std::atoi(e) : 0;
        return v > 0 ? v : 600;
    }()) {}

    struct HitState { int64_t winStart = 0; int count = 0; };
    struct Shard { std::mutex mtx; std::unordered_map<std::string, HitState> hits; };

    static int64_t nowSec() {
        return (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    static uint32_t hash(const std::string& s) {
        uint32_t h = 2166136261u;
        for (char c : s) { h ^= (uint8_t)c; h *= 16777619u; }
        return h;
    }

    std::array<Shard, 16> shards_;
    const int winSec_;
};

}  // namespace novawaf
