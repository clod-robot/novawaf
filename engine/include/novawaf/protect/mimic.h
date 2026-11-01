// NovaWAF - 拟态防御（Mimic Defense / Moving Target Defense）
// 核心思想：对外暴露的响应指纹随时间窗确定性轮换，使攻击者无法获得稳定的
// WAF/服务器解析行为画像，大幅提升指纹探测与差分绕过探测的成本。
//
// 设计要点：
//   * 时间窗种子：seed = FNV-1a(salt + ":" + epoch/windowMin)。窗内所有请求得到
//     完全一致的人格（正常用户体验稳定），跨窗人格轮换（攻击者跨窗探测结论失效）。
//   * 一体化画像（Persona）：Server banner / 拦截状态码 / 拦截页模板 / 会话 cookie 名
//     四者按同一风格成组轮换，避免出现 "nginx banner + IIS 页面" 这类一眼假的组合。
//   * 幽灵人格：404（扫描器把被拦路径标记为"不存在"，毒化扫描结果）与 503
//     （伪装过载，诱导扫描器降速/放弃）。
//   * 探测干扰：识别扫描器 UA 后，其拦截响应不再使用窗内人格，而是每次随机抽取
//     人格——同一工具在同一窗内连续探测也会得到自相矛盾的指纹。
//   * 仅作用于指纹三态的 HIDDEN 模式；PUBLIC 模式以品牌威慑为先，拟态让位。
//   * 检测语义零影响：内部解析/检测始终全维度最严，拟态只改变"对外表现"，
//     不引入任何漏检面。
// 配置（Redis HASH novawaf:mimic，2s 热刷新，与 WafMode 同模式）：
//   enabled   = 1|0（默认 0 关闭）
//   windowMin = 轮换窗口分钟数（默认 60，钳制 [5,1440]）
//   salt      = 随机盐，重置即更换全部人格序列（管理台一键轮换）
// 状态回写（Redis HASH novawaf:mimic:status）：人格变化时写入，供管理台预览。
#pragma once

#include "novawaf/core/redis_client.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/random.h>

namespace novawaf {

class MimicDefense {
public:
    // 一体化画像：四项指纹同风格成组
    struct Profile {
        const char* serverBanner;    // Server 响应头伪装
        int blockStatus;             // 拦截响应状态码
        const char* blockStatusText; // 状态码短语
        int pageTemplate;            // 拦截页模板（BlockPage::renderMimic）
        const char* cookieName;      // 会话 cookie 名（HIDDEN 下替换默认 sid）
        const char* persona;         // 人格名（管理台展示）
    };

    static MimicDefense& instance() { static MimicDefense inst; return inst; }

    // 热路径：当前窗人格。未启用返回 nullptr。
    // 2s 节流热刷新配置；人格按时间窗确定性选择并跨线程原子缓存。
    const Profile* current() {
        maybeRefresh();
        auto cfg = cfg_.load();
        if (!cfg || !cfg->enabled) {
            lastIdx_.store(-1, std::memory_order_release);
            return nullptr;
        }
        // seed 随 salt 与窗号确定性变化：同窗同人格，跨窗/换盐即轮换。
        // FNV 输入仅十余字节，热路径逐请求计算开销可忽略，换来换盐立即生效。
        int64_t slot = (int64_t)::time(nullptr) / ((int64_t)cfg->windowMin * 60);
        int idx = (int)(fnv1a(cfg->salt + ":" + std::to_string(slot)) % kProfileCount);
        int prev = lastIdx_.load(std::memory_order_acquire);
        if (idx != prev &&
            lastIdx_.compare_exchange_strong(prev, idx, std::memory_order_acq_rel)) {
            writeStatus(kProfiles[idx], (slot + 1) * ((int64_t)cfg->windowMin * 60));
        }
        return &kProfiles[idx];
    }

    // 探测干扰：扫描器来源的拦截每次随机人格（同窗内连续探测也自相矛盾）
    const Profile* randomProfile() {
        uint32_t r = 0;
        if (::getrandom(&r, sizeof(r), 0) != (ssize_t)sizeof(r))
            r = (uint32_t)(::time(nullptr) * 2654435761u);
        return &kProfiles[r % kProfileCount];
    }

    // HIDDEN 模式下的会话 cookie 名（拟态启用时替换默认 sid）
    const char* cookieName(const char* fallback) {
        const Profile* p = current();
        return p ? p->cookieName : fallback;
    }

    // 扫描器/指纹工具 UA 特征识别
    static bool looksLikeScanner(const std::string& ua) {
        if (ua.empty()) return false;
        std::string low = ua;
        for (auto& c : low) c = (char)tolower((unsigned char)c);
        static const char* kSig[] = {
            "wafw00f", "nikto", "sqlmap", "nmap", "masscan", "nuclei",
            "acunetix", "nessus", "openvas", "gobuster", "dirbuster",
            "dirsearch", "hydra", "metasploit", "burpsuite", "zgrab",
            "wpscan", "whatweb", "skipfish", "arachni", "appscan", "netsparker"
        };
        for (auto* s : kSig)
            if (low.find(s) != std::string::npos) return true;
        return false;
    }

    // 管理面/测试用：立即刷新配置
    void forceRefresh() {
        lastRefresh_.store(0, std::memory_order_release);
        maybeRefresh();
    }

private:
    MimicDefense() = default;

    struct Config {
        bool enabled = false;
        int windowMin = 60;
        std::string salt;
    };

    // FNV-1a 64 + splitmix64 终态混合：salt 保密时窗内种子对外不可预测
    static uint64_t fnv1a(const std::string& s) {
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
        h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        return h;
    }

    void maybeRefresh() {
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch()).count();
        int64_t last = lastRefresh_.load(std::memory_order_acquire);
        if (now - last > 2000 &&
            lastRefresh_.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
            refresh();
        }
    }

    void refresh() {
        const char* rh = std::getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db, 300)) return;  // 300ms 超时，不拖累热路径
        auto enabled = r.hget("novawaf:mimic", "enabled");
        auto windowMin = r.hget("novawaf:mimic", "windowMin");
        auto salt = r.hget("novawaf:mimic", "salt");
        auto cfg = std::make_shared<Config>();
        cfg->enabled = enabled && *enabled == "1";
        cfg->windowMin = 60;
        if (windowMin) {
            int w = std::atoi(windowMin->c_str());
            if (w < 5) w = 5;
            if (w > 1440) w = 1440;
            cfg->windowMin = w;
        }
        if (salt) cfg->salt = *salt;
        cfg_.store(cfg);
    }

    // 人格变化时回写状态，供管理台预览当前人格与窗口结束时间（低频写，窗内不变不写）
    void writeStatus(const Profile& p, int64_t slotEnd) {
        const char* rh = std::getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = std::getenv("NOVA_REDIS_PASS");
        int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db, 300)) return;
        r.hset("novawaf:mimic:status", "persona", p.persona);
        r.hset("novawaf:mimic:status", "banner", p.serverBanner);
        r.hset("novawaf:mimic:status", "blockStatus", std::to_string(p.blockStatus));
        r.hset("novawaf:mimic:status", "cookieName", p.cookieName);
        r.hset("novawaf:mimic:status", "slotEnd", std::to_string(slotEnd));
    }

    static constexpr Profile kProfiles[] = {
        // banner                      状态码  状态短语                          模板  cookie名              人格名
        { "nginx",                    403, "Forbidden",                        0, "sid",               "nginx"        },
        { "nginx/1.24.0",             403, "Forbidden",                        0, "sess",              "nginx 1.24"   },
        { "Apache/2.4.58 (Ubuntu)",   403, "Forbidden",                        1, "PHPSESSID",         "Apache 2.4"   },
        { "Microsoft-IIS/10.0",       403, "Forbidden",                        2, "ASP.NET_SessionId", "IIS 10"       },
        { "openresty/1.25.4.1",       403, "Forbidden",                        0, "session",           "openresty"    },
        { "Tengine/3.1.0",            403, "Forbidden",                        0, "token",             "Tengine"      },
        { "nginx",                    404, "Not Found",                        3, "sid",               "ghost-404"    },
        { "nginx",                    503, "Service Temporarily Unavailable",  4, "sid",               "busy-503"     },
    };
    static constexpr int kProfileCount = (int)(sizeof(kProfiles) / sizeof(kProfiles[0]));

    std::atomic<std::shared_ptr<Config>> cfg_{std::make_shared<Config>()};
    std::atomic<int64_t> lastRefresh_{0};
    std::atomic<int> lastIdx_{-1};
};

}  // namespace novawaf
