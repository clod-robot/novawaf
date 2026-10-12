// NovaWAF - 基于地理位置的 IP 拦截（地理围栏 / GeoIP 封锁）
// 设计原则（合规）：
//   - 纯离线：从本地文件加载 CIDR→国家代码 映射，运行时不访问任何外部 API，
//     不泄露访问者 IP，满足等保对数据出境与最小化的要求。
//   - 私有/保留地址（内网、环回、链路本地）永远放行，避免误伤内网与健康检查。
//   - 查找未命中（未知国家）默认放行，遵循"默认放行、显式封锁"的保守策略。
// 数据文件 rules/geoip.txt 格式：
//   cidr,CC[,country]      例: 8.8.8.0/24,US,Google
//   # 开头为注释。生产可由 GeoLite2 等库转换为该 CSV 覆盖更新。
// 高并发：数据集不可变 + atomic<shared_ptr> copy-on-write 热更新，查找无锁。
#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "novawaf/detect/http_model.h"

namespace novawaf {

// 处置模式
enum class GeoMode {
    BLACKLIST,  // 仅封锁 listed 国家
    WHITELIST   // 仅放行 listed 国家，其余封锁
};

class GeoFilter {
public:
    GeoFilter() : data_(std::make_shared<Dataset>()) {}

    // 从文本行加载 CIDR→国家映射，返回成功条目数。原子替换数据集（热更新）。
    size_t loadFromLines(const std::vector<std::string>& lines) {
        auto ds = std::make_shared<Dataset>();
        size_t n = 0;
        for (auto& raw : lines) {
            std::string line = trim(raw);
            if (line.empty() || line[0] == '#') continue;
            auto f = splitCsv(line);
            if (f.size() < 2) continue;
            std::string cidr = trim(f[0]);
            std::string cc = toUpper(trim(f[1]));
            if (cc.empty()) continue;
            auto range = parseCidr(cidr);
            if (range.first == 0 && range.second == 0) continue;
            ds->ranges.push_back({range.first, range.second, cc});
            n++;
        }
        std::sort(ds->ranges.begin(), ds->ranges.end(),
                  [](const Range& a, const Range& b) { return a.start < b.start; });
        ds->count = n;
        data_.store(ds, std::memory_order_release);
        return n;
    }

    // 配置封锁/放行国家代码集合（CC 大写，如 "CN","US"）
    void setBlockedCountries(std::vector<std::string> ccs) {
        std::lock_guard<std::mutex> lk(cfgMtx_);
        blocked_.clear();
        for (auto& c : ccs) blocked_.insert(toUpper(trim(c)));
    }
    void setAllowedCountries(std::vector<std::string> ccs) {
        std::lock_guard<std::mutex> lk(cfgMtx_);
        allowed_.clear();
        for (auto& c : ccs) allowed_.insert(toUpper(trim(c)));
    }
    void setMode(GeoMode m) { std::lock_guard<std::mutex> lk(cfgMtx_); mode_ = m; }
    void setEnabled(bool on) { enabled_.store(on, std::memory_order_release); }

    bool enabled() const { return enabled_.load(std::memory_order_acquire); }
    size_t rangeCount() const { return data_.load(std::memory_order_acquire)->count; }

    // 返回 IP 归属国家代码（大写）。内网/保留地址返回 "内网"，未知返回空串。
    // 锁无关 copy-on-write 查找，可在 reactor 热路径安全调用。
    std::string country(const std::string& ip) {
        if (ip.empty()) return {};
        if (isPrivateOrReserved(ip)) return "内网";
        uint32_t u = ipToUint(ip);
        if (u == 0) return {};
        return lookup(u);
    }

    // 评估：命中地理策略返回 BLOCK，否则空（放行）
    std::optional<DetectionResult> assess(const std::string& ip) {
        if (!enabled_.load(std::memory_order_acquire)) return std::nullopt;
        if (ip.empty() || isPrivateOrReserved(ip)) return std::nullopt;  // 内网/保留放行

        uint32_t u = ipToUint(ip);
        if (u == 0) return std::nullopt;
        std::string cc = lookup(u);
        if (cc.empty()) return std::nullopt;  // 未知国家 → 默认放行

        std::lock_guard<std::mutex> lk(cfgMtx_);
        bool hit = false;
        if (mode_ == GeoMode::BLACKLIST) {
            hit = blocked_.count(cc) > 0;
        } else {
            hit = !allowed_.empty() && allowed_.count(cc) == 0;  // 不在白名单 → 封锁
        }
        if (!hit) return std::nullopt;
        return DetectionResult{Action::BLOCK, "GEO-001", "GeoBlock",
                               std::string("geo-blocked country ") + cc, ip + "(" + cc + ")"};
    }

private:
    struct Range { uint32_t start; uint32_t end; std::string cc; };
    struct Dataset {
        std::vector<Range> ranges;
        size_t count = 0;
    };

    std::atomic<bool> enabled_{false};
    std::atomic<std::shared_ptr<Dataset>> data_;
    std::mutex cfgMtx_;
    GeoMode mode_ = GeoMode::BLACKLIST;
    std::unordered_set<std::string> blocked_;
    std::unordered_set<std::string> allowed_;

    // 二分查找：返回包含 u 的区间的国家代码，否则空
    std::string lookup(uint32_t u) const {
        auto ds = data_.load(std::memory_order_acquire);
        if (!ds || ds->ranges.empty()) return {};
        // 最大的 start <= u
        auto it = std::upper_bound(ds->ranges.begin(), ds->ranges.end(), u,
            [](uint32_t val, const Range& r) { return val < r.start; });
        if (it == ds->ranges.begin()) return {};
        --it;
        if (u >= it->start && u <= it->end) return it->cc;
        return {};
    }

    // 私有 / 保留地址判定（IPv4）
    static bool isPrivateOrReserved(const std::string& ip) {
        uint32_t u = ipToUint(ip);
        if (u == 0) return false;
        uint32_t a = (u >> 24) & 0xFF;
        // 0.0.0.0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 100.64/10, 224-255 组播/保留
        if (a == 0 || a == 10 || a == 127) return true;
        if (a == 192 && ((u >> 16) & 0xFF) == 168) return true;
        if (a == 172) { uint32_t b = (u >> 16) & 0xFF; if (b >= 16 && b <= 31) return true; }
        if (a == 169 && ((u >> 16) & 0xFF) == 254) return true;
        if (a == 100) { uint32_t b = (u >> 16) & 0xFF; if (b >= 64 && b <= 127) return true; }
        if (a >= 224) return true;
        return false;
    }

    static uint32_t ipToUint(const std::string& ip) {
        int a, b, c, d;
        if (std::sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;
        if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return 0;
        return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | uint32_t(d);
    }
    static std::pair<uint32_t, uint32_t> parseCidr(const std::string& s) {
        auto slash = s.find('/');
        if (slash == std::string::npos) {
            uint32_t ip = ipToUint(s);
            return ip ? std::make_pair(ip, ip) : std::make_pair(0u, 0u);
        }
        uint32_t net = ipToUint(s.substr(0, slash));
        int bits = std::atoi(s.substr(slash + 1).c_str());
        if (net == 0 || bits < 0 || bits > 32) return {0, 0};
        uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
        uint32_t start = net & mask;
        uint32_t end = (bits == 32) ? start : (start | (~mask));
        return {start, end};
    }

    static std::string trim(const std::string& s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace((unsigned char)s[a])) a++;
        while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
        return s.substr(a, b - a);
    }
    static std::string toUpper(std::string s) {
        for (auto& c : s) c = (char)std::toupper((unsigned char)c);
        return s;
    }
    static std::vector<std::string> splitCsv(const std::string& s) {
        std::vector<std::string> out; std::string cur;
        for (char c : s) { if (c == ',') { out.push_back(cur); cur.clear(); } else cur += c; }
        out.push_back(cur);
        return out;
    }
};

}  // namespace novawaf
