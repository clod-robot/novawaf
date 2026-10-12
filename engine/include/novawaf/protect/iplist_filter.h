// NovaWAF - IP 黑白名单（联动管理控制台 novawaf:blacklist / novawaf:whitelist）
// 数据来源：Redis JSON 数组，元素 {ip, enabled}（ip 支持单 IP 或 CIDR）。
// 热加载：版本号 novawaf:iplist:version 变化时整体原子替换，热路径 match 无锁。
// 语义：白名单命中 → 直接放行（跳过所有检测）；黑名单命中 → 直接拦截。
#pragma once

#include "novawaf/core/json.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace novawaf {

class IpListFilter {
public:
    enum class Verdict { NONE, WHITE, BLACK };

    static IpListFilter& instance() { static IpListFilter inst; return inst; }

    // 解析两份 JSON 并原子替换。返回 {black, white} 启用条数。
    std::pair<size_t, size_t> reload(const std::string& blackJson, const std::string& whiteJson) {
        auto next = std::make_shared<Snapshot>();
        size_t b = buildRanges(blackJson, next->black);
        size_t w = buildRanges(whiteJson, next->white);
        snap_.store(next, std::memory_order_release);
        return {b, w};
    }

    Verdict match(const std::string& ip) const {
        uint32_t u = ipToUint(ip);
        if (u == 0) return Verdict::NONE;
        auto s = snap_.load(std::memory_order_acquire);
        if (!s) return Verdict::NONE;
        if (contains(s->white, u)) return Verdict::WHITE;
        if (contains(s->black, u)) return Verdict::BLACK;
        return Verdict::NONE;
    }

private:
    struct Range { uint32_t start, end; };
    struct Snapshot { std::vector<Range> black; std::vector<Range> white; };
    std::atomic<std::shared_ptr<Snapshot>> snap_{std::make_shared<Snapshot>()};

    static bool contains(const std::vector<Range>& rs, uint32_t u) {
        if (rs.empty()) return false;
        int lo = 0, hi = (int)rs.size();
        while (lo < hi) { int mid = (lo + hi) >> 1; if (rs[mid].start <= u) lo = mid + 1; else hi = mid; }
        return lo > 0 && u >= rs[lo - 1].start && u <= rs[lo - 1].end;
    }

    static size_t buildRanges(const std::string& json, std::vector<Range>& out) {
        out.clear();
        if (json.empty()) return 0;
        JsonValue root;
        try { root = parseJson(json); } catch (...) { return 0; }
        if (!root.isArray()) return 0;
        std::vector<Range> tmp;
        for (auto& item : root.arr) {
            if (!item.isObject()) continue;
            const JsonValue& en = item.at("enabled");
            if (en.isBool() && !en.b) continue;          // 禁用跳过
            const JsonValue& ipf = item.at("ip");
            if (!ipf.isString() || ipf.str.empty()) continue;
            auto se = parseCidr(ipf.str);
            if (!se) continue;
            tmp.push_back({se->first, se->second});
        }
        std::sort(tmp.begin(), tmp.end(), [](const Range& a, const Range& b){ return a.start < b.start; });
        out = std::move(tmp);
        return out.size();
    }

    static uint32_t ipToUint(const std::string& ip) {
        int a, b, c, d;
        if (std::sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;
        if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return 0;
        return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | uint32_t(d);
    }
    static std::optional<std::pair<uint32_t, uint32_t>> parseCidr(const std::string& s) {
        auto slash = s.find('/');
        if (slash == std::string::npos) {
            uint32_t ip = ipToUint(s);
            if (!ip) return std::nullopt;
            return std::make_pair(ip, ip);
        }
        uint32_t net = ipToUint(s.substr(0, slash));
        int bits = std::atoi(s.substr(slash + 1).c_str());
        if (net == 0 || bits < 0 || bits > 32) return std::nullopt;
        uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
        uint32_t start = net & mask;
        uint32_t end = (bits == 32) ? start : (start | (~mask));
        return std::make_pair(start, end);
    }
};

}  // namespace novawaf
