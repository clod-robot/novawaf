// NovaWAF - 威胁情报（Threat Intelligence / IOC）模块
// 数据驱动的 IOC 库：恶意 IP / CIDR / 路径 / 域名 / User-Agent / 攻击签名。
// 能力：
//   - 从文本/CSV 加载（支持注释、类型分级、类别、描述）；
//   - copy-on-write 原子热更新（reload 不阻塞检测热路径）；
//   - 匹配请求 → 返回分级处置（BLOCK/CHALLENGE/LOG）；
//   - 可由远程威胁情报源定期刷新（见 ti_feed.h 或上层定时器）。
#pragma once

#include "novawaf/detect/http_model.h"
#include "novawaf/detect/ac_automaton.h"

#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace novawaf {

// 处置级别：数字越大越严重
enum class TiSeverity { LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4 };

// 单条 IOC
struct IoC {
    std::string type;       // ip / cidr / path / domain / ua / signature
    std::string value;
    TiSeverity severity = TiSeverity::MEDIUM;
    std::string category;   // 如 botnet / scanner / webshell / exploit-kit
    std::string desc;
};

// 解析级别字符串
inline TiSeverity parseSeverity(const std::string& s) {
    if (s == "critical" || s == "4") return TiSeverity::CRITICAL;
    if (s == "high"     || s == "3") return TiSeverity::HIGH;
    if (s == "low"      || s == "1") return TiSeverity::LOW;
    return TiSeverity::MEDIUM;
}
inline const char* sevName(TiSeverity s) {
    switch (s) {
        case TiSeverity::CRITICAL: return "critical";
        case TiSeverity::HIGH:     return "high";
        case TiSeverity::LOW:      return "low";
        default:                   return "medium";
    }
}

// 级别 → 处置动作（可配置阈值）
inline Action severityToAction(TiSeverity s, TiSeverity blockThreshold) {
    if (s >= blockThreshold) return Action::BLOCK;
    if (s >= TiSeverity::MEDIUM) return Action::CHALLENGE;
    return Action::LOG;
}

// 一个 IOC 数据集（不可变，reload 时整体替换）
struct TiDataset {
    std::unordered_set<std::string> ips;
    struct Cidr { uint32_t net; uint32_t mask; std::string value; };
    std::vector<Cidr> cidrs;  // IPv4
    AcAutomaton paths;        // 路径命中（前缀/包含）
    AcAutomaton domains;
    AcAutomaton uas;
    AcAutomaton signatures;   // 攻击签名（命中任意 payload）
    std::unordered_map<std::string, IoC> meta;  // key(type:value) -> 原始 IOC
    size_t count = 0;
};

class ThreatIntel {
public:
    explicit ThreatIntel(TiSeverity blockThreshold = TiSeverity::HIGH)
        : blockThreshold_(blockThreshold),
          data_(std::make_shared<TiDataset>()) {}

    // 从文本行加载：每行 "type,value,severity,category,desc"，# 开头为注释
    // 也接受只有 "type,value" 的简版（默认 medium）。返回成功解析条数。
    size_t loadFromLines(const std::vector<std::string>& lines) {
        auto ds = std::make_shared<TiDataset>();
        size_t n = 0;
        for (auto& raw : lines) {
            std::string line = trim(raw);
            if (line.empty() || line[0] == '#') continue;
            auto f = splitCsv(line);
            if (f.size() < 2) continue;
            IoC ioc;
            ioc.type = toLower(trim(f[0]));
            ioc.value = trim(f[1]);
            if (ioc.value.empty()) continue;
            ioc.severity = (f.size() >= 3) ? parseSeverity(toLower(trim(f[2]))) : TiSeverity::MEDIUM;
            ioc.category = (f.size() >= 4) ? trim(f[3]) : "ti";
            ioc.desc     = (f.size() >= 5) ? trim(f[4]) : "";
            addIoC(*ds, ioc);
            n++;
        }
        ds->paths.build(); ds->domains.build(); ds->uas.build(); ds->signatures.build();
        ds->count = n;
        data_.store(ds, std::memory_order_release);
        return n;
    }

    // 匹配请求，命中返回处置结果；否则空
    std::optional<DetectionResult> match(const HttpRequest& req) {
        auto ds = data_.load(std::memory_order_acquire);
        if (!ds || ds->count == 0) return std::nullopt;

        // 1) 源 IP（精确 + CIDR）
        if (!req.clientIp.empty()) {
            if (ds->ips.count(req.clientIp))
                return makeResult(*ds, "ip:" + req.clientIp, req.clientIp);
            uint32_t ip = ipToUint(req.clientIp);
            if (ip != 0) {
                for (auto& c : ds->cidrs) {
                    if ((ip & c.mask) == c.net)
                        return makeResult(*ds, "cidr:" + c.value, req.clientIp);
                }
            }
        }
        // 辅助：扫描自动机，返回首个命中的原始模式串
        auto acMatch = [](const AcAutomaton& ac, const std::string& text)
                          -> std::string {
            auto hits = ac.scan(text);
            if (hits.empty()) return {};
            return ac.pattern(hits[0].patternId);
        };

        // 2) 路径
        {
            std::string pat = acMatch(ds->paths, req.path);
            if (!pat.empty()) return makeResult(*ds, "path:" + pat, req.path);
        }
        // 3) 域名(Host)
        {
            auto hit = req.headers.find("Host");
            if (hit != req.headers.end()) {
                std::string pat = acMatch(ds->domains, hit->second);
                if (!pat.empty()) return makeResult(*ds, "domain:" + pat, hit->second);
            }
        }
        // 4) User-Agent（大小写不敏感）
        {
            auto hit = req.headers.find("User-Agent");
            if (hit != req.headers.end()) {
                std::string ua = hit->second;
                for (auto& c : ua) c = (char)std::tolower((unsigned char)c);
                std::string pat = acMatch(ds->uas, ua);
                if (!pat.empty()) return makeResult(*ds, "ua:" + pat, hit->second);
            }
        }
        // 5) 攻击签名（扫所有 payload）
        for (auto& payload : req.collectPayloads()) {
            std::string pat = acMatch(ds->signatures, payload);
            if (!pat.empty())
                return makeResult(*ds, "signature:" + pat, payload);
        }
        return std::nullopt;
    }

    size_t count() const { return data_.load(std::memory_order_acquire)->count; }

private:
    static void addIoC(TiDataset& ds, const IoC& ioc) {
        ds.meta[ioc.type + ":" + ioc.value] = ioc;
        if (ioc.type == "ip") {
            ds.ips.insert(ioc.value);
        } else if (ioc.type == "cidr") {
            auto cm = parseCidr(ioc.value);
            if (cm.first != 0) ds.cidrs.push_back({cm.first, cm.second, ioc.value});
        } else if (ioc.type == "path") {
            ds.paths.addPattern(ioc.value);
        } else if (ioc.type == "domain") {
            ds.domains.addPattern(ioc.value);
        } else if (ioc.type == "ua") {
            ds.uas.addPattern(ioc.value);
        } else if (ioc.type == "signature") {
            ds.signatures.addPattern(ioc.value);
        }
    }

    DetectionResult makeResult(const TiDataset& ds, const std::string& key,
                               const std::string& matched) const {
        auto it = ds.meta.find(key);
        TiSeverity sev = TiSeverity::MEDIUM;
        std::string cat = "ti", desc = "threat intel match";
        if (it != ds.meta.end()) { sev = it->second.severity; cat = it->second.category;
                                   if (!it->second.desc.empty()) desc = it->second.desc; }
        Action a = severityToAction(sev, blockThreshold_);
        return {a, "TI-001", cat, std::string("[") + sevName(sev) + "] " + desc, matched};
    }

    static std::string trim(const std::string& s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace((unsigned char)s[a])) a++;
        while (b > a && std::isspace((unsigned char)s[b-1])) b--;
        return s.substr(a, b - a);
    }
    static std::string toLower(std::string s) {
        for (auto& c : s) c = (char)std::tolower((unsigned char)c);
        return s;
    }
    static std::vector<std::string> splitCsv(const std::string& s) {
        std::vector<std::string> out; std::string cur;
        for (char c : s) {
            if (c == ',') { out.push_back(cur); cur.clear(); }
            else cur += c;
        }
        out.push_back(cur);
        return out;
    }
    static uint32_t ipToUint(const std::string& ip) {
        int a,b,c,d;
        if (std::sscanf(ip.c_str(), "%d.%d.%d.%d", &a,&b,&c,&d) != 4) return 0;
        if (a<0||a>255||b<0||b>255||c<0||c>255||d<0||d>255) return 0;
        return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d);
    }
    // 解析 "1.2.3.0/24" → (network, mask)
    static std::pair<uint32_t,uint32_t> parseCidr(const std::string& s) {
        auto slash = s.find('/');
        if (slash == std::string::npos) return {0,0};
        uint32_t net = ipToUint(s.substr(0, slash));
        int bits = std::atoi(s.substr(slash+1).c_str());
        if (net == 0 || bits < 0 || bits > 32) return {0,0};
        uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
        return {net & mask, mask};
    }

    TiSeverity blockThreshold_;
    std::atomic<std::shared_ptr<TiDataset>> data_;
};

}  // namespace novawaf
