// NovaWAF - CVE 虚拟补丁模板引擎（应急漏洞热防护）
// 场景：新 CVE 披露后、上游修复前，安全团队在管理控制台按模板批量下发虚拟补丁，
//       引擎经 Redis 热加载即时生效，无需重启/升级。
// 数据来源：Redis STRING novawaf:cve_patch（JSON 数组），版本键 novawaf:cve_patch:version
//   [{
//     "cve": "CVE-2021-44228",          // 必填，作为事件 ruleId（溯源/SIEM 关联 CVE 知识库）
//     "name": "Log4Shell JNDI",          // 可选，事件描述
//     "enabled": true,                   // 可选，默认 true
//     "action": "block",                 // 可选 block|log|pass，默认 block
//     "severity": "high",                // 可选，默认 high
//     "methods": ["GET","POST"],         // 可选，缺省匹配所有方法
//     "uri": "/api/login",               // 可选，path 子串收敛作用域
//     "scope": ["uri","args","headers","body"],  // 可选，缺省全域
//     "headers": {"x-api-version": "v1"},// 可选，指定头须含子串（全部满足才命中）
//     "match": "${jndi:"                 // 必填，匹配串（与检测文本同套归一化）
//   }]
// 匹配算法：所有补丁 match 串构建单棵 AC 自动机，各 scope 文本每请求仅扫描一次；
//           命中后再回验该补丁的 method/uri/headers/scope 条件，首条全满足的补丁胜出。
// 热更新：copy-on-write 原子替换（与 CustomRules 同构），检测热路径无锁。
#pragma once

#include "novawaf/core/json.h"
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <atomic>
#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace novawaf {

enum CveScope : uint8_t { S_URI = 1, S_ARGS = 2, S_HEADERS = 4, S_BODY = 8, S_ALL = 15 };

struct CvePatch {
    std::string cve;
    std::string name;
    std::string severity = "high";
    Action action = Action::BLOCK;
    std::vector<std::string> methods;                          // 大写；空=全部
    std::string uriSub;                                        // path 子串（原始大小写）
    uint8_t scopes = S_ALL;
    std::vector<std::pair<std::string, std::string>> headerConds;  // 头名(小写)->归一化子串
    std::string pattern;                                       // 归一化匹配串
};

// 不可变补丁集：解析 + 构建一次，只读匹配。热更新整体替换。
class CvePatchSet {
public:
    size_t loadFromJson(const std::string& jsonBlob) {
        patches_.clear();
        usedScopes_ = 0;
        if (jsonBlob.empty()) { ac_.build(); return 0; }
        JsonValue root;
        try {
            root = parseJson(jsonBlob);
        } catch (...) {
            ac_.build();
            return 0;  // 解析失败：空集，不影响其它检测器
        }
        if (!root.isArray()) { ac_.build(); return 0; }
        for (auto& item : root.arr) {
            if (!item.isObject()) continue;
            CvePatch p;
            const JsonValue& en = item.at("enabled");
            if (en.isBool() && !en.b) continue;  // 显式禁用
            const JsonValue& cve = item.at("cve");
            if (!cve.isString() || cve.str.empty()) continue;  // 无 CVE 号跳过
            p.cve = cve.str;
            if (item.at("name").isString()) p.name = item.at("name").str;
            if (item.at("severity").isString()) p.severity = item.at("severity").str;
            const JsonValue& act = item.at("action");
            if (act.isString()) {
                if (act.str == "log")       p.action = Action::LOG;
                else if (act.str == "pass") p.action = Action::PASS;
                else                        p.action = Action::BLOCK;
            }
            const JsonValue& ms = item.at("methods");
            if (ms.isArray())
                for (auto& m : ms.arr)
                    if (m.isString()) {
                        std::string u = m.str;
                        for (auto& c : u) c = (char)toupper((unsigned char)c);
                        p.methods.push_back(std::move(u));
                    }
            if (item.at("uri").isString()) p.uriSub = item.at("uri").str;
            const JsonValue& sc = item.at("scope");
            if (sc.isArray()) {
                p.scopes = 0;
                for (auto& s : sc.arr) {
                    if (!s.isString()) continue;
                    if (s.str == "uri") p.scopes |= S_URI;
                    else if (s.str == "args") p.scopes |= S_ARGS;
                    else if (s.str == "headers") p.scopes |= S_HEADERS;
                    else if (s.str == "body") p.scopes |= S_BODY;
                }
                if (p.scopes == 0) p.scopes = S_ALL;
            }
            const JsonValue& hc = item.at("headers");
            if (hc.isObject())
                for (auto& kv : hc.obj) {
                    std::string lname = kv.first;
                    for (auto& c : lname) c = (char)tolower((unsigned char)c);
                    if (kv.second.isString())
                        p.headerConds.push_back({std::move(lname),
                                                 Decoder::normalize(kv.second.str)});
                }
            const JsonValue& m = item.at("match");
            if (!m.isString() || m.str.empty()) continue;  // 无匹配串跳过
            p.pattern = Decoder::normalize(m.str);
            int pid = ac_.addPattern(p.pattern);
            (void)pid;  // addPattern 顺序返回，与 patches_ 下标天然对齐
            usedScopes_ |= p.scopes;
            patches_.push_back(std::move(p));
        }
        ac_.build();
        return patches_.size();
    }

    size_t enabledCount() const { return patches_.size(); }

    // 按 scope 顺序 uri->args->headers->body 惰性归一化扫描，返回首条全条件命中的补丁
    std::optional<CvePatch> match(const HttpRequest& req) const {
        if (patches_.empty()) return std::nullopt;
        if (usedScopes_ & S_URI)
            if (auto hit = scanScope(S_URI, Decoder::normalize(req.path), req)) return hit;
        if (usedScopes_ & S_ARGS) {
            std::string args = req.query;
            for (auto& kv : req.queryParams) {
                args += '\n';
                args += kv.first;
                args += '=';
                args += kv.second;
            }
            if (auto hit = scanScope(S_ARGS, Decoder::normalize(args), req)) return hit;
        }
        if (usedScopes_ & S_HEADERS) {
            std::string hv;
            for (auto& kv : req.headers) { hv += kv.second; hv += '\n'; }
            if (auto hit = scanScope(S_HEADERS, Decoder::normalize(hv), req)) return hit;
        }
        if ((usedScopes_ & S_BODY) && !req.body.empty())
            if (auto hit = scanScope(S_BODY, Decoder::normalize(req.body), req)) return hit;
        return std::nullopt;
    }

private:
    std::optional<CvePatch> scanScope(uint8_t bit, const std::string& normText,
                                      const HttpRequest& req) const {
        if (normText.empty()) return std::nullopt;
        for (auto& h : ac_.scan(normText)) {
            if (h.patternId < 0 || h.patternId >= (int)patches_.size()) continue;
            const CvePatch& p = patches_[h.patternId];
            if (!(p.scopes & bit)) continue;
            if (!methodOk(p, req)) continue;
            if (!p.uriSub.empty() && req.path.find(p.uriSub) == std::string::npos) continue;
            if (!headerCondsOk(p, req)) continue;
            return p;
        }
        return std::nullopt;
    }

    static bool methodOk(const CvePatch& p, const HttpRequest& req) {
        if (p.methods.empty()) return true;
        std::string m = req.method;
        for (auto& c : m) c = (char)toupper((unsigned char)c);
        for (auto& x : p.methods) if (x == m) return true;
        return false;
    }

    static bool headerCondsOk(const CvePatch& p, const HttpRequest& req) {
        for (auto& cond : p.headerConds) {
            bool ok = false;
            for (auto& kv : req.headers) {
                std::string lname = kv.first;
                for (auto& c : lname) c = (char)tolower((unsigned char)c);
                if (lname == cond.first &&
                    Decoder::normalize(kv.second).find(cond.second) != std::string::npos) {
                    ok = true;
                    break;
                }
            }
            if (!ok) return false;
        }
        return true;
    }

    AcAutomaton ac_;
    std::vector<CvePatch> patches_;  // 下标 == AC patternId
    uint8_t usedScopes_ = 0;         // 补丁并集用到的 scope（跳过无谓文本构建）
};

// 检测器包装：共享原子状态，pipeline clone 后仍共享同一热更新源（与 CustomRules 同构）
class CvePatchDetector : public IDetector {
public:
    CvePatchDetector()
        : set_(std::make_shared<std::atomic<std::shared_ptr<CvePatchSet>>>()) {
        set_->store(std::make_shared<CvePatchSet>(), std::memory_order_release);
    }

    const char* name() const override { return "CvePatch"; }

    std::unique_ptr<IDetector> clone() const override {
        return std::make_unique<CvePatchDetector>(*this);
    }

    // 热加载：解析新 JSON 构建新补丁集，原子替换。返回启用补丁数。
    size_t reload(const std::string& jsonBlob) {
        auto next = std::make_shared<CvePatchSet>();
        size_t n = next->loadFromJson(jsonBlob);
        set_->store(next, std::memory_order_release);
        return n;
    }

    size_t enabledCount() const {
        return set_->load(std::memory_order_acquire)->enabledCount();
    }

    DetectionResult detect(const HttpRequest& req) override {
        auto set = set_->load(std::memory_order_acquire);
        auto hit = set->match(req);
        if (hit) {
            return {hit->action,
                    hit->cve,                       // ruleId = CVE 编号
                    std::string("VirtualPatch"),    // 类别固定，便于按类统计应急防护量
                    hit->name.empty() ? hit->cve : hit->name,
                    hit->pattern};
        }
        return {};
    }

private:
    std::shared_ptr<std::atomic<std::shared_ptr<CvePatchSet>>> set_;
};

}  // namespace novawaf
