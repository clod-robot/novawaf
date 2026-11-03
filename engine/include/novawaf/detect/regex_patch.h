// NovaWAF - 正则虚拟补丁检测器（复杂 CVE 指纹的应急热防护）
// 与 CvePatchDetector（AC 字面量多模）互补：当漏洞特征无法用单一字面量表达时
// （如多变体混淆、结构化边界），用正则补丁覆盖。同一 JSON 模板、同一 COW 热更通道。
// 数据来源：Redis STRING novawaf:regex_patch（JSON 数组），版本键 novawaf:regex_patch:version
//   字段与 cve_patch 完全一致，唯一区别：match 为正则表达式（ECMAScript 语法，icase）。
// 性能护栏（正则比字面量贵且存在 ReDoS 风险，管理端同样校验）：
//   - 补丁数上限 100，单条 pattern ≤ 256 字符
//   - 拒绝嵌套量词形态 (x+)+ / (x*)* / (x+)* 等典型 ReDoS 结构
//   - body 仅扫前 16KB；编译失败的补丁跳过不影响其它
//   - 与 CvePatch 同构：copy-on-write 原子替换，检测热路径无锁
#pragma once

#include "novawaf/core/json.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <atomic>
#include <cctype>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace novawaf {

// 与 CvePatch 字段同构；pattern 存正则原文（不做归一化，避免破坏字符类/转义）
struct RegexPatch {
    std::string cve;
    std::string name;
    std::string severity = "high";
    Action action = Action::BLOCK;
    std::vector<std::string> methods;                               // 大写；空=全部
    std::string uriSub;                                             // path 子串（原始大小写）
    uint8_t scopes = 15;                                            // S_ALL
    std::vector<std::pair<std::string, std::string>> headerConds;   // 头名(小写)->归一化子串
    std::string pattern;                                            // 正则原文
    std::regex re;                                                  // 编译产物（icase）
};

class RegexPatchSet {
public:
    static constexpr size_t MAX_PATCHES = 100;
    static constexpr size_t MAX_PATTERN = 256;
    static constexpr size_t MAX_BODY_SCAN = 16384;

    // 典型 ReDoS 形态：组内含量词且组外再叠量词，如 (a+)+ (\w*)+
    static bool nestedQuantifier(const std::string& p) {
        bool inClass = false;
        for (size_t i = 0; i < p.size(); ++i) {
            char c = p[i];
            if (c == '\\') { ++i; continue; }
            if (c == '[') inClass = true;
            else if (c == ']') inClass = false;
            else if (c == '(' && !inClass) {
                bool innerQ = false;
                for (size_t j = i + 1; j < p.size() && p[j] != ')'; ++j) {
                    if (p[j] == '\\') { ++j; continue; }
                    if (p[j] == '(') break;          // 嵌套组不判，交给编译器/执行护栏
                    if (p[j] == '+' || p[j] == '*' || p[j] == '{') innerQ = true;
                }
                if (innerQ) {
                    size_t k = p.find(')', i);
                    if (k != std::string::npos && k + 1 < p.size() &&
                        (p[k + 1] == '+' || p[k + 1] == '*' || p[k + 1] == '{'))
                        return true;
                }
            }
        }
        return false;
    }

    size_t loadFromJson(const std::string& jsonBlob) {
        patches_.clear();
        usedScopes_ = 0;
        if (jsonBlob.empty()) return 0;
        JsonValue root;
        try {
            root = parseJson(jsonBlob);
        } catch (...) {
            return 0;  // 解析失败：空集，不影响其它检测器
        }
        if (!root.isArray()) return 0;
        for (auto& item : root.arr) {
            if (patches_.size() >= MAX_PATCHES) break;
            if (!item.isObject()) continue;
            RegexPatch p;
            const JsonValue& en = item.at("enabled");
            if (en.isBool() && !en.b) continue;
            const JsonValue& cve = item.at("cve");
            if (!cve.isString() || cve.str.empty()) continue;
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
                    if (s.str == "uri") p.scopes |= 1;
                    else if (s.str == "args") p.scopes |= 2;
                    else if (s.str == "headers") p.scopes |= 4;
                    else if (s.str == "body") p.scopes |= 8;
                }
                if (p.scopes == 0) p.scopes = 15;
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
            if (!m.isString() || m.str.empty() || m.str.size() > MAX_PATTERN) continue;
            if (nestedQuantifier(m.str)) continue;  // ReDoS 护栏
            p.pattern = m.str;
            try {
                p.re = std::regex(p.pattern,
                                  std::regex_constants::ECMAScript |
                                  std::regex_constants::icase |
                                  std::regex_constants::optimize);
            } catch (const std::regex_error&) {
                continue;  // 编译失败跳过该条
            }
            usedScopes_ |= p.scopes;
            patches_.push_back(std::move(p));
        }
        return patches_.size();
    }

    size_t enabledCount() const { return patches_.size(); }

    // 按 scope 顺序 uri->args->headers->body 扫描，返回首条全条件命中的补丁
    std::optional<RegexPatch> match(const HttpRequest& req) const {
        if (patches_.empty()) return std::nullopt;
        if (usedScopes_ & 1)
            if (auto hit = scanScope(1, Decoder::normalize(req.path), req)) return hit;
        if (usedScopes_ & 2) {
            std::string args = req.query;
            for (auto& kv : req.queryParams) {
                args += '\n'; args += kv.first; args += '='; args += kv.second;
            }
            if (auto hit = scanScope(2, Decoder::normalize(args), req)) return hit;
        }
        if (usedScopes_ & 4) {
            std::string hv;
            for (auto& kv : req.headers) { hv += kv.second; hv += '\n'; }
            if (auto hit = scanScope(4, Decoder::normalize(hv), req)) return hit;
        }
        if ((usedScopes_ & 8) && !req.body.empty()) {
            std::string body = Decoder::normalize(req.body);
            if (body.size() > MAX_BODY_SCAN) body.resize(MAX_BODY_SCAN);
            if (auto hit = scanScope(8, body, req)) return hit;
        }
        return std::nullopt;
    }

private:
    std::optional<RegexPatch> scanScope(uint8_t bit, const std::string& normText,
                                        const HttpRequest& req) const {
        if (normText.empty()) return std::nullopt;
        for (auto& p : patches_) {
            if (!(p.scopes & bit)) continue;
            if (!methodOk(p, req)) continue;
            if (!p.uriSub.empty() && req.path.find(p.uriSub) == std::string::npos) continue;
            if (!headerCondsOk(p, req)) continue;
            try {
                if (std::regex_search(normText, p.re)) return p;
            } catch (...) {
                // 极端输入导致运行时异常（如栈溢出）时跳过该条，不影响请求
                continue;
            }
        }
        return std::nullopt;
    }

    static bool methodOk(const RegexPatch& p, const HttpRequest& req) {
        if (p.methods.empty()) return true;
        std::string m = req.method;
        for (auto& c : m) c = (char)toupper((unsigned char)c);
        for (auto& x : p.methods) if (x == m) return true;
        return false;
    }

    static bool headerCondsOk(const RegexPatch& p, const HttpRequest& req) {
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

    std::vector<RegexPatch> patches_;
    uint8_t usedScopes_ = 0;
};

// 检测器包装：共享原子状态，pipeline clone 后仍共享同一热更新源（与 CvePatch 同构）
class RegexPatchDetector : public IDetector {
public:
    RegexPatchDetector()
        : set_(std::make_shared<std::atomic<std::shared_ptr<RegexPatchSet>>>()) {
        set_->store(std::make_shared<RegexPatchSet>(), std::memory_order_release);
    }

    const char* name() const override { return "RegexPatch"; }

    std::unique_ptr<IDetector> clone() const override {
        return std::make_unique<RegexPatchDetector>(*this);
    }

    // 热加载：解析新 JSON 构建新补丁集，原子替换。返回启用补丁数。
    size_t reload(const std::string& jsonBlob) {
        auto next = std::make_shared<RegexPatchSet>();
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
                    hit->cve,
                    std::string("VirtualPatchRegex"),  // 与字面量补丁区分统计
                    hit->name.empty() ? hit->cve : hit->name,
                    hit->pattern};
        }
        return {};
    }

private:
    std::shared_ptr<std::atomic<std::shared_ptr<RegexPatchSet>>> set_;
};

}  // namespace novawaf
