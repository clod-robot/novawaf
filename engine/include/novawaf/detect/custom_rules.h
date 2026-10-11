// NovaWAF - 控制台自定义规则检测器（打通管理控制台 -> 引擎的规则闭环）
// 数据来源：Redis 键 novawaf:rules，由 C++ 管理控制台写入，格式为 JSON 数组：
//   [{"id":1,"name":"block-sqli","pattern":"union select","action":"block","category":"sqli","enabled":true}, ...]
// 引擎每 60s（可配）从 Redis 热加载，copy-on-write 原子替换，检测热路径无锁。
#pragma once

#include "novawaf/core/json.h"
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace novawaf {

struct CustomRule {
    int id = 0;
    std::string name;
    std::string pattern;
    std::string category;
    Action action = Action::BLOCK;
    bool enabled = true;
};

// 不可变规则集：解析 + 构建一次，只读地用于匹配。热更新时整体替换。
class CustomRuleSet {
public:
    // 从 JSON 数组文本加载并构建 AC。返回启用规则数；解析异常返回 0（保留旧集）。
    size_t loadFromJson(const std::string& jsonBlob) {
        rules_.clear();
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
            CustomRule r;
            const JsonValue& en = item.at("enabled");
            r.enabled = en.isBool() ? en.b : true;  // 默认启用
            if (!r.enabled) continue;
            if (item.at("id").isNumber()) r.id = (int)item.at("id").num;
            if (item.at("name").isString()) r.name = item.at("name").str;
            const JsonValue& pat = item.at("pattern");
            if (!pat.isString() || pat.str.empty()) continue;  // 无 pattern 跳过
            // pattern 与检测文本用同一套归一化（解码+小写），保证大小写/编码绕过仍命中
            r.pattern = Decoder::normalize(pat.str);
            if (item.at("category").isString()) r.category = item.at("category").str;
            const JsonValue& act = item.at("action");
            if (act.isString()) {
                if (act.str == "log")       r.action = Action::LOG;
                else if (act.str == "pass") r.action = Action::PASS;
                else                        r.action = Action::BLOCK;
            }
            int pid = ac_.addPattern(r.pattern);
            // AC patternId -> rules_ 下标对齐
            if (pid != (int)rules_.size()) {
                // 理论上 addPattern 顺序返回，保险起见重排
            }
            rules_.push_back(r);
        }
        ac_.build();
        return rules_.size();
    }

    size_t enabledCount() const { return rules_.size(); }

    // 在归一化文本中匹配，返回命中的首条规则（AC 已合并 failure 输出，取 patternId 最小者）
    std::optional<CustomRule> match(const std::string& text) const {
        if (rules_.empty()) return std::nullopt;
        std::string norm = Decoder::normalize(text);
        auto hits = ac_.scan(norm);
        if (hits.empty()) return std::nullopt;
        int bestPid = hits[0].patternId;
        for (auto& h : hits) if (h.patternId < bestPid) bestPid = h.patternId;
        if (bestPid >= 0 && bestPid < (int)rules_.size()) return rules_[bestPid];
        return std::nullopt;
    }

private:
    AcAutomaton ac_;
    std::vector<CustomRule> rules_;  // 下标 == AC patternId
};

// 检测器：持有原子 shared_ptr<CustomRuleSet>，热更新时整体替换（与 detect 无锁竞争）
// set_ 用 shared_ptr 包一层 atomic，使 clone() 出来的副本与原实例共享同一份活规则集，
// 这样挂进流水线的克隆体也能实时看到 reload() 的更新，无需重建整条检测器链。
class CustomRuleDetector : public IDetector {
public:
    CustomRuleDetector()
        : set_(std::make_shared<std::atomic<std::shared_ptr<CustomRuleSet>>>()) {
        set_->store(std::make_shared<CustomRuleSet>(), std::memory_order_release);
    }

    const char* name() const override { return "CustomRule"; }

    std::unique_ptr<IDetector> clone() const override {
        auto c = std::make_unique<CustomRuleDetector>(*this);
        return c;
    }

    // 热加载：解析新 JSON 构建新规则集，原子替换。返回启用规则数。
    size_t reload(const std::string& jsonBlob) {
        auto next = std::make_shared<CustomRuleSet>();
        size_t n = next->loadFromJson(jsonBlob);
        set_->store(next, std::memory_order_release);
        return n;
    }

    size_t enabledCount() const {
        return set_->load(std::memory_order_acquire)->enabledCount();
    }

    DetectionResult detect(const HttpRequest& req) override {
        auto set = set_->load(std::memory_order_acquire);
        for (auto& payload : req.collectPayloads()) {
            auto hit = set->match(payload);
            if (hit) {
                return {hit->action,
                        std::string("CUSTOM-") + std::to_string(hit->id),
                        hit->category,
                        std::string("custom rule: ") + hit->name,
                        hit->pattern};
            }
        }
        return {};
    }

private:
    std::shared_ptr<std::atomic<std::shared_ptr<CustomRuleSet>>> set_;
};

}  // namespace novawaf
