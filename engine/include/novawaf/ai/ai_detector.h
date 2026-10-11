// NovaWAF - AI 语义检测器（二阶复核）
// 角色：作为 IDetector 接入流水线，调用大模型对请求做语义级攻击判定。
// 安全模型：
//   - 默认仅对【规则引擎已标记可疑】的流量做复核（降误报 + 识别 0day/变种），
//     不在每个正常请求上浪费 AI 调用（省成本、保吞吐）。
//   - AI 不可用/超时 → 立即降级：保持规则引擎的判定结果（fail-closed 偏安全），
//     绝不因 AI 故障放行攻击。
#pragma once

#include "novawaf/ai/llm_client.h"
#include "novawaf/detect/detectors.h"

#include <memory>
#include <string>

namespace novawaf {

class AiDetector : public IDetector {
public:
    explicit AiDetector(std::shared_ptr<LlmClient> llm) : llm_(std::move(llm)) {}

    const char* name() const override { return "AI"; }

    // AI 是否真正可用（启用且有 client）。不可用时复核应维持规则结果（fail-closed）。
    bool isActive() const { return llm_ && llm_->config().enabled; }

    std::unique_ptr<IDetector> clone() const override {
        // 共享同一个 LLM client（线程安全：只读配置 + 无状态调用）
        return std::make_unique<AiDetector>(llm_);
    }

    DetectionResult detect(const HttpRequest& req) override {
        auto r = analyze(req);
        return r ? *r : DetectionResult{};  // IDetector 接口：无结论=放行
    }

    // 二阶复核专用：返回 nullopt 表示 AI 不可用/调用失败，调用方应维持规则结果（fail-closed）。
    std::optional<DetectionResult> analyze(const HttpRequest& req) {
        if (!llm_ || !llm_->config().enabled) return std::nullopt;

        std::string user = buildUserPrompt(req);
        auto ans = llm_->chat(kSystemPrompt, user);
        if (!ans) return std::nullopt;  // 调用失败 → 交由规则引擎兜底

        Verdict v = parseVerdict(*ans);
        if (v.block) {
            return DetectionResult{Action::BLOCK, "AI-001", v.category,
                    "AI semantic detection: " + v.reason, v.raw};
        }
        // AI 明确判定非攻击 → 返回放行结论（可用于覆盖规则误报）
        return DetectionResult{Action::PASS, "AI-REVIEW", v.category,
                "AI verified benign: " + v.reason, v.raw};
    }

private:
    struct Verdict {
        bool block = false;
        std::string category = "AI";
        std::string reason;
        std::string raw;
    };

    // 解析模型返回的 JSON：{"block":true,"category":"SQLi","confidence":0.97,"reason":"..."}
    static Verdict parseVerdict(const std::string& s) {
        Verdict v;
        v.raw = s;
        // block 字段
        auto p = s.find("\"block\"");
        if (p != std::string::npos) {
            auto colon = s.find(':', p);
            if (colon != std::string::npos) {
                auto t = s.find("true", colon);
                auto f = s.find("false", colon);
                v.block = (t != std::string::npos && (f == std::string::npos || t < f));
            }
        }
        v.category = extractStringField(s, "category");
        if (v.category.empty()) v.category = "AI";
        v.reason = extractStringField(s, "reason");
        return v;
    }

    static std::string extractStringField(const std::string& s, const std::string& key) {
        std::string pat = "\"" + key + "\"";
        auto p = s.find(pat);
        if (p == std::string::npos) return "";
        auto colon = s.find(':', p);
        if (colon == std::string::npos) return "";
        auto q = s.find('"', colon);
        if (q == std::string::npos) return "";
        std::string out;
        size_t i = q + 1;
        while (i < s.size()) {
            char c = s[i++];
            if (c == '\\' && i < s.size()) { out += s[i++]; }
            else if (c == '"') break;
            else out += c;
        }
        return out;
    }

    static std::string buildUserPrompt(const HttpRequest& req) {
        std::string u = "METHOD=" + req.method + " PATH=" + req.path + "\n";
        u += "QUERY=" + req.query + "\n";
        u += "BODY=" + req.body + "\n";
        u += "HEADERS:\n";
        for (auto& kv : req.headers) u += "  " + kv.first + ": " + kv.second + "\n";
        return u;
    }

    static constexpr const char* kSystemPrompt =
        "You are a Web Application Firewall security analyzer. Analyze the HTTP request "
        "for injection, XSS, RCE, path traversal, SSRF, deserialization, and other web "
        "attacks, including obfuscated/encoded/variant payloads that simple rules may miss. "
        "Respond ONLY with compact JSON: {\"block\":true|false,\"category\":\"...\","
        "\"confidence\":0.0,\"reason\":\"short\"}. block=true only for actual attacks.";

    std::shared_ptr<LlmClient> llm_;
};

// 二阶复核编排：规则引擎判定 + AI 语义复核（降误报 + 抓变种/0day）。
// 策略：
//   - 规则已拦截 → AI 复核：确认攻击则维持拦截，判定误报则放行；
//   - 规则放行但【可疑】→ 增强模式下追加 AI 检测，捕捉规则漏判的攻击；
//   - AI 不可用/超时/失败 → 一律维持规则结果（fail-closed，绝不因 AI 故障放行攻击）。
// 仅对可疑/已拦截的小流量调用 AI，正常流量零 AI 开销，保证吞吐。
inline bool isSuspicious(const HttpRequest& req) {
    // 字符级低成本预筛：含攻击常见特征即视为可疑（宁可多送 AI 复核，不漏）
    auto scan = [](const std::string& s) {
        for (char c : s) {
            switch (c) {
                case '\'': case '"': case '<': case '>': case '`':
                case ';': case '|': case '&': case '\\': case '%':
                    return true;
                default: break;
            }
        }
        return s.find("../") != std::string::npos ||
               s.find("..\\") != std::string::npos;
    };
    if (scan(req.path) || scan(req.query) || scan(req.body)) return true;
    for (auto& kv : req.headers) if (scan(kv.second)) return true;
    for (auto& kv : req.queryParams) if (scan(kv.second)) return true;
    return false;
}

inline DetectionResult detectWithAiReview(DetectionPipeline& pipeline,
                                          const std::shared_ptr<AiDetector>& ai,
                                          const HttpRequest& req, bool augment = true) {
    DetectionResult r = pipeline.detect(req);

    if (!ai || !ai->isActive()) return r;  // AI 不可用 → 纯规则结果

    if (r.action == Action::BLOCK) {
        // 规则已拦 → AI 复核降误报
        auto ar = ai->analyze(req);
        if (!ar) return r;                  // AI 失败 → 维持拦截（fail-closed）
        if (ar->action == Action::PASS) return *ar;  // AI 判定误报 → 放行
        return r;                            // AI 也认为攻击 → 维持拦截
    }

    // 规则放行 → 增强模式下，对可疑流量追加 AI 检测（抓变种/0day）
    if (augment && isSuspicious(req)) {
        auto ar = ai->analyze(req);
        if (ar && ar->action == Action::BLOCK) return *ar;  // AI 抓到规则漏判的攻击
    }
    return r;
}

}  // namespace novawaf
