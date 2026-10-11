// NovaWAF - AI 语义检测器（二阶复核）
// 角色：作为 IDetector 接入流水线，调用大模型对请求做语义级攻击判定。
// 安全模型：
//   - 默认仅对【规则引擎已标记可疑】的流量做复核（降误报 + 识别 0day/变种），
//     不在每个正常请求上浪费 AI 调用（省成本、保吞吐）。
//   - AI 不可用/超时 → 立即降级：保持规则引擎的判定结果（fail-closed 偏安全），
//     绝不因 AI 故障放行攻击。
#pragma once

#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_cache.h"
#include "novawaf/core/thread_pool.h"
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

    // 注入缓存与异步执行器（异步化所需）。两者皆有时走非阻塞路径。
    void setCache(std::shared_ptr<AiCache> c) { cache_ = std::move(c); }
    void setExecutor(std::shared_ptr<ThreadPool> e) { exec_ = std::move(e); }
    bool asyncReady() const { return cache_ && exec_ && isActive(); }

    std::unique_ptr<IDetector> clone() const override {
        // 共享同一个 LLM client / 缓存 / 执行器（线程安全）
        auto d = std::make_unique<AiDetector>(llm_);
        d->setCache(cache_);
        d->setExecutor(exec_);
        return d;
    }

    DetectionResult detect(const HttpRequest& req) override {
        auto r = analyze(req);
        return r ? *r : DetectionResult{};  // IDetector 接口：无结论=放行
    }

    // 同步分析：真实调用大模型（阻塞）。返回 nullopt = AI 不可用/失败。
    std::optional<DetectionResult> analyze(const HttpRequest& req) {
        if (!llm_ || !llm_->config().enabled) return std::nullopt;

        std::string user = buildUserPrompt(req);
        auto ans = llm_->chat(kSystemPrompt, user);
        if (!ans) return std::nullopt;  // 调用失败 → 交由规则引擎兜底

        return verdictToResult(parseVerdict(*ans));
    }

    // 非阻塞分析（缓存 + 异步）：
    //   - 缓存命中 → 立即返回缓存结论（无 AI 调用）；
    //   - 未命中 → 立即返回 nullopt，并异步提交 AI 任务填充缓存（本次响应不等待）；
    //   - 调用方据此：未命中时维持规则结果，后续相同 payload 即可秒级命中缓存。
    std::optional<DetectionResult> analyzeNonBlocking(const HttpRequest& req) {
        if (!isActive()) return std::nullopt;
        std::string key = AiCache::makeKey(req);
        if (cache_) {
            auto hit = cache_->get(key);
            if (hit) { cacheHits_++; return hit; }   // 命中秒回
        }
        cacheMisses_++;
        if (exec_ && cache_) {
            // 后台异步：调用 AI → 写缓存。捕获 req 副本，闭包安全。
            HttpRequest copy = req;
            std::weak_ptr<LlmClient> wllm = llm_;
            auto wcache = cache_;
            std::string k = key;
            exec_->submit([wllm, wcache, k, copy, sys = std::string(kSystemPrompt)]() {
                auto llm = wllm.lock();
                if (!llm) return;
                std::string user = AiDetector::buildUserPrompt(copy);
                auto ans = llm->chat(sys, user);
                if (!ans) return;
                wcache->put(k, AiDetector::verdictToResult(AiDetector::parseVerdict(*ans)));
            });
        }
        return std::nullopt;  // 未命中 → 本次按规则结果响应（不阻塞）
    }

    size_t cacheHits() const { return cacheHits_.load(); }
    size_t cacheMisses() const { return cacheMisses_.load(); }

private:
    struct Verdict {
        bool block = false;
        std::string category = "AI";
        std::string reason;
        std::string raw;
    };

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

    static DetectionResult verdictToResult(const Verdict& v) {
        if (v.block) {
            return {Action::BLOCK, "AI-001", v.category,
                    "AI semantic detection: " + v.reason, v.raw};
        }
        return {Action::PASS, "AI-REVIEW", v.category,
                "AI verified benign: " + v.reason, v.raw};
    }

    static constexpr const char* kSystemPrompt =
        "You are a Web Application Firewall security analyzer. Analyze the HTTP request "
        "for injection, XSS, RCE, path traversal, SSRF, deserialization, and other web "
        "attacks, including obfuscated/encoded/variant payloads that simple rules may miss. "
        "Respond ONLY with compact JSON: {\"block\":true|false,\"category\":\"...\","
        "\"confidence\":0.0,\"reason\":\"short\"}. block=true only for actual attacks.";

    std::shared_ptr<LlmClient> llm_;
    std::shared_ptr<AiCache> cache_;
    std::shared_ptr<ThreadPool> exec_;
    std::atomic<size_t> cacheHits_{0};
    std::atomic<size_t> cacheMisses_{0};
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

    // 异步路径（缓存 + 后台线程池）：响应绝不阻塞。
    // 命中缓存 → 秒回 AI 结论；未命中 → 立即按规则响应，后台异步填缓存。
    if (ai->asyncReady()) {
        auto ar = ai->analyzeNonBlocking(req);
        if (ar) {
            // 有缓存结论：AI 判攻击则拦截；AI 判良性且规则已拦则视为误报放行
            if (ar->action == Action::BLOCK) return *ar;
            if (r.action == Action::BLOCK) return *ar;
        }
        // 未命中(或 AI 判良性且规则放行) → 维持规则结果，本次不等待 AI
        return r;
    }

    // 同步降级路径（未配置缓存/线程池时）：阻塞调用 AI，仅用于小流量或测试。
    if (r.action == Action::BLOCK) {
        auto ar = ai->analyze(req);
        if (!ar) return r;                  // AI 失败 → 维持拦截（fail-closed）
        if (ar->action == Action::PASS) return *ar;  // AI 判定误报 → 放行
        return r;                            // AI 也认为攻击 → 维持拦截
    }
    if (augment && isSuspicious(req)) {
        auto ar = ai->analyze(req);
        if (ar && ar->action == Action::BLOCK) return *ar;
    }
    return r;
}

}  // namespace novawaf
