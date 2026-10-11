// NovaWAF - LLM 大模型客户端（OpenAI 兼容 Chat Completions 接口）
// 设计目标：
//   1) 可指向本地模型(vLLM/llama.cpp/TGI 的 OpenAI 兼容接口) 或 外部 API；
//   2) 严格超时 + 指数退避重试，绝不阻塞引擎热路径；
//   3) 传输层可注入（便于单测，不依赖真实网络）；
//   4) 任何失败均返回空 optional，由上层降级到规则引擎。
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace novawaf {

struct LlmConfig {
    bool enabled = false;               // 总开关：false 时直接降级，不发起任何调用
    std::string endpoint;               // 如 http://127.0.0.1:8000/v1/chat/completions
    std::string apiKey;                 // 外部 API 必填；本地可留空
    std::string model = "gpt-4o-mini";  // 模型名
    int timeoutMs = 1500;               // 单次调用超时（ms）——必须短，避免拖垮热路径
    int maxRetries = 1;                 // 失败重试次数（指数退避）
    double temperature = 0.0;           // 安全判定需确定性，用 0
    int maxTokens = 256;                // 只取判定结论，省 token
};

// 传输层接口：输入完整 HTTP 请求体(JSON)，返回 HTTP 响应体；失败返回空。
// 生产用 LlmHttpClient，测试可注入 fake。
using LlmTransport = std::function<std::optional<std::string>(const std::string&)>;

// 极简 JSON 转义（prompt 里可能含用户输入，必须转义防注入/格式破坏）
inline std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

class LlmClient {
public:
    LlmClient(LlmConfig cfg, LlmTransport transport = nullptr)
        : cfg_(std::move(cfg)), transport_(std::move(transport)) {}

    // 发送一轮对话，返回模型文本内容；任何异常/超时返回空。
    std::optional<std::string> chat(const std::string& systemPrompt,
                                    const std::string& userPrompt) {
        if (!cfg_.enabled || !transport_) return std::nullopt;

        std::string body = buildRequestBody(systemPrompt, userPrompt);
        for (int attempt = 0; attempt <= cfg_.maxRetries; ++attempt) {
            if (attempt > 0) {
                // 指数退避：100ms, 200ms...（但总预算必须受控）
                int backoff = 100 * (1 << (attempt - 1));
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
            }
            auto resp = transport_(body);
            if (resp) {
                auto content = extractContent(*resp);
                if (content) return content;
            }
            // 失败继续重试
        }
        return std::nullopt;  // 全部失败 → 上层降级
    }

    const LlmConfig& config() const { return cfg_; }

private:
    // 构建 OpenAI 兼容的 chat/completions 请求体
    std::string buildRequestBody(const std::string& sys, const std::string& user) const {
        std::string b = "{";
        b += "\"model\":\"" + jsonEscape(cfg_.model) + "\",";
        b += "\"temperature\":" + std::to_string(cfg_.temperature) + ",";
        b += "\"max_tokens\":" + std::to_string(cfg_.maxTokens) + ",";
        b += "\"messages\":[";
        b += "{\"role\":\"system\",\"content\":\"" + jsonEscape(sys) + "\"},";
        b += "{\"role\":\"user\",\"content\":\"" + jsonEscape(user) + "\"}";
        b += "]}";
        return b;
    }

    // 从响应 JSON 中提取 choices[0].message.content（手写极简解析，零依赖）
    static std::optional<std::string> extractContent(const std::string& json) {
        // 找 "content":" ... "
        const std::string key = "\"content\":\"";
        auto p = json.find(key);
        if (p == std::string::npos) return std::nullopt;
        p += key.size();
        std::string out;
        while (p < json.size()) {
            char c = json[p++];
            if (c == '\\' && p < json.size()) {
                char e = json[p++];
                switch (e) {
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    default: out += e; break;
                }
            } else if (c == '"') {
                return out;  // 结束
            } else {
                out += c;
            }
        }
        return std::nullopt;
    }

    LlmConfig cfg_;
    LlmTransport transport_;
};

}  // namespace novawaf
