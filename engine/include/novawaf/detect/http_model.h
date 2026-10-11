// NovaWAF - HTTP 请求数据模型（检测引擎的输入）
#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace novawaf {

struct HttpRequest {
    std::string method;
    std::string path;           // 原始 path（含 query）
    std::string query;
    std::string version;
    std::string body;
    std::string clientIp;
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::pair<std::string, std::string>> queryParams;  // 解析后的 k/v

    // 提取所有需要检测的 payload 字段（归一化后的检测点）
    std::vector<std::string> collectPayloads() const {
        std::vector<std::string> payloads;
        payloads.push_back(path);
        payloads.push_back(query);
        payloads.push_back(body);
        for (auto& [k, v] : headers) {
            if (k != "Host" && k != "User-Agent") payloads.push_back(v);
            else payloads.push_back(v);  // UA 也要检测爬虫
        }
        for (auto& [k, v] : queryParams) {
            payloads.push_back(k);
            payloads.push_back(v);
        }
        return payloads;
    }
};

enum class Action {
    PASS,       // 放行
    BLOCK,      // 拦截
    LOG,        // 仅记录
    CHALLENGE   // 人机验证
};

struct DetectionResult {
    Action action = Action::PASS;
    std::string ruleId;
    std::string category;   // SQLi/XSS/RCE/...
    std::string description;
    std::string matched;    // 命中的片段

    bool isBlocked() const { return action == Action::BLOCK; }
};

}  // namespace novawaf
