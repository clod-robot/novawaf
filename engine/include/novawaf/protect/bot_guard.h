// NovaWAF - Bot / 自动化行为防护
// 思路：不靠单一 UA 特征（易伪造），而是对"浏览器完整性 + 行为节奏"多维度打分。
// 设计：策略模式（IBotStrategy 可插拔评分器），分数累计，阈值分级处置。
// 评分维度（命中加分）：
//   - 缺失标准浏览器头（Accept/Accept-Language/Accept-Encoding）
//   - UA 与头集合不匹配（声明 Chrome 却无 sec-ch-ua 等）
//   - 无 Referer 且无 Cookie 的高频首访
//   - JA4 指纹与 UA 声明的浏览器族不一致（高级，需指纹）
//   - 请求间隔过于规律（机器人固定间隔）—— 由动态防护侧补充，此处给出接口
#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <vector>

#include "novawaf/detect/http_model.h"

namespace novawaf {

// 单条评分策略接口（策略模式）
struct IBotStrategy {
    virtual ~IBotStrategy() = default;
    // 返回该策略给请求打的分（>=0），并可填充 reason
    virtual int score(const HttpRequest& req, const std::string& ja4,
                      std::string& reason) const = 0;
};

// 缺失标准浏览器头
class MissingBrowserHeaders : public IBotStrategy {
public:
    int score(const HttpRequest& req, const std::string&, std::string& reason) const override {
        int s = 0;
        auto has = [&](const char* k) { return headerExists(req, k); };
        if (!has("accept")) { s += 15; reason = "no-accept"; }
        if (!has("accept-language")) { s += 10; if (reason.empty()) reason = "no-accept-language"; }
        if (!has("accept-encoding")) { s += 8; if (reason.empty()) reason = "no-accept-encoding"; }
        if (!has("user-agent")) { s += 25; reason = "no-ua"; }
        return s;
    }
private:
    static bool headerExists(const HttpRequest& req, const char* key) {
        for (auto& [k, v] : req.headers) {
            std::string lk = k;
            for (auto& c : lk) c = (char)std::tolower((unsigned char)c);
            if (lk == key) return true;
        }
        return false;
    }
};

// UA 声明了现代浏览器，但缺少对应的客户端提示头
class UaMismatchHeaders : public IBotStrategy {
public:
    int score(const HttpRequest& req, const std::string&, std::string& reason) const override {
        std::string ua = getHeader(req, "user-agent");
        for (auto& c : ua) c = (char)std::tolower((unsigned char)c);
        bool modern = ua.find("chrome/") != std::string::npos ||
                      ua.find("firefox/") != std::string::npos ||
                      ua.find("safari/") != std::string::npos;
        if (!modern) return 0;
        int s = 0;
        // 现代浏览器通常带 sec-fetch-* 或 sec-ch-ua
        if (!headerHasPrefix(req, "sec-fetch") && !headerExists(req, "sec-ch-ua")) {
            s += 20; reason = "modern-ua-without-client-hints";
        }
        return s;
    }
private:
    static std::string getHeader(const HttpRequest& req, const char* key) {
        for (auto& [k, v] : req.headers) {
            std::string lk = k; for (auto& c : lk) c = (char)std::tolower((unsigned char)c);
            if (lk == key) return v;
        }
        return {};
    }
    static bool headerExists(const HttpRequest& req, const char* key) {
        return !getHeader(req, key).empty();
    }
    static bool headerHasPrefix(const HttpRequest& req, const std::string& pfx) {
        for (auto& [k, v] : req.headers) {
            std::string lk = k; for (auto& c : lk) c = (char)std::tolower((unsigned char)c);
            if (lk.compare(0, pfx.size(), pfx) == 0) return true;
        }
        return false;
    }
};

// Bot 防护：聚合所有策略评分
class BotGuard {
public:
    struct Config {
        int scoreToChallenge = 30;
        int scoreToBlock = 60;
    };
    explicit BotGuard(const Config& cfg) : cfg_(cfg) {
        strategies_.push_back(std::make_unique<MissingBrowserHeaders>());
        strategies_.push_back(std::make_unique<UaMismatchHeaders>());
    }
    // 允许注入自定义策略（开放扩展点）
    void addStrategy(std::unique_ptr<IBotStrategy> s) { strategies_.push_back(std::move(s)); }

    DetectionResult assess(const HttpRequest& req, const std::string& ja4 = "") {
        int total = 0;
        std::string reason;
        for (auto& s : strategies_) {
            std::string r;
            int v = s->score(req, ja4, r);
            if (v > 0) { total += v; if (reason.empty()) reason = r; }
        }
        Action a = Action::PASS;
        if (total >= cfg_.scoreToBlock) a = Action::BLOCK;
        else if (total >= cfg_.scoreToChallenge) a = Action::CHALLENGE;
        return {a, "BOT-001", "Bot", "Automated / non-browser behavior", reason};
    }

private:
    Config cfg_;
    std::vector<std::unique_ptr<IBotStrategy>> strategies_;
};

}  // namespace novawaf
