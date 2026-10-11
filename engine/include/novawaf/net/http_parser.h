// NovaWAF - 简易 HTTP 请求解析器（从零实现，无第三方依赖，平台无关）
// 解析 request line + headers，支持 query string 拆分。
#pragma once

#include "novawaf/detect/http_model.h"

#include <string>
#include <string_view>

namespace novawaf {

class HttpParser {
public:
    enum class State { REQUEST_LINE, HEADERS, BODY, DONE, ERROR };

    HttpParser() = default;

    // 持续喂数据，返回当前状态
    State feed(const char* data, size_t len) {
        buf_.append(data, len);
        return parse();
    }

    State feed(std::string_view sv) { return feed(sv.data(), sv.size()); }

    bool done() const { return state_ == State::DONE; }
    bool hasError() const { return state_ == State::ERROR; }

    HttpRequest request() const { return req_; }

    // 重置以解析下一个请求（keep-alive 复用）
    void reset() {
        buf_.clear();
        req_ = HttpRequest{};
        state_ = State::REQUEST_LINE;
        bodyLeft_ = 0;
    }

private:
    State parse() {
        while (state_ != State::DONE && state_ != State::ERROR) {
            switch (state_) {
                case State::REQUEST_LINE: {
                    size_t eol = buf_.find("\r\n");
                    if (eol == std::string::npos) return state_;
                    if (!parseRequestLine(buf_.substr(0, eol))) {
                        state_ = State::ERROR;
                        return state_;
                    }
                    buf_.erase(0, eol + 2);
                    state_ = State::HEADERS;
                    break;
                }
                case State::HEADERS: {
                    size_t eol = buf_.find("\r\n");
                    if (eol == std::string::npos) return state_;
                    if (eol == 0) {  // 空行，headers 结束
                        buf_.erase(0, 2);
                        auto it = req_.headers.find("Content-Length");
                        if (it != req_.headers.end()) {
                            bodyLeft_ = std::stoul(it->second);
                            state_ = (bodyLeft_ > 0) ? State::BODY : State::DONE;
                        } else {
                            state_ = State::DONE;
                        }
                    } else {
                        parseHeader(buf_.substr(0, eol));
                        buf_.erase(0, eol + 2);
                    }
                    break;
                }
                case State::BODY: {
                    if (buf_.size() < bodyLeft_) return state_;
                    req_.body = buf_.substr(0, bodyLeft_);
                    buf_.erase(0, bodyLeft_);
                    state_ = State::DONE;
                    break;
                }
                default:
                    return state_;
            }
        }
        return state_;
    }

    bool parseRequestLine(const std::string& line) {
        size_t sp1 = line.find(' ');
        if (sp1 == std::string::npos) return false;
        size_t sp2 = line.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) return false;
        req_.method = line.substr(0, sp1);
        std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        req_.version = line.substr(sp2 + 1);
        // 拆分 path 和 query
        size_t q = target.find('?');
        if (q != std::string::npos) {
            req_.path = target.substr(0, q);
            req_.query = target.substr(q + 1);
            parseQuery(req_.query);
        } else {
            req_.path = target;
        }
        return true;
    }

    void parseHeader(const std::string& line) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) return;
        std::string key = trim(line.substr(0, colon));
        std::string val = trim(line.substr(colon + 1));
        req_.headers[key] = val;
    }

    void parseQuery(const std::string& q) {
        size_t start = 0;
        while (start < q.size()) {
            size_t amp = q.find('&', start);
            std::string kv = q.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
            size_t eq = kv.find('=');
            if (eq != std::string::npos)
                req_.queryParams.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
            else
                req_.queryParams.emplace_back(kv, "");
            if (amp == std::string::npos) break;
            start = amp + 1;
        }
    }

    static std::string trim(const std::string& s) {
        size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return "";
        size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    }

    std::string buf_;
    HttpRequest req_;
    State state_ = State::REQUEST_LINE;
    size_t bodyLeft_ = 0;
};

}  // namespace novawaf
