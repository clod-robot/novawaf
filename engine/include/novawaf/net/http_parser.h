// NovaWAF - 简易 HTTP 请求解析器（从零实现，无第三方依赖，平台无关）
// 解析 request line + headers，支持 query string 拆分。
// body 帧格式：Content-Length 定长 或 Transfer-Encoding: chunked（TE 优先，RFC 9112 §6.3）。
#pragma once

#include "novawaf/detect/http_model.h"

#include <cctype>
#include <string>
#include <string_view>

namespace novawaf {

class HttpParser {
public:
    enum class State { REQUEST_LINE, HEADERS, BODY, CHUNK_SIZE, CHUNK_DATA, CHUNK_TRAILER, DONE, ERROR };

    HttpParser() = default;

    // 持续喂数据，返回当前状态
    State feed(const char* data, size_t len) {
        buf_.append(data, len);
        return parse();
    }

    State feed(std::string_view sv) { return feed(sv.data(), sv.size()); }

    bool done() const { return state_ == State::DONE; }
    bool hasError() const { return state_ == State::ERROR; }
    // body 超 setMaxBody 上限导致的 ERROR（用于上层回 413 而非直接断连）
    bool bodyTooLarge() const { return bodyTooLarge_; }

    HttpRequest request() const { return req_; }

    // body 解码上限（默认 8MB；TLS 桥接路径按 NOVA_MAX_BODY 收紧）
    void setMaxBody(size_t n) { maxBody_ = n; }

    // DONE 状态下 buf_ 内剩余为流水线下一请求的字节：reset 前取出保留（TLS h1 流水线用）
    void stealLeftover(std::string& out) { out = std::move(buf_); buf_.clear(); }

    // 重置以解析下一个请求（keep-alive 复用）
    void reset() {
        buf_.clear();
        req_ = HttpRequest{};
        state_ = State::REQUEST_LINE;
        bodyLeft_ = 0;
        chunkLeft_ = 0;
        decodedBody_ = 0;
        bodyTooLarge_ = false;
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
                        const std::string* te = hdrCi("transfer-encoding");
                        bool chunked = false;
                        if (te) {
                            std::string lv;
                            lv.reserve(te->size());
                            for (char c : *te) lv += (char)std::tolower((unsigned char)c);
                            chunked = lv.find("chunked") != std::string::npos;
                        }
                        if (chunked) {  // TE 优先于 CL
                            state_ = State::CHUNK_SIZE;
                            break;
                        }
                        if (const std::string* cl = hdrCi("content-length")) {
                            bodyLeft_ = std::stoul(*cl);
                            if (bodyLeft_ > maxBody_) {
                                bodyTooLarge_ = true;
                                state_ = State::ERROR;
                            } else {
                                state_ = (bodyLeft_ > 0) ? State::BODY : State::DONE;
                            }
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
                case State::CHUNK_SIZE: {
                    size_t eol = buf_.find("\r\n");
                    if (eol == std::string::npos) return state_;
                    if (eol == 0 || eol > 32) {  // 空 size 行/畸形超长行
                        state_ = State::ERROR;
                        return state_;
                    }
                    unsigned long long csz = 0;
                    bool any = false;
                    for (size_t i = 0; i < eol; ++i) {
                        char ch = buf_[i];
                        if (ch == ';') break;  // chunk 扩展（;后）忽略
                        int d;
                        if (ch >= '0' && ch <= '9') d = ch - '0';
                        else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                        else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                        else if (ch == ' ' || ch == '\t') continue;
                        else {
                            state_ = State::ERROR;
                            return state_;
                        }
                        csz = csz * 16 + (unsigned)d;
                        any = true;
                        if (csz > (1ULL << 40)) {  // 防乘法溢出
                            bodyTooLarge_ = true;
                            state_ = State::ERROR;
                            return state_;
                        }
                    }
                    if (!any) {
                        state_ = State::ERROR;
                        return state_;
                    }
                    buf_.erase(0, eol + 2);
                    chunkLeft_ = (size_t)csz;
                    if (csz == 0) {
                        state_ = State::CHUNK_TRAILER;
                        break;
                    }
                    decodedBody_ += chunkLeft_;
                    if (decodedBody_ > maxBody_) {
                        bodyTooLarge_ = true;
                        state_ = State::ERROR;
                        return state_;
                    }
                    state_ = State::CHUNK_DATA;
                    break;
                }
                case State::CHUNK_DATA: {
                    if (buf_.size() < chunkLeft_ + 2) return state_;  // 数据 + 尾 CRLF
                    req_.body.append(buf_, 0, chunkLeft_);
                    buf_.erase(0, chunkLeft_ + 2);
                    state_ = State::CHUNK_SIZE;
                    break;
                }
                case State::CHUNK_TRAILER: {
                    // trailer 字段逐行丢弃，空行终止
                    size_t eol = buf_.find("\r\n");
                    if (eol == std::string::npos) return state_;
                    buf_.erase(0, eol + 2);
                    if (eol == 0) state_ = State::DONE;
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

    // headers 以原样大小写存储：大小写不敏感查找（lowerName 必须已小写）
    const std::string* hdrCi(const char* lowerName) const {
        for (const auto& [k, v] : req_.headers) {
            if (k.size() == std::char_traits<char>::length(lowerName)) {
                bool eq = true;
                for (size_t i = 0; i < k.size(); ++i) {
                    if ((char)std::tolower((unsigned char)k[i]) != lowerName[i]) { eq = false; break; }
                }
                if (eq) return &v;
            }
        }
        return nullptr;
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
    size_t chunkLeft_ = 0;
    size_t decodedBody_ = 0;
    size_t maxBody_ = 8u << 20;
    bool bodyTooLarge_ = false;
};

}  // namespace novawaf
