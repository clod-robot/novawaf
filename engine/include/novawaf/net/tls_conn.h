#pragma once

// TLS 连接（TCP）：SSL 握手 → ALPN 分发 h1 / h2 → H1Bridge。
// h1 模式支持 keep-alive 流水线（FIFO 有序响应）；h2 模式委托 H2Session。
// 每个 TlsConn 由所属 reactor 线程独占驱动（无锁）。

#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <utility>

#include "bridge.h"
#include "h2_session.h"
#include "http_parser.h"

namespace novawaf {

class TlsConn : public H2Session::Io {
public:
    TlsConn(int fd, SSL* ssl, int epfd, H1Bridge& bridge, std::string peerIp, size_t maxBody)
        : fd_(fd), ssl_(ssl), epfd_(epfd), bridge_(bridge), peerIp_(std::move(peerIp)) {
        SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_set_accept_state(ssl_);
        h1Parser_.setMaxBody(maxBody);
        h2_ = std::make_unique<H2Session>(*this, bridge_, peerIp_, maxBody);
    }

    ~TlsConn() {
        if (fd_ >= 0) {
            epoll_ctl(epfd_, EPOLL_CTL_DEL, fd_, nullptr);
            close(fd_);
        }
        if (ssl_) SSL_free(ssl_);
    }

    TlsConn(const TlsConn&) = delete;
    TlsConn& operator=(const TlsConn&) = delete;

    int fd() const { return fd_; }
    bool closed() const { return closed_; }
    const std::string& peerIp() const { return peerIp_; }

    // 无在途请求且输出已排空（drain 期间空闲回收判定）
    bool idle() const {
        return handshaken_ && !closed_ && outQ_.empty() && h1In_.empty() &&
               h1Queue_.empty() && !h1Awaiting_ && (!h2Mode_ || h2_->idle());
    }

    void onEvent(uint32_t events) {
        if (closed_) return;
        if (!handshaken_) {
            doHandshake();
            return;
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            markClosed();
            return;
        }
        if (events & EPOLLOUT) flushOut();
        if (closed_) return;
        if (events & (EPOLLIN | EPOLLRDHUP)) doRead();
    }

    // ---- H2Session::Io ----
    void h2QueueOut(const uint8_t* data, size_t len) override {
        if (closed_) return;
        if (outQ_.size() + len > maxOutQ_) {
            markClosed();  // 背压上限，防内存膨胀
            return;
        }
        outQ_.append(reinterpret_cast<const char*>(data), len);
        // 桥异步回调路径不经过 doRead：入队后必须立即尝试写出
        // （否则 EPOLLOUT 未订阅、数据永远滞留 —— h2 挂死根因）
        flushOut();
    }

private:
    void doHandshake() {
        int rv = SSL_accept(ssl_);
        if (rv == 1) {
            handshaken_ = true;
            const unsigned char* alpn = nullptr;
            unsigned int alpnLen = 0;
            SSL_get0_alpn_selected(ssl_, &alpn, &alpnLen);
            h2Mode_ = (alpnLen == 2 && std::memcmp(alpn, "h2", 2) == 0);
            if (h2Mode_ && !h2_->init()) {
                markClosed();
                return;
            }
            applyEvents();
            flushOut();
            // h2 客户端常在 TLS 握手同航班即发 preface/SETTINGS：数据已在 OpenSSL
            // 缓冲区，ET 模式不会再通知 —— 必须立即主动读一轮（h1 流水线同理受益）
            if (!closed_) doRead();
            return;
        }
        int err = SSL_get_error(ssl_, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            wantOut_ = (err == SSL_ERROR_WANT_WRITE);
            applyEvents();
            return;
        }
        markClosed();
    }

    void doRead() {
        uint8_t buf[16384];
        for (;;) {
            int rv = SSL_read(ssl_, buf, sizeof(buf));
            if (rv > 0) {
                int pr = h2Mode_ ? h2_->onRecv(buf, static_cast<size_t>(rv))
                                 : onH1Bytes(buf, static_cast<size_t>(rv));
                if (pr < 0) {
                    markClosed();
                    return;
                }
                flushOut();
                if (closed_) return;
                continue;
            }
            int err = SSL_get_error(ssl_, rv);
            if (err == SSL_ERROR_WANT_READ) {
                applyEvents();
                return;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                wantOut_ = true;
                applyEvents();
                return;
            }
            markClosed();  // ZERO_RETURN / SYSCALL / 其他
            return;
        }
    }

    void flushOut() {
        while (outPos_ < outQ_.size()) {
            int rv = SSL_write(ssl_, outQ_.data() + outPos_,
                               static_cast<int>(outQ_.size() - outPos_));
            if (rv > 0) {
                outPos_ += static_cast<size_t>(rv);
                continue;
            }
            int err = SSL_get_error(ssl_, rv);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                wantOut_ = true;
                applyEvents();
                return;
            }
            markClosed();
            return;
        }
        outQ_.clear();
        outPos_ = 0;
        wantOut_ = false;
        if (closeAfterFlush_) {
            markClosed();
            return;
        }
        applyEvents();
    }

    void applyEvents() {
        if (closed_) return;
        uint32_t ev = EPOLLIN | EPOLLET | EPOLLRDHUP;
        if (wantOut_ || outPos_ < outQ_.size()) ev |= EPOLLOUT;
        struct epoll_event ee{};
        ee.events = ev;
        ee.data.fd = fd_;
        epoll_ctl(epfd_, EPOLL_CTL_MOD, fd_, &ee);
    }

    void markClosed() {
        if (closed_) return;
        closed_ = true;
        SSL_shutdown(ssl_);  // 非阻塞 fire-and-forget
    }

    // ---------------- h1 over TLS ----------------

    // headers 为原样大小写的 unordered_map：大小写不敏感查找
    static const std::string* hdrCiRef(const HttpRequest& req, const char* lowerName) {
        for (const auto& [k, v] : req.headers)
            if (lowerStr(k) == lowerName) return &v;
        return nullptr;
    }

    static bool keepAliveOf(const HttpRequest& req) {
        const std::string* conn = hdrCiRef(req, "connection");
        if (req.version.find("1.1") != std::string::npos) {
            return !(conn && lowerStr(*conn) == "close");
        }
        return conn && lowerStr(*conn) == "keep-alive";
    }

    int onH1Bytes(const uint8_t* data, size_t len) {
        if (h1In_.size() + len > (8u << 20)) return -1;
        h1In_.append(reinterpret_cast<const char*>(data), len);
        for (;;) {
            // HttpParser 内部持有缓冲：整段喂入，DONE 后取回流水线剩余字节
            HttpParser::State st = h1Parser_.feed(h1In_.data(), h1In_.size());
            h1In_.clear();
            if (st == HttpParser::State::ERROR) {
                if (h1Parser_.bodyTooLarge()) {  // 超 body 上限：回 413 后优雅关连
                    static const char r413[] =
                        "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n"
                        "Connection: close\r\n\r\n";
                    if (outQ_.size() + sizeof(r413) <= maxOutQ_) {
                        outQ_ += r413;
                        closeAfterFlush_ = true;
                        flushOut();
                        return 0;
                    }
                }
                return -1;
            }
            if (!h1Parser_.done()) return 0;  // 数据不足，等下一批
            HttpRequest req = h1Parser_.request();
            h1Parser_.stealLeftover(h1In_);  // 保留流水线多余字节供下一轮解析
            h1Parser_.reset();
            h1Queue_.push_back(H1Pending{std::move(req)});
            if (h1Queue_.size() > 64) return -1;  // 流水线深度保护
            if (!h1Awaiting_) submitNextH1();
            if (closed_) return 0;
            if (h1In_.empty()) return 0;
        }
    }

    void submitNextH1() {
        if (h1Queue_.empty()) return;
        h1Awaiting_ = true;
        const HttpRequest& req = h1Queue_.front().req;

        BridgeRequest br;
        br.method = req.method;
        br.target = req.path;
        if (!req.query.empty()) {
            br.target += '?';
            br.target += req.query;
        }
        if (const std::string* host = hdrCiRef(req, "host")) br.host = *host;
        br.headOnly = (req.method == "HEAD");
        br.clientIp = peerIp_;
        bool trusted = novaTrustedProxy(peerIp_);
        for (const auto& [k, v] : req.headers) {
            if (trusted && lowerStr(k) == "x-forwarded-for") {
                std::string lm = xffLeftmost(v);
                if (!lm.empty()) br.clientIp = lm;
            }
            br.headers.emplace_back(k, v);
        }
        br.body = req.body;

        // 桥异步回调可能晚于本对象析构触发（连接中途断开）：weak 存活令牌防悬空
        std::weak_ptr<char> wp = alive_;
        bridge_.submit(std::move(br), [this, wp](const BridgeResponse& resp) {
            if (wp.expired()) return;
            onH1Response(resp);
        });
    }

    void onH1Response(const BridgeResponse& resp) {
        if (closed_) return;
        if (h1Queue_.empty()) {  // 防御：不应发生
            h1Awaiting_ = false;
            return;
        }
        const HttpRequest& req = h1Queue_.front().req;
        bool ka = keepAliveOf(req);
        bool head = (req.method == "HEAD");
        bool http10 = (req.version != "HTTP/1.1");
        h1Queue_.pop_front();

        int status = resp.status > 0 ? resp.status : 502;
        const std::string& body = (resp.status > 0 && !head) ? resp.body : emptyBody();
        size_t bodyLen = head ? 0 : body.size();

        std::string out;
        out.reserve(256 + bodyLen);
        out += "HTTP/1.1 " + std::to_string(status) + " " + reasonPhrase(status) + "\r\n";
        bool hasDate = false, hasServer = false;
        for (const auto& [k, v] : resp.headers) {
            std::string lk = lowerStr(k);
            if (isHopByHop(lk)) continue;
            if (lk == "date") hasDate = true;
            if (lk == "server") hasServer = true;
            out += k + ": " + v + "\r\n";
        }
        if (resp.status <= 0) out += "Content-Type: text/plain\r\n";
        if (!hasServer) out += "Server: NovaWAF\r\n";
        (void)hasDate;
        out += "Content-Length: " + std::to_string(head ? resp.body.size() : bodyLen) + "\r\n";
        out += std::string("Connection: ") + (ka ? "keep-alive" : "close") + "\r\n\r\n";
        if (bodyLen) out += body;
        (void)http10;

        if (outQ_.size() + out.size() > maxOutQ_) {
            markClosed();
            return;
        }
        outQ_ += out;
        if (!ka) closeAfterFlush_ = true;
        h1Awaiting_ = false;
        if (ka) submitNextH1();
        flushOut();
    }

    static const std::string& emptyBody() {
        static const std::string e;
        return e;
    }

    static const char* reasonPhrase(int s) {
        switch (s) {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 413: return "Content Too Large";
            case 414: return "URI Too Long";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return "OK";
        }
    }

    int fd_ = -1;
    SSL* ssl_ = nullptr;
    int epfd_ = -1;
    H1Bridge& bridge_;
    std::string peerIp_;
    bool handshaken_ = false;
    bool h2Mode_ = false;
    bool closed_ = false;
    bool wantOut_ = false;
    bool closeAfterFlush_ = false;
    std::string outQ_;
    size_t outPos_ = 0;
    size_t maxOutQ_ = 16u << 20;
    std::unique_ptr<H2Session> h2_;

    // h1 模式状态
    std::string h1In_;
    HttpParser h1Parser_;
    struct H1Pending {
        HttpRequest req;
    };
    std::deque<H1Pending> h1Queue_;
    bool h1Awaiting_ = false;
    std::shared_ptr<char> alive_ = std::make_shared<char>(0);  // 析构即失效的存活令牌
};

}  // namespace novawaf
