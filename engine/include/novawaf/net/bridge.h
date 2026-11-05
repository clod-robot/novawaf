#pragma once

// H1 回环桥：把 TLS/QUIC 侧解析出的请求合成为标准 HTTP/1.1 字节，
// 经 per-reactor 回环连接池送入本机 h1 检测管线（唯一检测真值源），
// 解析 h1 响应后回调给来源协议层回帧。全部方法仅限所属 reactor 线程调用（无锁）。

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace novawaf {

struct BridgeRequest {
    std::string method;
    std::string target;  // path + ?query
    std::string host;
    std::string clientIp;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool headOnly = false;  // HEAD：响应丢弃 body（由调用方处理，桥只透传）
};

struct BridgeResponse {
    int status = 0;  // 0 = 桥失败（对端应映射 502）
    bool connClose = false;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

// main.cpp 提供（单 TU 构建）：受信代理判断
bool novaTrustedProxy(const std::string& ip);

// XFF 取最左（原始客户端）
inline std::string xffLeftmost(const std::string& v) {
    size_t comma = v.find(',');
    std::string first = (comma == std::string::npos) ? v : v.substr(0, comma);
    size_t b = first.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    size_t e = first.find_last_not_of(" \t");
    return first.substr(b, e - b + 1);
}

inline std::string lowerStr(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

// 连接级 / 定界头：桥合成与响应回帧时剔除
inline bool isHopByHop(const std::string& lowerName) {
    return lowerName == "connection" || lowerName == "keep-alive" || lowerName == "proxy-connection" ||
           lowerName == "transfer-encoding" || lowerName == "upgrade" || lowerName == "te" ||
           lowerName == "trailer" || lowerName == "content-length";
}

class H1Bridge {
public:
    using Callback = std::function<void(const BridgeResponse&)>;

    H1Bridge(int epfd, uint16_t port) : epfd_(epfd), port_(port) {
        const char* mr = getenv("NOVA_BRIDGE_MAX_RESP");
        if (mr && *mr) maxResp_ = static_cast<size_t>(std::atoll(mr));
    }
    ~H1Bridge() { closeAll(); }

    void submit(BridgeRequest req, Callback cb) {
        if (queue_.size() >= maxQueue_) {
            BridgeResponse r;  // status=0 → 调用方回 502
            cb(r);
            return;
        }
        queue_.push_back(Pending{std::move(req), std::move(cb), false, false});
        pump();
    }

    bool owns(int fd) const { return conns_.find(fd) != conns_.end(); }
    size_t inFlight() const { return inFlight_; }

    void onEvent(int fd, uint32_t events) {
        auto it = conns_.find(fd);
        if (it == conns_.end()) return;
        Conn* c = it->second.get();

        if (c->connecting) {
            if (events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len);
                c->connecting = false;
                if (err != 0) {
                    fail(c);
                    return;
                }
                applyEvents(c);
            } else {
                return;
            }
        }

        if (events & (EPOLLERR | EPOLLHUP)) {
            fail(c);
            return;
        }
        if ((events & EPOLLOUT) && c->outPos < c->out.size()) {
            if (!flushOut(c)) return;
        }
        if (events & (EPOLLIN | EPOLLRDHUP)) {
            readIn(c);
        }
    }

    // reactor 定时器驱动：回收超时在途请求 + 闲置连接
    void sweep(int64_t nowMs) {
        std::vector<Conn*> dead;
        for (auto& [fd, cp] : conns_) {
            Conn* c = cp.get();
            if (c->busy && nowMs - c->startMs > timeoutMs_) dead.push_back(c);
            else if (!c->busy && nowMs - c->idleSinceMs > idleKeepMs_) dead.push_back(c);
        }
        for (Conn* c : dead) {
            if (c->busy) fail(c);
            else closeConn(c);
        }
    }

    void closeAll() {
        while (!conns_.empty()) closeConn(conns_.begin()->second.get());
        idle_.clear();
        while (!queue_.empty()) {
            BridgeResponse r;
            queue_.front().cb(r);
            queue_.pop_front();
        }
    }

private:
    enum class ChunkState { SIZE, DATA, TRAILER, RAW };

    struct Conn {
        int fd = -1;
        bool connecting = false;
        bool busy = false;
        bool fromIdle = false;
        bool closeWhenDone = false;
        bool readToEof = false;
        bool headOnly = false;
        std::string out;
        size_t outPos = 0;
        std::string in;
        bool gotAnyIn = false;
        bool headDone = false;
        int status = 0;
        bool chunked = false;
        long long contentLength = -1;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        ChunkState chunkState = ChunkState::SIZE;
        long long chunkLeft = 0;
        Callback cb;
        int64_t startMs = 0;
        int64_t idleSinceMs = 0;
    };

    struct Pending {
        BridgeRequest req;
        Callback cb;
        bool retried;
        bool fromIdle;
    };

    static int64_t nowMs() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }

    void pump() {
        while (!queue_.empty()) {
            bool fromIdle = false;
            Conn* c = acquire(fromIdle);
            if (!c) return;
            Pending p = std::move(queue_.front());
            queue_.pop_front();
            p.fromIdle = fromIdle;
            dispatch(c, std::move(p));
        }
    }

    Conn* acquire(bool& fromIdle) {
        while (!idle_.empty()) {
            Conn* c = idle_.back();
            idle_.pop_back();
            if (conns_.find(c->fd) != conns_.end()) {
                fromIdle = true;
                return c;  // 仍存活
            }
        }
        if (conns_.size() >= maxConns_) return nullptr;

        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) return nullptr;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port_);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        int rv = connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        if (rv < 0 && errno != EINPROGRESS) {
            close(fd);
            return nullptr;
        }

        auto conn = std::make_unique<Conn>();
        conn->fd = fd;
        conn->connecting = (rv < 0);
        Conn* raw = conn.get();
        conns_[fd] = std::move(conn);

        struct epoll_event ee{};
        ee.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
        ee.data.fd = fd;
        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ee) < 0) {
            conns_.erase(fd);
            close(fd);
            return nullptr;
        }
        return raw;
    }

    static bool skipReqHeader(const std::string& lower) {
        return isHopByHop(lower) || lower == "host" || lower == "x-forwarded-for" ||
               lower == "x-real-ip" || lower == "x-forwarded-proto" || lower == "x-forwarded-host";
    }

    static std::string synthesize(const BridgeRequest& r) {
        std::string s;
        s.reserve(512 + r.body.size());
        s += r.method;
        s += ' ';
        s += r.target.empty() ? "/" : r.target;
        s += " HTTP/1.1\r\n";
        s += "Host: ";
        s += r.host.empty() ? "localhost" : r.host;
        s += "\r\n";
        for (const auto& [k, v] : r.headers) {
            std::string lk = lowerStr(k);
            if (lk.empty() || lk[0] == ':' || skipReqHeader(lk)) continue;
            s += k;
            s += ": ";
            s += v;
            s += "\r\n";
        }
        s += "X-Forwarded-For: " + (r.clientIp.empty() ? std::string("127.0.0.1") : r.clientIp) + "\r\n";
        s += "X-Forwarded-Proto: https\r\n";
        s += "Connection: keep-alive\r\n";
        s += "Content-Length: " + std::to_string(r.body.size()) + "\r\n\r\n";
        s += r.body;
        return s;
    }

    void dispatch(Conn* c, Pending&& p) {
        c->out = synthesize(p.req);
        c->outPos = 0;
        c->in.clear();
        c->gotAnyIn = false;
        c->headDone = false;
        c->status = 0;
        c->chunked = false;
        c->contentLength = -1;
        c->headers.clear();
        c->body.clear();
        c->chunkState = ChunkState::SIZE;
        c->chunkLeft = 0;
        c->closeWhenDone = false;
        c->readToEof = false;
        c->headOnly = p.req.headOnly;
        c->busy = true;
        c->fromIdle = p.fromIdle;
        c->cb = std::move(p.cb);
        c->startMs = nowMs();
        ++inFlight_;
        currentReq_[c->fd] = std::move(p.req);
        if (!flushOut(c)) return;
    }

    bool flushOut(Conn* c) {
        while (c->outPos < c->out.size()) {
            ssize_t n = write(c->fd, c->out.data() + c->outPos, c->out.size() - c->outPos);
            if (n > 0) {
                c->outPos += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                applyEvents(c);
                return true;
            }
            if (n < 0 && errno == EINTR) continue;
            fail(c);
            return false;
        }
        applyEvents(c);
        return true;
    }

    void applyEvents(Conn* c) {
        uint32_t ev = EPOLLIN | EPOLLET | EPOLLRDHUP;
        if (c->connecting || c->outPos < c->out.size()) ev |= EPOLLOUT;
        struct epoll_event ee{};
        ee.events = ev;
        ee.data.fd = c->fd;
        epoll_ctl(epfd_, EPOLL_CTL_MOD, c->fd, &ee);
    }

    void readIn(Conn* c) {
        char buf[16384];
        for (;;) {
            ssize_t n = read(c->fd, buf, sizeof(buf));
            if (n > 0) {
                c->gotAnyIn = true;
                c->in.append(buf, static_cast<size_t>(n));
                if (c->in.size() > maxResp_ + 65536) {
                    fail(c);
                    return;
                }
                if (c->busy && parse(c)) return;
                if (conns_.find(c->fd) == conns_.end()) return;  // parse 内可能 finish/fail
                continue;
            }
            if (n == 0) {  // EOF
                if (!c->busy) {
                    closeConn(c);
                    return;
                }
                if (c->readToEof && c->headDone) {
                    c->body = std::move(c->in);
                    c->closeWhenDone = true;
                    finish(c);
                    return;
                }
                fail(c);
                return;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            fail(c);
            return;
        }
    }

    // 返回 true = 连接生命周期已结束（finish/fail），调用方不得再触碰 c
    bool parse(Conn* c) {
        if (!c->headDone) {
            size_t he = c->in.find("\r\n\r\n");
            if (he == std::string::npos) return false;
            if (!parseHead(c, he)) {
                fail(c);
                return true;
            }
            c->headDone = true;
            c->in.erase(0, he + 4);

            bool noBody = c->headOnly || (c->status >= 100 && c->status < 200) || c->status == 204 ||
                          c->status == 304;
            if (noBody) {
                finish(c);
                return true;
            }
            if (c->contentLength == 0 && !c->chunked && !c->readToEof) {
                finish(c);
                return true;
            }
        }

        if (c->chunked) {
            int r = parseChunks(c);
            if (r < 0) {
                fail(c);
                return true;
            }
            if (r == 1) {
                finish(c);
                return true;
            }
            return false;
        }
        if (c->contentLength >= 0) {
            if (c->in.size() >= static_cast<size_t>(c->contentLength)) {
                c->body = c->in.substr(0, static_cast<size_t>(c->contentLength));
                finish(c);
                return true;
            }
            return false;
        }
        return false;  // readToEof：等 EOF
    }

    bool parseHead(Conn* c, size_t headLen) {
        std::string head = c->in.substr(0, headLen);
        size_t eol = head.find("\r\n");
        std::string statusLine = (eol == std::string::npos) ? head : head.substr(0, eol);
        // HTTP/1.1 200 OK
        size_t sp = statusLine.find(' ');
        if (sp == std::string::npos) return false;
        c->status = std::atoi(statusLine.c_str() + sp + 1);
        if (c->status <= 0) return false;

        size_t pos = (eol == std::string::npos) ? head.size() : eol + 2;
        while (pos < head.size()) {
            size_t le = head.find("\r\n", pos);
            if (le == std::string::npos) le = head.size();
            std::string line = head.substr(pos, le - pos);
            pos = le + 2;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            size_t vb = value.find_first_not_of(" \t");
            if (vb != std::string::npos) value = value.substr(vb);
            std::string lname = lowerStr(name);
            if (lname == "transfer-encoding" && lowerStr(value).find("chunked") != std::string::npos) {
                c->chunked = true;
            } else if (lname == "content-length") {
                c->contentLength = std::atoll(value.c_str());
                if (c->contentLength < 0 || static_cast<unsigned long long>(c->contentLength) > maxResp_)
                    return false;
            } else if (lname == "connection" && lowerStr(value) == "close") {
                c->closeWhenDone = true;
            }
            c->headers.emplace_back(std::move(name), std::move(value));
        }
        if (!c->chunked && c->contentLength < 0) c->readToEof = true;
        return true;
    }

    // 0=需更多 1=完成 -1=错误
    int parseChunks(Conn* c) {
        for (;;) {
            if (c->chunkState == ChunkState::SIZE) {
                size_t eol = c->in.find("\r\n");
                if (eol == std::string::npos) return 0;
                std::string line = c->in.substr(0, eol);
                size_t semi = line.find(';');
                if (semi != std::string::npos) line = line.substr(0, semi);
                unsigned long long sz = 0;
                int cnt = 0;
                for (char ch : line) {
                    int d;
                    if (ch >= '0' && ch <= '9') d = ch - '0';
                    else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                    else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                    else if (ch == ' ' || ch == '\t') continue;
                    else return -1;
                    sz = (sz << 4) | static_cast<unsigned long long>(d);
                    if (++cnt > 16) return -1;
                }
                if (sz > maxResp_) return -1;
                c->in.erase(0, eol + 2);
                if (sz == 0) {
                    c->chunkState = ChunkState::TRAILER;
                    continue;
                }
                c->chunkLeft = static_cast<long long>(sz);
                c->chunkState = ChunkState::DATA;
            } else if (c->chunkState == ChunkState::DATA) {
                if (c->in.size() < static_cast<size_t>(c->chunkLeft) + 2) return 0;
                if (c->in[static_cast<size_t>(c->chunkLeft)] != '\r' ||
                    c->in[static_cast<size_t>(c->chunkLeft) + 1] != '\n')
                    return -1;
                c->body.append(c->in, 0, static_cast<size_t>(c->chunkLeft));
                if (c->body.size() > maxResp_) return -1;
                c->in.erase(0, static_cast<size_t>(c->chunkLeft) + 2);
                c->chunkLeft = 0;
                c->chunkState = ChunkState::SIZE;
            } else {  // TRAILER
                size_t eol = c->in.find("\r\n");
                if (eol == std::string::npos) return 0;
                if (eol == 0) return 1;  // 空行收尾
                c->in.erase(0, eol + 2);
            }
        }
    }

    void finish(Conn* c) {
        BridgeResponse resp;
        resp.status = c->status;
        resp.connClose = c->closeWhenDone;
        for (auto& [k, v] : c->headers) {
            if (isHopByHop(lowerStr(k))) continue;
            resp.headers.emplace_back(std::move(k), std::move(v));
        }
        resp.body = std::move(c->body);
        Callback cb = std::move(c->cb);
        releaseConn(c);
        cb(resp);  // 回调最后执行（可能触发新 submit）
    }

    void fail(Conn* c) {
        // 空闲连接复用竞争：一字节未收到且未重试过 → 换新连接重试一次
        auto it = currentReq_.find(c->fd);
        if (c->fromIdle && !c->gotAnyIn && it != currentReq_.end() && queue_.size() < maxQueue_) {
            Pending p{std::move(it->second), std::move(c->cb), true, false};
            currentReq_.erase(it);
            closeConn(c);
            inFlight_--;
            queue_.push_front(std::move(p));
            pump();
            return;
        }
        Callback cb = std::move(c->cb);
        if (it != currentReq_.end()) currentReq_.erase(it);
        closeConn(c);
        inFlight_--;
        if (cb) {
            BridgeResponse r;
            cb(r);
        }
        pump();
    }

    void releaseConn(Conn* c) {
        currentReq_.erase(c->fd);
        inFlight_--;
        c->busy = false;
        c->cb = nullptr;
        if (c->closeWhenDone || c->readToEof) {
            closeConn(c);
            return;
        }
        c->idleSinceMs = nowMs();
        idle_.push_back(c);
        pump();
    }

    void closeConn(Conn* c) {
        if (!c) return;
        for (auto it = idle_.begin(); it != idle_.end(); ++it) {
            if (*it == c) {
                idle_.erase(it);
                break;
            }
        }
        currentReq_.erase(c->fd);
        epoll_ctl(epfd_, EPOLL_CTL_DEL, c->fd, nullptr);
        close(c->fd);
        conns_.erase(c->fd);
    }

    int epfd_;
    uint16_t port_;
    std::unordered_map<int, std::unique_ptr<Conn>> conns_;
    std::unordered_map<int, BridgeRequest> currentReq_;  // 重试用
    std::vector<Conn*> idle_;
    std::deque<Pending> queue_;
    size_t inFlight_ = 0;
    size_t maxConns_ = 32;
    size_t maxQueue_ = 2048;
    size_t maxResp_ = 8 << 20;  // 8MB 缓冲上限（SSE/WebSocket 为缓冲模式）
    int64_t timeoutMs_ = 60000;
    int64_t idleKeepMs_ = 10000;  // 引擎 keep-alive 15s，提前回收
};

}  // namespace novawaf
