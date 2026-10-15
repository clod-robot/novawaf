// NovaWAF - 上游异步转发器（门面模式 + 生产者-消费者）
// reactor 提交转发任务后立即返回，由独立 IO 线程池执行 connect/send/recv，
// 完成后回写客户端并关闭连接、释放计数——彻底避免阻塞 reactor 线程。
// 池满/未初始化时 submit 返回 false，调用方应回退到同步转发（保证不丢请求）。
#pragma once

#include "novawaf/core/thread_pool.h"
#include "novawaf/core/traffic_sink.h"
#include "novawaf/net/upstream_pool.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <string>

namespace novawaf {

class UpstreamForwarder {
public:
    struct Ctx {
        int         clientFd = -1;
        std::string data;          // 原始请求字节
        std::string upstreamHost;
        int         upstreamPort = 0;
        std::string clientIp;
        bool        newSess = false;
        std::string sid;
        std::string appId;
        bool        statsEnabled = false;
        int         reactorIdx = 0;
        // 访问明细（透传到 TrafficSink 落 novawaf:access）
        std::string ua;
        std::string host;
        std::string path;
        std::string referer;
        std::string country;
        bool        keepAlive = false;   // 客户端连接是否复用(keep-alive)
        // 转发完成回调（在 IO 线程执行）：keepAlive=true 时由回调把客户端 fd 重新挂回 epoll；
        // keepAlive=false 时回调负责关闭 fd。为空则沿用旧行为(直接关闭)。
        std::function<void(int clientFd, bool keepAlive)> onComplete;
    };

    // 连接关闭回调（用于释放 DDoS 并发计数等），依赖倒置避免耦合具体防护类
    using OnDisconnect = std::function<void(const std::string&)>;

    explicit UpstreamForwarder(size_t ioThreads = 0, size_t queueSize = 1 << 16) {
        if (ioThreads == 0) ioThreads = std::thread::hardware_concurrency();
        pool_ = std::make_shared<ThreadPool>(ioThreads, queueSize);
        pool_->start();
    }
    ~UpstreamForwarder() { stop(); }

    void setOnDisconnect(OnDisconnect cb) { onDisconnect_ = std::move(cb); }

    // 入队异步转发。成功返回 true：调用方须将 fd 从 epoll 移除，交由本对象回写/关闭。
    // 返回 false：队列满或未运行，调用方应回退同步处理。
    bool submit(Ctx ctx) {
        if (!pool_) return false;
        return pool_->submit([this, ctx = std::move(ctx)]() mutable { run(std::move(ctx)); });
    }

    // 排空 IO 线程池并关闭所有池化连接（停止前调用，保证任务不丢、资源不泄漏）
    void stop() {
        if (pool_) { pool_->stop(); pool_.reset(); }
        connPool_.stop();
    }

private:
    // 归一化响应的 Connection 头（大小写不敏感替换）
    // 规范构造：head 为不含末尾空行的头区、body 为空行之后的精确字节；
    // 逐行重建时每条头行统一补 CRLF，最后再补一个空行(CRLF)，杜绝空行 CRLF 被计入 body
    // 导致响应体错位（历史缺陷：body=substr(he) 含空行，真实 body 被顶掉）。
    static void setResponseConnection(std::string& resp, bool keepAlive) {
        size_t he = resp.find("\r\n\r\n");
        std::string head = (he == std::string::npos) ? resp : resp.substr(0, he);
        std::string body = (he == std::string::npos) ? "" : resp.substr(he + 4);
        std::string out;
        size_t pos = 0;
        while (pos < head.size()) {
            size_t eol = head.find("\r\n", pos);
            std::string line = (eol == std::string::npos) ? head.substr(pos) : head.substr(pos, eol - pos);
            std::string low = line;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            if (low.compare(0, 11, "connection:") != 0) {
                out += line;
                out += "\r\n";   // 每条头行（含最后一条）统一行终止
            }
            if (eol == std::string::npos) break;
            pos = eol + 2;
        }
        size_t firstEol = out.find("\r\n");
        if (firstEol != std::string::npos)
            out.insert(firstEol + 2,
                       std::string("Connection: ") + (keepAlive ? "keep-alive" : "close") + "\r\n");
        resp = out + "\r\n" + body;  // 头区已各自带 CRLF，此处补空行 + 精确 body
    }

    // 客户端连接收尾：keep-alive 交回 reactor 复用，否则关闭
    void finishClient(Ctx& ctx) {
        setCliNonblock(ctx.clientFd);  // 复位非阻塞，交还 reactor 做 ET 读
        if (ctx.onComplete) {
            ctx.onComplete(ctx.clientFd, ctx.keepAlive);
        } else {
            ::close(ctx.clientFd);
            if (onDisconnect_) onDisconnect_(ctx.clientIp);
        }
    }

    // 客户端 fd 在 reactor 中为非阻塞(ET 读)；IO 线程回写时切阻塞，保证响应完整发出
    static void setCliBlocking(int fd) {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    // 回写完成后复位非阻塞，交还 reactor 做 ET 读
    static void setCliNonblock(int fd) {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }

    void run(Ctx ctx) {
        static const std::string k502 =
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        setCliBlocking(ctx.clientFd);  // 回写期间阻塞，保证响应完整（收尾时 reactor 会复位非阻塞）

        // 单次尝试：取连接→发请求→读响应。成功返回 true 并填充 outResp/ufd。
        auto attempt = [&](int& ufdOut, std::string& resp) -> bool {
            int ufd = connPool_.acquire(ctx.upstreamHost, ctx.upstreamPort);
            if (ufd < 0) return false;
            if (!sendAll(ufd, ctx.data.data(), ctx.data.size())) {
                connPool_.discard(ufd);   // 发送失败：连接已坏
                return false;
            }
            std::string head;
            if (!readHead(ufd, head)) {
                connPool_.discard(ufd);   // 读头失败：对端关闭/空闲死连接
                return false;
            }
            if (isStreamResp(head)) { resp = head; ufdOut = ufd; return true; }
            resp = head;
            if (!readBody(ufd, resp)) { connPool_.discard(ufd); return false; }
            connPool_.release(ctx.upstreamHost, ctx.upstreamPort, ufd);
            ufdOut = ufd;
            return true;
        };

        std::string outResp;
        int ufd = -1;
        bool ok = attempt(ufd, outResp);
        if (!ok) {                       // 死连接重试一次（池化空闲连接可能已被上游 FIN）
            outResp.clear();
            ok = attempt(ufd, outResp);
        }

        if (!ok) {
            std::string e = k502;
            setResponseConnection(e, false);
            writeAll(ctx.clientFd, e);
            finishClient(ctx);
            return;
        }
        // SSE(101/事件流)：流式中继，长连接不复用
        if (isStreamResp(outResp)) {
            if (ctx.newSess) injectHeader(outResp, "Set-Cookie: novasid=" + ctx.sid + "; Path=/; HttpOnly");
            setResponseConnection(outResp, false);
            writeAll(ctx.clientFd, outResp);
            relay(ctx.clientFd, ufd);
            connPool_.discard(ufd);
            if (ctx.statsEnabled) emitStat(ctx, respStatus(outResp), false);
            finishClient(ctx);
            return;
        }
        if (ctx.newSess) injectHeader(outResp, "Set-Cookie: novasid=" + ctx.sid + "; Path=/; HttpOnly");
        setResponseConnection(outResp, ctx.keepAlive);
        if (ctx.statsEnabled) emitStat(ctx, respStatus(outResp), false);
        writeAll(ctx.clientFd, outResp);
        finishClient(ctx);
    }

    void emitStat(const Ctx& ctx, int status, bool blocked) {
        TrafficReq tr;
        tr.ts = (int64_t)std::time(nullptr);
        tr.appId = ctx.appId; tr.status = status; tr.blocked = blocked; tr.attack = false;
        tr.ip = ctx.clientIp; tr.sid = ctx.sid; tr.ua = ctx.ua; tr.host = ctx.host;
        tr.path = ctx.path; tr.referer = ctx.referer; tr.country = ctx.country;
        TrafficSink::instance().emit(std::move(tr));
    }

    static bool sendAll(int fd, const char* d, size_t n) {
        size_t s = 0;
        while (s < n) {
            ssize_t w = ::send(fd, d + s, n - s, MSG_NOSIGNAL);
            if (w <= 0) return false;
            s += (size_t)w;
        }
        return true;
    }

    // 读到响应头结束(\r\n\r\n)；返回已读字节（含头及可能的首批 body）
    static bool readHead(int ufd, std::string& out) {
        out.clear();
        char buf[8192];
        while (true) {
            ssize_t n = ::recv(ufd, buf, sizeof(buf), 0);
            if (n <= 0) return !out.empty();
            out.append(buf, (size_t)n);
            if (out.find("\r\n\r\n") != std::string::npos) return true;
            if (out.size() > 65536) return true; // 头过大即止，防异常连接占满缓冲
        }
    }

    // 是否流式响应：101 Switching Protocols 或 Content-Type: text/event-stream
    static bool isStreamResp(const std::string& head) {
        size_t he = head.find("\r\n\r\n");
        std::string h = he == std::string::npos ? head : head.substr(0, he);
        for (auto& c : h) c = (char)tolower((unsigned char)c);
        if (h.compare(0, 9, "http/1.1 ") == 0) {
            auto sp = h.find(' ', 9);
            if (sp != std::string::npos && h.compare(9, sp - 9, "101") == 0) return true;
        }
        return h.find("text/event-stream") != std::string::npos;
    }

    // 读取 body：优先按 Content-Length，其次 chunked 解码，最后靠对端关闭(EOF)
    static bool readBody(int ufd, std::string& outResp) {
        size_t headerEnd = outResp.find("\r\n\r\n");
        if (headerEnd == std::string::npos) return !outResp.empty();
        std::string hdrs = outResp.substr(0, headerEnd);
        for (auto& c : hdrs) c = (char)tolower((unsigned char)c);
        // chunked 传输：无 Content-Length，必须按分块解码到结束块，否则会阻塞到 RCVTIMEO
        if (hdrs.find("transfer-encoding:") != std::string::npos &&
            hdrs.find("chunked") != std::string::npos) {
            return readChunked(ufd, outResp, headerEnd + 4);
        }
        long long contentLen = -1;
        auto cl = hdrs.find("\ncontent-length:");
        if (cl != std::string::npos) {
            auto eol = hdrs.find('\r', cl);
            if (eol == std::string::npos) eol = hdrs.size();
            contentLen = std::atoll(hdrs.substr(cl + 16, eol - cl - 16).c_str());
        }
        char buf[8192];
        while (true) {
            if (contentLen >= 0) {
                size_t bodyHave = outResp.size() - (headerEnd + 4);
                if ((long long)bodyHave >= contentLen) return true;
            }
            ssize_t n = ::recv(ufd, buf, sizeof(buf), 0);
            if (n > 0) outResp.append(buf, (size_t)n);
            else break;
        }
        return !outResp.empty();
    }

    // chunked 分块解码：读到 "0\r\n" 结束块（含尾部 trailer）即返回，避免等超时
    static bool readChunked(int ufd, std::string& buf, size_t pos) {
        char tmp[8192];
        auto fill = [&]() -> bool {
            ssize_t n = ::recv(ufd, tmp, sizeof(tmp), 0);
            if (n > 0) { buf.append(tmp, (size_t)n); return true; }
            return false;
        };
        while (true) {
            size_t eol;
            while ((eol = buf.find("\r\n", pos)) == std::string::npos) { if (!fill()) return !buf.empty(); }
            std::string sizeLine = buf.substr(pos, eol - pos);
            auto semi = sizeLine.find(';');
            if (semi != std::string::npos) sizeLine = sizeLine.substr(0, semi);
            long long chunkSize = std::strtoll(sizeLine.c_str(), nullptr, 16);
            pos = eol + 2;
            if (chunkSize == 0) {
                // 结束块：消费尾部 CRLF / trailer，直到空行
                while (buf.find("\r\n\r\n", pos > 2 ? pos - 2 : 0) == std::string::npos) { if (!fill()) break; }
                return true;
            }
            while ((long long)(buf.size() - pos) < chunkSize + 2) { if (!fill()) return !buf.empty(); }
            pos += (size_t)chunkSize + 2;
        }
    }

    // 双向流式中继：SSE / WebSocket，边收边发，任一端关闭即结束
    static void relay(int cfd, int ufd) {
        char buf[16384];
        struct pollfd fds[2];
        fds[0].fd = ufd;  fds[0].events = POLLIN;
        fds[1].fd = cfd;  fds[1].events = POLLIN;
        while (true) {
            fds[0].revents = 0; fds[1].revents = 0;
            int r = ::poll(fds, 2, 5000);
            if (r < 0) break;
            if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = ::recv(ufd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                if (!sendAll(cfd, buf, (size_t)n)) break;
            }
            if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                if (!sendAll(ufd, buf, (size_t)n)) break;
            }
        }
    }

    static void writeAll(int fd, const std::string& data) {
        sendAll(fd, data.data(), data.size());
    }

    static void injectHeader(std::string& resp, const std::string& headerLine) {
        auto p = resp.find("\r\n");
        if (p != std::string::npos) resp.insert(p + 2, headerLine + "\r\n");
    }

    static int respStatus(const std::string& resp) {
        auto p = resp.find(' ');
        if (p == std::string::npos) return 0;
        auto p2 = resp.find(' ', p + 1);
        return std::atoi(resp.substr(p + 1, p2 == std::string::npos ? std::string::npos : p2 - p - 1).c_str());
    }

    std::shared_ptr<ThreadPool> pool_;
    UpstreamPool connPool_;
    OnDisconnect onDisconnect_;
};

}  // namespace novawaf
