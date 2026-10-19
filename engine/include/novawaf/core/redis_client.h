// NovaWAF - 极简 header-only Redis 客户端（RESP over TCP，零第三方依赖）
// 仅实现引擎加载数据所需的命令：AUTH / SELECT / GET / HGET / PING。
// 用途：从 Redis 内存加载 geoip / ioc 数据，免除磁盘 IO 与重复解析。
// 设计（安全/稳定）：
//   * 同步阻塞调用，带连接/读写超时，避免网络异常拖垮检测线程。
//   * 仅用于后台加载线程，不在请求热路径调用。
//   * 与 Redis 通信应为内网；生产须配密码 + 绑定受信地址。
#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace novawaf {

class RedisClient {
public:
    RedisClient() = default;
    ~RedisClient() { disconnect(); }
    RedisClient(const RedisClient&) = delete;
    RedisClient& operator=(const RedisClient&) = delete;

    // 连接（带超时毫秒）。失败返回 false。
    bool connect(const std::string& host, int port, const std::string& pass = "",
                 int db = 0, int timeoutMs = 2000) {
        disconnect();
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        // 非阻塞 connect 以实现超时
        int flags = ::fcntl(fd_, F_GETFL, 0);
        ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            // 主机名解析
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
                addr.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
                ::freeaddrinfo(res);
            } else {
                disconnect();
                return false;
            }
        }
        int rc = ::connect(fd_, (sockaddr*)&addr, sizeof(addr));
        if (rc < 0 && errno != EINPROGRESS) { disconnect(); return false; }
        if (rc < 0) {
            // poll 无 FD_SETSIZE 限制，支持 fd>=1024（select 在高 fd 会直接 abort）
            struct pollfd pfd{};
            pfd.fd = fd_;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, timeoutMs) <= 0) { disconnect(); return false; }
            int err = 0; socklen_t el = sizeof(err);
            ::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &el);
            if (err != 0) { disconnect(); return false; }
        }
        ::fcntl(fd_, F_SETFL, flags);  // 恢复阻塞
        if (!pass.empty()) {
            auto r = command({"AUTH", pass});
            if (!r || r->asString() != "OK") { disconnect(); return false; }
        }
        if (db != 0) {
            auto r = command({"SELECT", std::to_string(db)});
            if (!r || r->asString() != "OK") { disconnect(); return false; }
        }
        timeoutMs_ = timeoutMs;
        return true;
    }

    void disconnect() {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }
    bool connected() const { return fd_ >= 0; }

    // GET key -> 字符串值（不存在返回 nullopt）
    std::optional<std::string> get(const std::string& key) {
        auto r = command({"GET", key});
        if (!r) return std::nullopt;
        if (r->kind == Reply::BULK && r->bulk.has_value()) return r->bulk;
        return std::nullopt;
    }
    // HGET key field -> 值（不存在返回 nullopt）
    std::optional<std::string> hget(const std::string& key, const std::string& field) {
        auto r = command({"HGET", key, field});
        if (!r) return std::nullopt;
        if (r->kind == Reply::BULK && r->bulk.has_value()) return r->bulk;
        return std::nullopt;
    }
    // HSET key field value -> 成功返回 true
    bool hset(const std::string& key, const std::string& field, const std::string& value) {
        auto r = command({"HSET", key, field, value});
        return r && (r->kind == Reply::INTEGER || r->asString() == "OK");
    }
    // SET key value（成功返回 true）
    bool set(const std::string& key, const std::string& value) {
        auto r = command({"SET", key, value});
        return r && r->asString() == "OK";
    }
    // DEL key（返回被删数量，失败 -1）
    int64_t del(const std::string& key) {
        auto r = command({"DEL", key});
        if (!r || r->kind != Reply::INTEGER) return -1;
        return r->integer;
    }
    // INCR key -> 自增后的值（失败 nullopt）
    std::optional<int64_t> incr(const std::string& key) {
        auto r = command({"INCR", key});
        if (!r || r->kind != Reply::INTEGER) return std::nullopt;
        return r->integer;
    }
    // RPUSH key value -> 推送后列表长度（失败 nullopt）
    std::optional<int64_t> rpush(const std::string& key, const std::string& value) {
        auto r = command({"RPUSH", key, value});
        if (!r || r->kind != Reply::INTEGER) return std::nullopt;
        return r->integer;
    }
    // RPUSH key v1 v2 ... 批量推送（失败 nullopt）
    std::optional<int64_t> rpushMulti(const std::string& key, const std::vector<std::string>& values) {
        std::vector<std::string> args;
        args.reserve(values.size() + 2);
        args.push_back("RPUSH");
        args.push_back(key);
        for (auto& v : values) args.push_back(v);
        auto r = command(args);
        if (!r || r->kind != Reply::INTEGER) return std::nullopt;
        return r->integer;
    }
    // LTRIM key start stop（成功返回 true）
    bool ltrim(const std::string& key, int64_t start, int64_t stop) {
        auto r = command({"LTRIM", key, std::to_string(start), std::to_string(stop)});
        return r && r->kind == Reply::STATUS && r->status == "OK";
    }
    // LRANGE key start stop -> 元素列表（失败 nullopt）
    std::optional<std::vector<std::string>> lrange(const std::string& key, int64_t start, int64_t stop) {
        auto r = command({"LRANGE", key, std::to_string(start), std::to_string(stop)});
        if (!r || r->kind != Reply::ARRAY) return std::nullopt;
        return r->arr;
    }
    // HINCRBY key field delta -> 自增后的值（溯源按 IP 分桶真实计数用）
    std::optional<int64_t> hincrby(const std::string& key, const std::string& field, int64_t delta) {
        auto r = command({"HINCRBY", key, field, std::to_string(delta)});
        if (!r || r->kind != Reply::INTEGER) return std::nullopt;
        return r->integer;
    }
    // HGETALL key -> [field1, value1, field2, value2, ...]（失败 nullopt）
    std::optional<std::vector<std::string>> hgetall(const std::string& key) {
        auto r = command({"HGETALL", key});
        if (!r || r->kind != Reply::ARRAY) return std::nullopt;
        return r->arr;
    }
    // EXPIRE key seconds（成功返回 true）
    bool expire(const std::string& key, int64_t seconds) {
        auto r = command({"EXPIRE", key, std::to_string(seconds)});
        return r && r->kind == Reply::INTEGER && r->integer == 1;
    }

private:
    struct Reply {
        enum Kind { STATUS, ERROR, INTEGER, BULK, ARRAY } kind = STATUS;
        std::string status;   // STATUS / ERROR 文本
        int64_t integer = 0;
        std::optional<std::string> bulk;
        std::vector<std::string> arr;  // ARRAY（批量字符串）
        std::string asString() const { return kind == BULK ? (bulk.value_or("")) : status; }
    };

    int fd_ = -1;
    int timeoutMs_ = 2000;

    bool sendAll(const char* data, size_t n) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = ::send(fd_, data + off, n - off, MSG_NOSIGNAL);
            if (w <= 0) { if (errno == EINTR) continue; return false; }
            off += (size_t)w;
        }
        return true;
    }

    // 发送 RESP 命令：*N\r\n$len\r\narg\r\n ...
    bool sendCmd(const std::vector<std::string>& args) {
        std::string buf;
        buf += "*" + std::to_string(args.size()) + "\r\n";
        for (auto& a : args) {
            buf += "$" + std::to_string(a.size()) + "\r\n";
            buf += a;
            buf += "\r\n";
        }
        return sendAll(buf.data(), buf.size());
    }

    bool readExact(char* dst, size_t n) {
        size_t off = 0;
        while (off < n) {
            if (!waitReadable()) return false;
            ssize_t r = ::recv(fd_, dst + off, n - off, 0);
            if (r <= 0) { if (errno == EINTR) continue; return false; }
            off += (size_t)r;
        }
        return true;
    }

    // 读到一行（不含 \r\n）
    bool readLine(std::string& out) {
        out.clear();
        char c;
        while (true) {
            if (!readExact(&c, 1)) return false;
            if (c == '\r') {
                if (!readExact(&c, 1)) return false;  // consume \n
                return true;
            }
            out.push_back(c);
        }
    }

    bool waitReadable() {
        // 使用 poll：select 的 fd_set 上限 1024，后台重连时 fd 可能更高导致进程 abort
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int pr = ::poll(&pfd, 1, timeoutMs_);
        if (pr <= 0) return false;
        // 出错/挂断也返回，交由随后的 recv 得到 0/-1 走失败分支
        return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
    }

    std::optional<Reply> readReply() {
        std::string line;
        if (!readLine(line) || line.empty()) return std::nullopt;
        Reply rep;
        char t = line[0];
        std::string body = line.substr(1);
        if (t == '+') { rep.kind = Reply::STATUS; rep.status = body; return rep; }
        if (t == '-') { rep.kind = Reply::ERROR; rep.status = body; return rep; }
        if (t == ':') { rep.kind = Reply::INTEGER; rep.integer = std::atoll(body.c_str()); return rep; }
        if (t == '$') {
            long len = std::atol(body.c_str());
            if (len < 0) { rep.kind = Reply::BULK; rep.bulk = std::nullopt; return rep; }  // nil
            std::string s((size_t)len, '\0');
            if (len > 0 && !readExact(&s[0], (size_t)len)) return std::nullopt;
            char crlf[2];
            if (!readExact(crlf, 2)) return std::nullopt;  // 尾部 \r\n
            rep.kind = Reply::BULK;
            rep.bulk = std::move(s);
            return rep;
        }
        if (t == '*') {
            long count = std::atol(body.c_str());
            rep.kind = Reply::ARRAY;
            if (count < 0) return rep;  // nil array
            for (long i = 0; i < count; ++i) {
                auto elem = readReply();
                if (!elem) return std::nullopt;
                if (elem->kind == Reply::BULK) rep.arr.push_back(elem->bulk.value_or(""));
                else if (elem->kind == Reply::STATUS) rep.arr.push_back(elem->status);
                else rep.arr.push_back(std::to_string(elem->integer));
            }
            return rep;
        }
        return std::nullopt;
    }

    std::optional<Reply> command(const std::vector<std::string>& args) {
        if (fd_ < 0) return std::nullopt;
        if (!sendCmd(args)) return std::nullopt;
        return readReply();
    }
};

}  // namespace novawaf
