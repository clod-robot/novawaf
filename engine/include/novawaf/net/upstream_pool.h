// NovaWAF - 上游连接池（享元/对象池模式）
// 按 "host:port" 复用 keep-alive 连接，减少高并发下反复 connect 的开销。
// acquire 时对复用连接做非阻塞存活探测，失效则自动新建，保证正确性。
#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {

class UpstreamPool {
public:
    UpstreamPool() = default;
    ~UpstreamPool() { stop(); }

    // 取一条到 host:port 的连接：优先复用池内空闲连接，否则新建。失败返回 -1。
    int acquire(const std::string& host, int port) {
        const std::string key = makeKey(host, port);
        int fd = -1;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = idle_.find(key);
            if (it != idle_.end() && !it->second.empty()) {
                fd = it->second.back();
                it->second.pop_back();
            }
        }
        if (fd >= 0) {
            if (isAlive(fd)) return fd;   // 连接健康，直接复用
            ::close(fd);                   // 上游已关闭/异常，丢弃后新建
        }
        return openConn(host, port);
    }

    // 归还一条健康连接以备后续复用
    void release(const std::string& host, int port, int fd) {
        if (fd < 0) return;
        std::lock_guard<std::mutex> lk(mtx_);
        idle_[makeKey(host, port)].push_back(fd);
    }

    // 丢弃一条损坏连接（直接关闭，不复用）
    void discard(int fd) {
        if (fd >= 0) ::close(fd);
    }

    void stop() {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& kv : idle_)
            for (int fd : kv.second) ::close(fd);
        idle_.clear();
    }

private:
    static std::string makeKey(const std::string& h, int p) {
        return h + ":" + std::to_string(p);
    }

    // 非阻塞 peek 探测连接是否仍存活：true=可复用
    static bool isAlive(int fd) {
        char b;
        ssize_t n = ::recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
        if (n > 0) return false;        // 残留数据（异常），不复用
        if (n == 0) return false;       // EOF：上游已关闭
        return errno == EAGAIN || errno == EWOULDBLOCK;  // 无数据=健康
    }

    // 新建到上游的连接（带收发超时）
    int openConn(const std::string& host, int port) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
            return -1;
        int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { freeaddrinfo(res); return -1; }
        timeval tv{5, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        timeval rtv{3, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
        bool ok = (::connect(fd, res->ai_addr, res->ai_addrlen) == 0);
        freeaddrinfo(res);
        if (!ok) { ::close(fd); return -1; }
        return fd;
    }

    std::mutex mtx_;
    std::unordered_map<std::string, std::vector<int>> idle_;
};

}  // namespace novawaf
