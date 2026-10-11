// NovaWAF - Linux 检测引擎主程序
// 多 Reactor (SO_REUSEPORT) + epoll + 检测流水线 + 限流器
// 编译: 见 CMakeLists.txt (Linux, g++/clang++ C++20)
#include "novawaf/core/buffer.h"
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/thread_pool.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace novawaf;

static std::atomic<bool> g_running{true};

static int createListenFd(int port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, backlog) < 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static void setNonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

// 单 Reactor 线程：监听 + 读请求 + 检测 + 简单回包（演示版）
static void reactorLoop(int listenFd, DetectionPipeline& pipeline,
                        RateLimiter& limiter, int idx) {
    int epfd = epoll_create1(0);
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listenFd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenFd, &ev);

    std::vector<epoll_event> events(1024);
    std::printf("[reactor %d] started\n", idx);

    while (g_running) {
        int n = epoll_wait(epfd, events.data(), (int)events.size(), 200);
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == listenFd) {
                while (true) {
                    sockaddr_in caddr{};
                    socklen_t clen = sizeof(caddr);
                    int cfd = accept(listenFd, (sockaddr*)&caddr, &clen);
                    if (cfd < 0) break;
                    setNonblock(cfd);
                    epoll_event ce{};
                    ce.events = EPOLLIN | EPOLLET;
                    ce.data.fd = cfd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ce);
                }
            } else {
                char buf[8192];
                std::string data;
                while (true) {
                    ssize_t r = read(fd, buf, sizeof(buf));
                    if (r > 0) data.append(buf, r);
                    else if (r == 0 || (r < 0 && errno != EAGAIN)) { goto closefd; }
                    else break;
                }
                // 解析 + 检测
                HttpParser parser;
                parser.feed(data);
                HttpRequest req = parser.request();
                char ipstr[32] = {0};
                sockaddr_in peer{};
                socklen_t plen = sizeof(peer);
                getpeername(fd, (sockaddr*)&peer, &plen);
                inet_ntop(AF_INET, &peer.sin_addr, ipstr, sizeof(ipstr));
                req.clientIp = ipstr;

                const char* resp;
                if (!limiter.allow(req.clientIp)) {
                    resp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                } else {
                    DetectionResult r = pipeline.detect(req);
                    if (r.isBlocked()) {
                        std::printf("[reactor %d] BLOCK %s from %s: %s\n",
                                    idx, r.category.c_str(), ipstr, r.matched.c_str());
                        resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                               "Content-Length: 52\r\n\r\n"
                               "<html><body>Blocked by NovaWAF</body></html>";
                    } else {
                        resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    }
                }
                write(fd, resp, strlen(resp));
            closefd:
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                close(fd);
            }
        }
    }
    close(epfd);
}

int main(int argc, char** argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    int threads = (argc > 2) ? atoi(argv[2]) : (int)std::thread::hardware_concurrency();
    signal(SIGPIPE, SIG_IGN);

    DetectionPipeline pipeline;
    RateLimiter limiter(100, 1000);  // 每 IP 突发 100，每秒补 1000

    std::printf("NovaWAF engine starting on port %d with %d reactors\n", port, threads);
    std::vector<std::thread> reactors;
    for (int i = 0; i < threads; ++i) {
        int lfd = createListenFd(port, 4096);
        if (lfd < 0) { std::perror("listen"); return 1; }
        reactors.emplace_back(reactorLoop, lfd, std::ref(pipeline),
                              std::ref(limiter), i);
    }
    for (auto& t : reactors) t.join();
    return 0;
}
