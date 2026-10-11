// NovaWAF - Linux 检测引擎主程序
// 多 Reactor (SO_REUSEPORT) + epoll + 检测流水线 + 限流器
// 编译: 见 CMakeLists.txt (Linux, g++/clang++ C++20)
#include "novawaf/core/buffer.h"
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/thread_pool.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/http_transport.h"

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
#include <cstdlib>
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
                        RateLimiter& limiter, DdosGuard& ddos,
                        const std::shared_ptr<AiDetector>& ai, int idx) {
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
                    // DDoS 防护：取源 IP，检查并发上限/连接速率/黑名单
                    char ipstr[32] = {0};
                    inet_ntop(AF_INET, &caddr.sin_addr, ipstr, sizeof(ipstr));
                    if (!ddos.onConnect(ipstr)) {
                        close(cfd);  // 直接丢弃，不消耗应用层资源
                        continue;
                    }
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
                {
                    // 解析 + 检测（独立块作用域，变量不越过 goto 标签）
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
                    if (!ddos.onRequest(req.clientIp)) {
                        // 请求速率超限 → 触发封禁链路，返回 429
                        resp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                    } else if (!limiter.allow(req.clientIp)) {
                        resp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                    } else {
                        DetectionResult dr = detectWithAiReview(pipeline, ai, req);
                        if (dr.isBlocked()) {
                            std::printf("[reactor %d] BLOCK %s from %s: %s\n",
                                        idx, dr.category.c_str(), ipstr, dr.matched.c_str());
                            resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                   "Content-Length: 52\r\n\r\n"
                                   "<html><body>Blocked by NovaWAF</body></html>";
                        } else {
                            resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        }
                    }
                    ssize_t w = write(fd, resp, strlen(resp));
                    (void)w;
                }
            closefd:
                {
                    // 释放 DDoS 并发连接计数
                    char ipstr[32] = {0};
                    sockaddr_in peer{};
                    socklen_t plen = sizeof(peer);
                    if (getpeername(fd, (sockaddr*)&peer, &plen) == 0) {
                        inet_ntop(AF_INET, &peer.sin_addr, ipstr, sizeof(ipstr));
                        ddos.onDisconnect(ipstr);
                    }
                }
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

    // DDoS / 网络攻击防护配置
    DdosGuard::Config ddosCfg;
    ddosCfg.maxConcurrentPerIp = 200;   // 单 IP 并发连接上限
    ddosCfg.newConnPerSec       = 200;  // 单 IP 新建连接速率
    ddosCfg.reqPerSec           = 1000; // 单 IP 请求速率
    ddosCfg.slowTimeoutMs       = 5000; // 慢速攻击判定超时
    ddosCfg.banThreshold        = 5;    // 违规 5 次触发封禁
    ddosCfg.banSeconds          = 300;  // 封禁 5 分钟，到期自动解封
    DdosGuard ddos(ddosCfg);

    // ---- AI 大模型二阶复核（可指向本地模型或外部 API，不可用则自动降级）----
    // 配置来源：环境变量。未配置 NOVAAI_ENABLE=1 时 AI 完全不启用，引擎=纯规则。
    LlmConfig llmCfg;
    llmCfg.enabled = (getenv("NOVAAI_ENABLE") && std::string(getenv("NOVAAI_ENABLE")) == "1");
    if (const char* e = getenv("NOVAAI_ENDPOINT")) llmCfg.endpoint = e;
    if (const char* e = getenv("NOVAAI_APIKEY"))   llmCfg.apiKey = e;
    if (const char* e = getenv("NOVAAI_MODEL"))    llmCfg.model = e;
    if (const char* e = getenv("NOVAAI_TIMEOUT_MS")) llmCfg.timeoutMs = std::atoi(e);
    auto llm = std::make_shared<LlmClient>(llmCfg, makeHttpTransport(llmCfg));
    auto ai = std::make_shared<AiDetector>(llm);

    std::printf("NovaWAF engine starting on port %d with %d reactors\n", port, threads);
    std::printf("  DDoS guard: maxConn=%d newConn/s=%d req/s=%d ban=%ds\n",
                ddosCfg.maxConcurrentPerIp, ddosCfg.newConnPerSec,
                ddosCfg.reqPerSec, ddosCfg.banSeconds);
    std::printf("  AI review: %s model=%s endpoint=%s timeout=%dms\n",
                llmCfg.enabled ? "ENABLED" : "disabled(pure-rules)",
                llmCfg.model.c_str(), llmCfg.endpoint.c_str(), llmCfg.timeoutMs);
    std::vector<std::thread> reactors;
    for (int i = 0; i < threads; ++i) {
        int lfd = createListenFd(port, 4096);
        if (lfd < 0) { std::perror("listen"); return 1; }
        reactors.emplace_back(reactorLoop, lfd, std::ref(pipeline),
                              std::ref(limiter), std::ref(ddos), ai, i);
    }
    for (auto& t : reactors) t.join();
    return 0;
}
