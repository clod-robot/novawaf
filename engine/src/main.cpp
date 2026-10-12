// NovaWAF - Linux 检测引擎主程序
// 多 Reactor (SO_REUSEPORT) + epoll + 检测流水线 + 限流器
// 编译: 见 CMakeLists.txt (Linux, g++/clang++ C++20)
#include "novawaf/core/buffer.h"
#include "novawaf/core/app_registry.h"
#include "novawaf/core/event_sink.h"
#include "novawaf/core/traffic_sink.h"
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/core/redis_client.h"
#include "novawaf/core/thread_pool.h"
#include "novawaf/core/event_bus.h"
#include "novawaf/net/upstream_forwarder.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/detect/custom_rules.h"
#include "novawaf/detect/threat_intel.h"
#include "novawaf/detect/ransomware_detector.h"
#include "novawaf/av/clamav_client.h"
#include "novawaf/av/yara_detector.h"
#include "novawaf/av/magic_detector.h"
#include "novawaf/av/external_intel.h"
#include "novawaf/fw/fw_ban.h"
#include "novawaf/protect/cc_guard.h"
#include "novawaf/protect/bot_guard.h"
#include "novawaf/protect/dynamic_shield.h"
#include "novawaf/protect/fingerprint.h"
#include "novawaf/protect/geo_filter.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/http_transport.h"

#include <fstream>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace novawaf;

static std::atomic<bool> g_running{true};

// 异步上游转发器（独立 IO 线程池），在 main 中初始化；
// reactor 对放行请求优先提交给它转发，避免阻塞 reactor 线程。
static std::shared_ptr<UpstreamForwarder> g_upstream;

// 态势统计：拦截事件发布到事件总线（观察者模式），由各订阅者异步消费，热路径不阻塞
static void emitEvt(const std::string& ip, const std::string& cat,
                    const std::string& action, const std::string& ruleId,
                    const std::string& matched) {
    AttackEvent e;
    e.ts = (int64_t)std::time(nullptr);
    e.ip = ip; e.category = cat; e.action = action; e.ruleId = ruleId; e.matched = matched;
    EventBus<AttackEvent>::instance().publish(e);
}

// 拆分逗号分隔字符串（用于 NOVA_GEO_BLOCK=CN,RU 等环境变量）
static std::vector<std::string> splitCsvStr(const char* s) {
    std::vector<std::string> out;
    std::string cur;
    for (const char* p = s; *p; ++p) {
        if (*p == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += *p;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// 把一段文本按行切分（用于 Redis 返回的整文件内容）
static std::vector<std::string> splitLines(const std::string& blob) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : blob) {
        if (c == '\n') { lines.push_back(cur); cur.clear(); }
        else if (c != '\r') cur += c;
    }
    if (!cur.empty()) lines.push_back(cur);
    return lines;
}

// 加载数据行：优先 Redis（NOVA_REDIS_HOST 配置时），失败/未配置回退本地文件。
// redisKey     : Redis 中存整文件内容的 STRING 键，如 "novawaf:geoip"
// cksumField   : novawaf:meta 哈希中记录 cksum 的字段，如 "geoip_cksum"
// filePath     : 回退用的本地文件路径
// inoutCksum   : 上次加载的 cksum，未变则返回空（调用方据此跳过重解析）
// outFromRedis : 输出本次是否来自 Redis
static std::vector<std::string> loadDataLines(const char* redisKey,
                                              const char* cksumField,
                                              const std::string& filePath,
                                              std::string& inoutCksum,
                                              bool& outFromRedis) {
    outFromRedis = false;
    const char* rh = getenv("NOVA_REDIS_HOST");
    if (rh && *rh) {
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (r.connect(rh, port, pass ? pass : "", db)) {
            auto cs = r.hget("novawaf:meta", cksumField);
            if (cs && !cs->empty() && *cs == inoutCksum) {
                outFromRedis = true;
                return {};  // 内容未变，无需重解析
            }
            auto blob = r.get(redisKey);
            if (blob) {
                inoutCksum = cs.value_or("");
                outFromRedis = true;
                return splitLines(*blob);
            }
            // Redis 连通但无该键：回退文件
        }
        // 连接失败：回退文件，保证可用性
    }
    std::ifstream in(filePath);
    if (!in) return {};
    std::vector<std::string> lines;
    std::string ln;
    while (std::getline(in, ln)) lines.push_back(ln);
    return lines;
}

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

// 解析 "host:port" → host, port
static bool parseHostPort(const std::string& s, std::string& host, int& port) {
    auto c = s.rfind(':');
    if (c == std::string::npos) return false;
    host = s.substr(0, c);
    port = atoi(s.substr(c + 1).c_str());
    return !host.empty() && port > 0;
}

// 真实反向代理：把原始请求字节转发到上游，读回完整响应填入 outResp。
// 失败（连不上/超时/空响应）返回 false，调用方应返回 502。
static bool forwardToUpstream(const std::string& host, int port,
                              const std::string& reqBytes, std::string& outResp) {
    outResp.clear();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) return false;
    int ufd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ufd < 0) { freeaddrinfo(res); return false; }
    timeval tv{5, 0};
    setsockopt(ufd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    timeval rtv{3, 0};
    setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
    bool ok = false;
    if (connect(ufd, res->ai_addr, res->ai_addrlen) == 0) {
        size_t sent = 0;
        while (sent < reqBytes.size()) {
            ssize_t n = send(ufd, reqBytes.data() + sent, reqBytes.size() - sent, 0);
            if (n <= 0) break;
            sent += (size_t)n;
        }
        if (sent == reqBytes.size()) {
            char buf[8192];
            size_t headerEnd = std::string::npos;
            long long contentLen = -1;
            bool chunked = false;
            while (true) {
                ssize_t n = recv(ufd, buf, sizeof(buf), 0);
                if (n > 0) outResp.append(buf, (size_t)n);
                else break;
                if (headerEnd == std::string::npos) {
                    auto pos = outResp.find("\r\n\r\n");
                    if (pos != std::string::npos) {
                        headerEnd = pos;
                        std::string hdrs = outResp.substr(0, pos);
                        for (auto& ch : hdrs) ch = (char)tolower((unsigned char)ch);
                        if (hdrs.find("transfer-encoding:") != std::string::npos &&
                            hdrs.find("chunked") != std::string::npos) chunked = true;
                        auto cl = hdrs.find("\ncontent-length:");
                        if (cl != std::string::npos) {
                            auto eol = hdrs.find('\r', cl); if (eol == std::string::npos) eol = hdrs.size();
                            contentLen = atoll(hdrs.substr(cl + 16, eol - cl - 16).c_str());
                        }
                    }
                }
                if (chunked) {
                    // 结束块 "0\r\n\r\n" 已到达即可返回，避免阻塞到 3s 超时
                    if (outResp.size() >= 5 &&
                        outResp.compare(outResp.size() - 5, 5, "0\r\n\r\n") == 0) { ok = true; break; }
                } else if (headerEnd != std::string::npos && contentLen >= 0) {
                    size_t bodyHave = outResp.size() - (headerEnd + 4);
                    if ((long long)bodyHave >= contentLen) { ok = true; break; }
                }
            }
            ok = ok || !outResp.empty();
        }
    }
    close(ufd);
    freeaddrinfo(res);
    return ok && !outResp.empty();
}

// 生成不可预测的 session id（16 字节随机 → hex）
static std::string genSid() {
    static std::atomic<unsigned> ctr{0};
    unsigned char buf[16];
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { size_t rd = fread(buf, 1, sizeof(buf), f); fclose(f); if (rd != sizeof(buf)) {
        for (int i = 0; i < 16; ++i) buf[i] = (unsigned char)(rand() ^ (ctr.fetch_add(1) * 2654435761u)); } }
    else { for (int i = 0; i < 16; ++i) buf[i] = (unsigned char)(rand() ^ (ctr.fetch_add(1) * 2654435761u)); }
    static const char* hx = "0123456789abcdef";
    std::string s; s.reserve(32);
    for (int i = 0; i < 16; ++i) { s += hx[buf[i] >> 4]; s += hx[buf[i] & 0xf]; }
    return s;
}
// 从请求头提取 novasid
static std::string getCookieSid(const std::unordered_map<std::string,std::string>& headers) {
    for (auto& [k, v] : headers) {
        std::string lk = k; for (auto& c : lk) c = (char)tolower((unsigned char)c);
        if (lk == "cookie") {
            size_t p = 0;
            while (p < v.size()) {
                size_t sc = v.find(';', p);
                std::string kv = (sc == std::string::npos) ? v.substr(p) : v.substr(p, sc - p);
                size_t a = 0; while (a < kv.size() && isspace((unsigned char)kv[a])) ++a;
                if (kv.compare(a, 7, "novasid") == 0) {
                    size_t eq = kv.find('=', a);
                    if (eq != std::string::npos) return kv.substr(eq + 1);
                }
                if (sc == std::string::npos) break;
                p = sc + 1;
            }
        }
    }
    return "";
}
// 在响应首行后注入一个响应头
static void injectHeader(std::string& resp, const std::string& headerLine) {
    auto p = resp.find("\r\n");
    if (p != std::string::npos) resp.insert(p + 2, headerLine + "\r\n");
}
// 从响应首行解析状态码（"HTTP/1.1 200 OK" → 200）
static int respStatus(const std::string& resp) {
    auto p = resp.find(' ');
    if (p == std::string::npos) return 0;
    auto p2 = resp.find(' ', p + 1);
    return std::atoi(resp.substr(p + 1, p2 == std::string::npos ? std::string::npos : p2 - p - 1).c_str());
}
// 大小写不敏感取请求头
static std::string hdrCi(const HttpRequest& req, const std::string& key) {
    for (auto& kv : req.headers) {
        if (kv.first.size() != key.size()) continue;
        bool eq = true;
        for (size_t i = 0; i < key.size(); ++i)
            if (std::tolower((unsigned char)kv.first[i]) != std::tolower((unsigned char)key[i])) { eq = false; break; }
        if (eq) return kv.second;
    }
    return {};
}

// 单 Reactor 线程：监听 + 读请求 + 检测 + 简单回包（演示版）
static void reactorLoop(int listenFd, DetectionPipeline& pipeline,
                        RateLimiter& limiter, DdosGuard& ddos,
                        const std::shared_ptr<AiDetector>& ai,
                        CcGuard& cc, BotGuard& bot,
                        const std::shared_ptr<ThreatIntel>& ti,
                        DynamicShield& shield, GeoFilter& geo, int idx) {
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
                    // 若位于反向代理/CDN 之后，真实客户端 IP 在 X-Forwarded-For / X-Real-IP
                    // 取最左侧（原始）IP，用于地理围栏等基于真实来源的判定
                    for (auto& [k, v] : req.headers) {
                        std::string lk = k;
                        for (auto& c : lk) c = (char)tolower((unsigned char)c);
                        if (lk == "x-forwarded-for" || lk == "x-real-ip") {
                            std::string ff = v;
                            auto comma = ff.find(',');
                            if (comma != std::string::npos) ff = ff.substr(0, comma);
                            // trim
                            size_t a = 0; while (a < ff.size() && isspace((unsigned char)ff[a])) a++;
                            ff = ff.substr(a);
                            if (!ff.empty()) { req.clientIp = ff; break; }
                        }
                    }

                    // 会话：无 novasid 则生成，响应时注入 Set-Cookie（用于 UV 去重）
                    std::string sid = getCookieSid(req.headers);
                    bool newSess = sid.empty();
                    if (newSess) sid = genSid();

                    // 按 Host 选应用（流量归属 + 上游选择）
                    std::string hostHdr;
                    for (auto& [k, v] : req.headers) {
                        std::string lk = k; for (auto& c : lk) c = (char)tolower((unsigned char)c);
                        if (lk == "host") { hostHdr = v; break; }
                    }
                    auto apps = app_reg::current();
                    const App* app = apps ? app_reg::select(*apps, hostHdr) : nullptr;
                    std::string appId = app ? app->id : "";
                    int appMode = app ? app->mode : 0; // 0防护 1观察 2维护
                    // 维护页（静态，仅构造一次）
                    static const std::string kMaint = []{
                        std::string b = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>系统维护中</title>"
                          "<style>body{margin:0;background:#0b1020;color:#9fc4e8;font-family:sans-serif;display:flex;"
                          "align-items:center;justify-content:center;height:100vh}h1{color:#00e5ff;font-size:28px}"
                          "p{color:#6c8bb0}.d span{display:inline-block;width:10px;height:10px;background:#00e5ff;"
                          "border-radius:50%;margin:0 4px;animation:b 1.2s infinite}@keyframes b{0%,80%,100%{opacity:.2}"
                          "40%{opacity:1}}</style></head><body><div style=\"text-align:center\">"
                          "<h1>系统维护中</h1><p>应用正在维护，请稍后再访问</p>"
                          "<div class=\"d\"><span></span><span></span><span></span></div></div></body></html>";
                        return "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\n"
                               "Content-Length: " + std::to_string(b.size()) + "\r\nConnection: close\r\n\r\n" + b;
                    }();
                    bool tBlocked = false, tAttack = false;

                    std::string outResp;
                    bool asyncHandled = false;  // 异步转发器接管后，reactor 跳过回写与关闭
                    // 转发到上游：异步优先，失败回退同步；返回 true 表示已由异步 IO 接管
                    auto forwardToApp = [&]() -> bool {
                        static const std::string k502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        if (app && g_upstream) {
                            UpstreamForwarder::Ctx ctx;
                            ctx.clientFd = fd; ctx.data = data;
                            ctx.upstreamHost = app->upstreamHost; ctx.upstreamPort = app->upstreamPort;
                            ctx.clientIp = req.clientIp; ctx.newSess = newSess; ctx.sid = sid;
                            ctx.appId = appId; ctx.statsEnabled = app->statsEnabled; ctx.reactorIdx = idx;
                            ctx.ua = hdrCi(req, "User-Agent"); ctx.host = hdrCi(req, "Host");
                            ctx.path = req.path; ctx.referer = hdrCi(req, "Referer");
                            ctx.country = geo.country(req.clientIp);
                            if (g_upstream->submit(std::move(ctx))) {
                                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                                return true;
                            }
                        }
                        if (app && forwardToUpstream(app->upstreamHost, app->upstreamPort, data, outResp)) return false;
                        outResp = k502;
                        return false;
                    };
                    if (appMode == 2) {
                        // 维护模式：所有请求返回维护页，不检测、不转发
                        outResp = kMaint;
                    } else if (!ddos.onRequest(req.clientIp)) {
                        // 请求速率超限 → 触发封禁链路，返回 429
                        outResp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                        shield.recordBlock();
                        emitEvt(req.clientIp, "DDoS", "block", "", "conn/rate limit");
                        FwBanPoster::instance()->enqueue(req.clientIp, "DDoS", "rate");
                        tBlocked = true;
                    } else if (!limiter.allow(req.clientIp)) {
                        outResp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                        shield.recordBlock();
                        emitEvt(req.clientIp, "RateLimit", "block", "", "rate limit");
                        FwBanPoster::instance()->enqueue(req.clientIp, "RateLimit", "rate");
                        tBlocked = true;
                    } else {
                        // 动态防护统计
                        shield.recordRequest();
                        shield.recordIp(req.clientIp);

                        // 指纹（JA4 由前置层通过 X-JA4 透传；HTTP 指纹本地计算）
                        std::string ja4, httpFp;
                        for (auto& [k, v] : req.headers) {
                            std::string lk = k;
                            for (auto& c : lk) c = (char)tolower((unsigned char)c);
                            if (lk == "x-ja4") { ja4 = v; }
                        }
                        httpFp = httpFingerprint(req.method, req.headers);

                        // 威胁情报：指纹/IP/路径/UA/签名 黑名单
                        bool blocked = false;
                        if (ti) {
                            auto tr = ti->match(req, ja4, httpFp);
                            if (tr && tr->isBlocked()) {
                                std::printf("[reactor %d] BLOCK TI-%s from %s: %s\n",
                                            idx, tr->category.c_str(), ipstr, tr->matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 52\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, tr->category, "block", tr->ruleId, tr->matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // CC 攻击防护
                        if (!blocked) {
                            // 地理位置拦截（GeoIP 地理围栏）
                            auto gr = geo.assess(req.clientIp);
                            if (gr && gr->isBlocked()) {
                                std::printf("[reactor %d] BLOCK Geo from %s: %s\n",
                                            idx, ipstr, gr->matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 52\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, "Geo", "block", gr->ruleId, gr->matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        if (!blocked) {
                            DetectionResult cr = cc.assess(req.clientIp, req.path);
                            if (cr.action != Action::PASS) {
                                std::printf("[reactor %d] %s CC from %s: %s\n",
                                            idx, cr.action == Action::BLOCK ? "BLOCK" : "CHAL",
                                            ipstr, cr.matched.c_str());
                                outResp = (cr.action == Action::BLOCK)
                                       ? "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 52\r\n\r\n"
                                         "<html><body>Blocked by NovaWAF</body></html>"
                                       : "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 0\r\n\r\n";
                                if (cr.action == Action::BLOCK) shield.recordBlock();
                                emitEvt(req.clientIp, "CC", cr.action == Action::BLOCK ? "block" : "challenge", cr.ruleId, cr.matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // Bot 行为防护
                        if (!blocked) {
                            DetectionResult br = bot.assess(req, ja4);
                            if (br.action != Action::PASS) {
                                std::printf("[reactor %d] %s Bot from %s: %s\n",
                                            idx, br.action == Action::BLOCK ? "BLOCK" : "CHAL",
                                            ipstr, br.matched.c_str());
                                outResp = (br.action == Action::BLOCK)
                                       ? "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 52\r\n\r\n"
                                         "<html><body>Blocked by NovaWAF</body></html>"
                                       : "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 0\r\n\r\n";
                                if (br.action == Action::BLOCK) shield.recordBlock();
                                emitEvt(req.clientIp, "Bot", br.action == Action::BLOCK ? "block" : "challenge", br.ruleId, br.matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // 规则 + AI 二阶复核
                        if (!blocked) {
                            DetectionResult dr = detectWithAiReview(pipeline, ai, req);
                            if (dr.isBlocked()) {
                                std::printf("[reactor %d] BLOCK %s from %s: %s\n",
                                            idx, dr.category.c_str(), ipstr, dr.matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 52\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, dr.category, "block", dr.ruleId, dr.matched);
                                tBlocked = true; tAttack = true;
                            } else {
                                asyncHandled = forwardToApp();
                            }
                        }
                    }
                    // 观察模式：命中攻击仅记录事件(tAttack 已置位)，不拦截、不封禁，仍转发上游
                    if (appMode == 1 && tAttack && app) {
                        tBlocked = false;
                        asyncHandled = forwardToApp();
                    }
                    if (asyncHandled) {
                        // fd 已交由异步转发器回写并关闭，reactor 直接处理下一事件
                        continue;
                    }
                    // 确认攻击命中 → 投递防火墙联动封禁（观察模式只记录不封禁）
                    if (tAttack && appMode != 1) FwBanPoster::instance()->enqueue(req.clientIp, "WAF", "attack");
                    if (newSess && !outResp.empty())
                        injectHeader(outResp, "Set-Cookie: novasid=" + sid + "; Path=/; HttpOnly");
                    // 流量统计埋点（仅已启用统计的应用；热路径入队不阻塞）
                    if (app && app->statsEnabled) {
                        TrafficReq tr;
                        tr.ts = (int64_t)std::time(nullptr);
                        tr.appId = appId; tr.status = respStatus(outResp);
                        tr.blocked = tBlocked; tr.attack = tAttack;
                        tr.ip = req.clientIp; tr.sid = sid;
                        tr.ua = hdrCi(req, "User-Agent");
                        tr.host = hdrCi(req, "Host");
                        tr.path = req.path;
                        tr.referer = hdrCi(req, "Referer");
                        tr.country = geo.country(req.clientIp);
                        TrafficSink::instance().emit(std::move(tr));
                    }
                    ssize_t w = write(fd, outResp.data(), outResp.size());
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

    // 态势统计事件汇聚（异步写 Redis，可视化大屏数据源）
    EventSink::instance().start();
    TrafficSink::instance().start();

    DetectionPipeline pipeline;
    RateLimiter limiter(100, 1000);  // 每 IP 突发 100，每秒补 1000

    // ---- 威胁情报 IOC：优先从 Redis 加载（免磁盘 IO），失败回退文件，支持热更新 ----
    auto threatIntel = std::make_shared<ThreatIntel>(TiSeverity::HIGH);
    const char* iocFile = getenv("NOVA_IOC_FILE");
    std::string iocPath = iocFile ? iocFile : "rules/ioc.txt";
    auto iocCksum = std::make_shared<std::string>();  // 跨线程共享的 cksum 状态
    auto loadIoc = [threatIntel, iocPath, iocCksum](bool initial) -> size_t {
        bool fromRedis = false;
        auto lines = loadDataLines("novawaf:ioc", "ioc_cksum", iocPath, *iocCksum, fromRedis);
        if (lines.empty() && !fromRedis) return 0;          // 文件不存在
        if (lines.empty() && fromRedis) return (size_t)-1;   // Redis 内容未变，跳过重解析
        size_t n = threatIntel->loadFromLines(lines);
        if (initial)
            std::printf("  IOC: loaded %zu entries from %s\n", n, fromRedis ? "redis" : iocPath.c_str());
        else
            std::printf("  IOC: hot-reloaded %zu entries from %s\n", n, fromRedis ? "redis" : iocPath.c_str());
        return n;
    };
    size_t iocN = loadIoc(true);
    pipeline.addDetector(std::make_unique<TiDetector>(threatIntel));
    pipeline.addDetector(std::make_unique<RansomwareDetector>());
    pipeline.addDetector(std::make_unique<MagicDetector>());
    pipeline.addDetector(std::make_unique<YaraDetector>());
    pipeline.addDetector(std::make_unique<ClamavDetector>());
    pipeline.addDetector(std::make_unique<ExternalIntelDetector>());
    // 后台定时刷新线程（每 60s 从 Redis/文件重读；cksum 未变则跳过重解析）
    std::thread([threatIntel, iocPath, loadIoc]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (!g_running) break;
            loadIoc(false);  // copy-on-write 原子替换，不阻塞检测
        }
    }).detach();

    // ---- 控制台自定义规则：从 Redis 键 novawaf:rules 热加载（JSON），闭环管理控制台 -> 引擎 ----
    auto customRules = std::make_shared<CustomRuleDetector>();
    // 读 Redis 原始 STRING 值（含读取版本号做脏检查，未变则跳过重解析）
    auto readRulesBlob = [](std::string& inoutVersion, bool& outChanged) -> std::optional<std::string> {
        outChanged = false;
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return std::nullopt;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return std::nullopt;
        auto ver = r.get("novawaf:rules:version");
        std::string cur = ver.value_or("");
        if (cur == inoutVersion) return std::nullopt;  // 版本未变
        auto blob = r.get("novawaf:rules");
        if (!blob) return std::nullopt;
        inoutVersion = cur;
        outChanged = true;
        return blob;
    };
    auto rulesVersion = std::make_shared<std::string>("-");
    auto loadRules = [customRules, readRulesBlob, rulesVersion](bool initial) -> size_t {
        bool changed = false;
        auto blob = readRulesBlob(*rulesVersion, changed);
        if (!blob) return initial ? customRules->reload("") : (size_t)-1;  // -1 = 无变化
        size_t n = customRules->reload(*blob);
        std::printf("  CustomRules: %s %zu rules from redis\n",
                    initial ? "loaded" : "hot-reloaded", n);
        return n;
    };
    loadRules(true);
    pipeline.addDetector(std::unique_ptr<CustomRuleDetector>(
        static_cast<CustomRuleDetector*>(customRules->clone().release())));
    int rulesInterval = getenv("NOVA_RULES_INTERVAL") ? atoi(getenv("NOVA_RULES_INTERVAL")) : 60;
    std::thread([loadRules, rulesInterval]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(rulesInterval));
            if (!g_running) break;
            loadRules(false);
        }
    }).detach();

    // ---- 应用表：从 Redis novawaf:apps 热加载（copy-on-write），供按 Host 选上游 ----
    auto applyApps = [](const std::string& blob) {
        auto apps = std::make_shared<AppTable>(app_reg::parseApps(blob));
        // 回退：Redis 无配置时，用 NOVA_UPSTREAM 合成一个默认应用，保证引擎仍可代理
        if (apps->empty()) {
            const char* up = getenv("NOVA_UPSTREAM");
            std::string h; int p = 0;
            if (up && *up && parseHostPort(up, h, p)) {
                App a; a.id = "default"; a.name = "default"; a.host = "";
                a.upstreamHost = h; a.upstreamPort = p; a.isDefault = true; a.statsEnabled = true;
                apps->push_back(std::move(a));
            }
        }
        app_reg::set(apps);
        std::printf("  Apps: loaded %zu app(s)\n", apps->size());
    };
    auto appsVersion = std::make_shared<std::string>("-");
    auto loadApps = [applyApps, appsVersion](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) { if (initial) applyApps(""); return; }
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) { if (initial) applyApps(""); return; }
        auto ver = r.get("novawaf:apps:version");
        std::string cur = ver.value_or("");
        if (cur == *appsVersion && !initial) return;
        auto blob = r.get("novawaf:apps");
        *appsVersion = cur;
        applyApps(blob.value_or(""));
    };
    loadApps(true);
    std::thread([loadApps]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadApps(false);
        }
    }).detach();

    // DDoS / 网络攻击防护配置
    DdosGuard::Config ddosCfg;
    ddosCfg.maxConcurrentPerIp = 200;   // 单 IP 并发连接上限
    ddosCfg.newConnPerSec       = 200;  // 单 IP 新建连接速率
    ddosCfg.reqPerSec           = 1000; // 单 IP 请求速率
    ddosCfg.slowTimeoutMs       = 5000; // 慢速攻击判定超时
    ddosCfg.banThreshold        = 5;    // 违规 5 次触发封禁
    ddosCfg.banSeconds          = 300;  // 封禁 5 分钟，到期自动解封
    DdosGuard ddos(ddosCfg);

    // ---- 应用层防护：CC / Bot / 动态自适应 / 指纹威胁情报 ----
    CcGuard::Config ccCfg;
    ccCfg.maxReqPerWindow  = 300;   // 单 IP 10s 内 300 次（正常浏览远低于此）
    ccCfg.burstPerUrl      = 80;    // 单 IP 刷同 URL 上限
    ccCfg.hotUrlGlobal     = 800;   // 全局热点 URL 阈值
    CcGuard cc(ccCfg);
    BotGuard bot(BotGuard::Config{});
    DynamicShield shield(DynamicShield::Config{});

    // ---- 地理位置拦截（GeoIP 地理围栏）：优先 Redis，回退文件，copy-on-write 热更新 ----
    GeoFilter geo;
    const char* geoFile = getenv("NOVA_GEO_FILE");
    std::string geoPath = geoFile ? geoFile : "rules/geoip.txt";
    {
        std::string geoCksum;
        bool fromRedis = false;
        auto glines = loadDataLines("novawaf:geoip", "geoip_cksum", geoPath, geoCksum, fromRedis);
        if (!glines.empty() || fromRedis) {
            size_t gn = geo.loadFromLines(glines);
            std::printf("  GeoIP: loaded %zu CIDR ranges from %s\n", gn,
                        fromRedis ? "redis" : geoPath.c_str());
        }
    }
    // 配置：NOVA_GEO_BLOCK=CN,RU  黑名单；NOVA_GEO_ALLOW=CN  白名单（仅放行）
    if (const char* e = getenv("NOVA_GEO_BLOCK")) {
        geo.setBlockedCountries(splitCsvStr(e));
        geo.setEnabled(true);
        std::printf("  GeoIP: BLACKLIST mode, blocked countries = %s\n", e);
    } else if (const char* e = getenv("NOVA_GEO_ALLOW")) {
        geo.setAllowedCountries(splitCsvStr(e));
        geo.setMode(GeoMode::WHITELIST);
        geo.setEnabled(true);
        std::printf("  GeoIP: WHITELIST mode, allowed countries = %s\n", e);
    }
    // 观察者：态势升级 → 收紧 CC 阈值
    shield.observe([&](ThreatLevel lvl) {
        cc.applyThreatLevel((int)lvl);
        std::printf("[shield] threat level -> %s\n", levelName(lvl));
    });
    shield.start();

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

    // AI 缓存 + 异步执行器（命中秒回、未命中不阻塞响应）
    int cacheTtl = (getenv("NOVAAI_CACHE_TTL")) ? std::atoi(getenv("NOVAAI_CACHE_TTL")) : 300;
    int cacheMax = (getenv("NOVAAI_CACHE_MAX")) ? std::atoi(getenv("NOVAAI_CACHE_MAX")) : 10000;
    int aiThreads = (getenv("NOVAAI_THREADS")) ? std::atoi(getenv("NOVAAI_THREADS")) : 4;
    auto aiCache = std::make_shared<AiCache>(cacheTtl, (size_t)cacheMax);
    auto aiPool = std::make_shared<ThreadPool>(aiThreads, 1 << 16);
    aiPool->start();
    ai->setCache(aiCache);
    ai->setExecutor(aiPool);

    // ---- 攻击事件总线订阅（观察者模式）：态势落库，后续可扩告警/SIEM ----
    EventBus<AttackEvent>::instance().subscribe(
        [](const AttackEvent& e) { EventSink::instance().emit(e); });

    // ---- 异步上游转发：独立 IO 线程池 + 连接池，reactor 不再被上游阻塞 ----
    int ioThreads = getenv("NOVA_IO_THREADS") ? std::atoi(getenv("NOVA_IO_THREADS"))
                                              : (int)std::thread::hardware_concurrency();
    g_upstream = std::make_shared<UpstreamForwarder>((size_t)ioThreads, 1 << 16);
    g_upstream->setOnDisconnect([&ddos](const std::string& ip) { ddos.onDisconnect(ip); });
    std::printf("  Upstream async forwarder: io_threads=%d (pool + keep-alive reuse)\n", ioThreads);

    std::printf("NovaWAF engine starting on port %d with %d reactors\n", port, threads);
    std::printf("  DDoS guard: maxConn=%d newConn/s=%d req/s=%d ban=%ds\n",
                ddosCfg.maxConcurrentPerIp, ddosCfg.newConnPerSec,
                ddosCfg.reqPerSec, ddosCfg.banSeconds);
    std::printf("  AI review: %s model=%s endpoint=%s timeout=%dms\n",
                llmCfg.enabled ? "ENABLED" : "disabled(pure-rules)",
                llmCfg.model.c_str(), llmCfg.endpoint.c_str(), llmCfg.timeoutMs);
    if (llmCfg.enabled)
        std::printf("  AI cache: ttl=%ds max=%d async threads=%d (non-blocking)\n",
                    cacheTtl, cacheMax, aiThreads);
    std::vector<std::thread> reactors;
    for (int i = 0; i < threads; ++i) {
        int lfd = createListenFd(port, 4096);
        if (lfd < 0) { std::perror("listen"); return 1; }
        reactors.emplace_back(reactorLoop, lfd, std::ref(pipeline),
                              std::ref(limiter), std::ref(ddos), ai,
                              std::ref(cc), std::ref(bot), threatIntel,
                              std::ref(shield), std::ref(geo), i);
    }
    for (auto& t : reactors) t.join();
    if (g_upstream) g_upstream->stop();  // 排空异步转发任务（ddos 此时仍存活）
    shield.stop();
    EventSink::instance().stop();
    TrafficSink::instance().stop();
    return 0;
}
