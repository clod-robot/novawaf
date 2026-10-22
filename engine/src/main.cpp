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
#include "novawaf/protect/iplist_filter.h"
#include "novawaf/protect/path_policy.h"
#include "novawaf/protect/tamper_cache.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/http_transport.h"
#include "novawaf/accel/accel_runtime.h"

#include <fstream>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace novawaf;

static std::atomic<bool> g_running{true};

// 热路径调试日志开关：默认关闭。printf 内部持有 libc 全局 stdout 锁，
// 高并发下每个拦截请求都 printf 会把所有 reactor 串行化，严重损耗多核扩展。
// 仅当 NOVA_DEBUG=1 时才输出。
static const bool g_debugLog = [] {
    const char* e = getenv("NOVA_DEBUG");
    return e && std::string(e) == "1";
}();

// 异步上游转发器（独立 IO 线程池），在 main 中初始化；
// reactor 对放行请求优先提交给它转发，避免阻塞 reactor 线程。
static std::shared_ptr<UpstreamForwarder> g_upstream;

// ---- per-reactor 观测（定位多核串行点）：NOVA_REACTOR_STATS=1 时每 2s 打印 ----
static std::atomic<uint64_t> g_rReq[64];      // 各 reactor 累计处理请求数
static std::atomic<uint64_t> g_rBusyNs[64];   // 各 reactor 处理请求累计耗时(纳秒)
static const bool g_reactorStats = [] {
    const char* e = getenv("NOVA_REACTOR_STATS");
    return e && std::string(e) == "1";
}();
// 单个请求处理作用域：析构时累计该 reactor 的请求数与处理耗时
struct ReactorReqScope {
    int idx;
    uint64_t t0 = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
    ~ReactorReqScope() {
        if (g_reactorStats) {
            uint64_t t1 = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
            g_rReq[idx].fetch_add(1, std::memory_order_relaxed);
            g_rBusyNs[idx].fetch_add(t1 - t0, std::memory_order_relaxed);
        }
    }
};

// ---- 分阶段耗时（微秒）累计，NOVA_REACTOR_STATS=1 时随 rstat 打印各阶段均耗时 ----
enum Stage { S_PARSE=0, S_GUARD, S_FP_TI, S_GEO_CC_BOT, S_PIPE, S_POST, S_WRITE, S__N };
static std::atomic<uint64_t> g_stNs[S__N];
static std::atomic<uint64_t> g_stCnt[S__N];
static inline uint64_t nowNs() {
    return (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
}
struct StageTimer {
    Stage s; uint64_t t0;
    explicit StageTimer(Stage x) : s(x), t0(nowNs()) {}
    ~StageTimer() {
        if (g_reactorStats) {
            g_stNs[s].fetch_add(nowNs() - t0, std::memory_order_relaxed);
            g_stCnt[s].fetch_add(1, std::memory_order_relaxed);
        }
    }
};

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

// 防绕过：仅当直连对端是可信反向代理时，才采信其 X-Forwarded-For/X-Real-IP。
// 否则一律用 socket 真实对端 IP，杜绝客户端伪造 XFF 冒充白名单/绕开地理与限速。
static uint32_t ipU(const std::string& ip) {
    int a,b,c,d; if (std::sscanf(ip.c_str(),"%d.%d.%d.%d",&a,&b,&c,&d)!=4) return 0;
    if ((a|b|c|d)<0||a>255||b>255||c>255||d>255) return 0;
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d);
}
static bool isTrustedProxy(const std::string& peerIp) {
    static const auto ranges = []() -> std::vector<std::pair<uint32_t,uint32_t>> {
        std::vector<std::pair<uint32_t,uint32_t>> r;
        const char* e = getenv("NOVA_TRUSTED_PROXIES");
        if (!e || !*e) return r;
        for (auto& s : splitCsvStr(e)) {
            auto slash = s.find('/');
            if (slash == std::string::npos) { uint32_t ip=ipU(s); if(ip) r.push_back({ip,ip}); }
            else {
                uint32_t net = ipU(s.substr(0,slash)); int bits = std::atoi(s.substr(slash+1).c_str());
                if (net && bits>=0 && bits<=32) {
                    uint32_t mask = bits==0?0:(0xFFFFFFFFu<<(32-bits));
                    uint32_t st=net&mask; r.push_back({st, bits==32?st:(st|(~mask))});
                }
            }
        }
        return r;
    }();
    if (ranges.empty()) return false;
    uint32_t u = ipU(peerIp); if (!u) return false;
    for (auto& rg : ranges) if (u>=rg.first && u<=rg.second) return true;
    return false;
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
static void setBlocking(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
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

// 生成不可预测的 session id（16 字节随机 → hex）。
// 用 getrandom() 单次系统调用，避免每请求 fopen/fclose /dev/urandom 的高开销。
static std::string genSid() {
    static std::atomic<unsigned> ctr{0};
    unsigned char buf[16];
    ssize_t got = -1;
#if defined(__linux__)
    got = getrandom(buf, sizeof(buf), 0);  // <sys/random.h>
#endif
    if (got != (ssize_t)sizeof(buf)) {     // 回退：常驻 fd（只在首次打开）
        static int urd = [] { int f = open("/dev/urandom", O_RDONLY); return f; }();
        if (urd >= 0) {
            size_t off = 0;
            while (off < sizeof(buf)) {
                ssize_t rd = read(urd, buf + off, sizeof(buf) - off);
                if (rd > 0) off += (size_t)rd; else break;
            }
            if (off != sizeof(buf))
                for (int i = 0; i < 16; ++i) buf[i] = (unsigned char)(rand() ^ (ctr.fetch_add(1) * 2654435761u));
        } else {
            for (int i = 0; i < 16; ++i) buf[i] = (unsigned char)(rand() ^ (ctr.fetch_add(1) * 2654435761u));
        }
    }
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

// ---- HTTP keep-alive 支持 ----
// 从接收缓冲区切出一个完整请求：返回 1=完整(rawReq/totalLen) 0=不完整 -1=协议错误
static int nextRequest(const std::string& buf, std::string& rawReq, size_t& totalLen) {
    size_t he = buf.find("\r\n\r\n");
    if (he == std::string::npos) {
        // 请求行/头过长仍不完整，按畸形处理，防止无限缓冲
        return buf.size() > 65536 ? -1 : 0;
    }
    std::string head = buf.substr(0, he);
    long long bodyLen = -1;
    {   // 解析 Content-Length（大小写不敏感）
        std::string low = head;
        for (auto& c : low) c = (char)tolower((unsigned char)c);
        size_t p = low.find("content-length:");
        if (p != std::string::npos) {
            size_t e = low.find("\r\n", p);
            std::string v = low.substr(p + 15, (e == std::string::npos ? low.size() : e) - (p + 15));
            bodyLen = std::atoll(v.c_str());
        }
    }
    if (bodyLen < 0) bodyLen = 0;
    totalLen = he + 4 + (size_t)bodyLen;
    if (buf.size() < totalLen) return 0;
    rawReq = buf.substr(0, totalLen);
    return 1;
}

// 按 HTTP 版本与 Connection 头判定是否复用连接
static bool wantsKeepAlive(const HttpRequest& req) {
    std::string conn = hdrCi(req, "Connection");
    for (auto& c : conn) c = (char)tolower((unsigned char)c);
    bool is11 = req.version.find("1.1") != std::string::npos;
    if (conn.find("close") != std::string::npos) return false;
    if (conn.find("keep-alive") != std::string::npos) return true;
    return is11;  // HTTP/1.1 默认 keep-alive，1.0 默认关闭
}

// 归一化本地生成响应的 Connection 头（大小写不敏感替换/插入）
static void setRespConnection(std::string& resp, bool keepAlive) {
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
            out += "\r\n";
        }
        if (eol == std::string::npos) break;
        pos = eol + 2;
    }
    size_t firstEol = out.find("\r\n");
    if (firstEol != std::string::npos)
        out.insert(firstEol + 2,
                   std::string("Connection: ") + (keepAlive ? "keep-alive" : "close") + "\r\n");
    resp = out + "\r\n" + body;
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

    // ---- per-connection 状态（keep-alive 复用读缓冲）----
    struct ConnState {
        std::string inbuf;
        std::string peerIp;
        bool peerReady = false;
        // 非阻塞回写：send 遇到 EAGAIN 时，剩余响应在此排队，由 EPOLLOUT 排空（不阻塞 reactor）
        std::string outQ;
        size_t outPos = 0;
        bool closeAfterFlush = false;
        int64_t lastActiveMs = 0;
    };
    std::unordered_map<int, ConnState> conns;
    std::mutex busyMtx;
    std::unordered_set<int> busy;   // 已交给异步转发器、尚未回写完成的 fd
    constexpr int64_t kKeepAliveIdleMs = 15000;  // 空闲连接 15s 回收
    auto nowMs = [] { return std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch()).count(); };

    // 关闭并清理一条客户端连接（reactor 线程与异步完成回调共用，幂等）
    auto closeConn = [&](int cfd) {
        {
            std::lock_guard<std::mutex> lk(busyMtx);
            if (busy.count(cfd)) return;   // 异步转发进行中，由完成回调收尾
            if (conns.erase(cfd) == 0) return;  // 已被异步回调关闭，避免重复 close
        }
        epoll_ctl(epfd, EPOLL_CTL_DEL, cfd, nullptr);
        sockaddr_in peer{}; socklen_t plen = sizeof(peer);
        if (getpeername(cfd, (sockaddr*)&peer, &plen) == 0) {
            char ipstr[32] = {0};
            inet_ntop(AF_INET, &peer.sin_addr, ipstr, sizeof(ipstr));
            ddos.onDisconnect(ipstr);
        }
        ::close(cfd);
    };

    // 1s 周期 timerfd：驱动 keep-alive 空闲连接回收
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    itimerspec its{}; its.it_interval.tv_sec = 1; its.it_value.tv_sec = 1;
    timerfd_settime(tfd, 0, &its, nullptr);
    epoll_event tev{}; tev.events = EPOLLIN; tev.data.fd = tfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &tev);

    std::printf("[reactor %d] started\n", idx);

    while (g_running) {
        int n = epoll_wait(epfd, events.data(), (int)events.size(), 200);
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == tfd) { uint64_t exp; while (read(tfd, &exp, 8) > 0) {} continue; }
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
                    // 读保持非阻塞(ET 边沿触发需 drain 到 EAGAIN)；写响应时临时切阻塞以发完整
                    setNonblock(cfd);
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));  // 降低小包延迟
                    // TCP keepalive：及时发现半开/失活对端
                    int on = 1, idle = 10, intv = 3, cnt = 3;
                    setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
                    setsockopt(cfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
                    setsockopt(cfd, IPPROTO_TCP, TCP_KEEPINTVL, &intv, sizeof(intv));
                    setsockopt(cfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
                    timeval sndtv{10, 0}, rcvtv{15, 0};  // 防慢客户端长期占用 reactor
                    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &sndtv, sizeof(sndtv));
                    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rcvtv, sizeof(rcvtv));
                    epoll_event ce{};
                    ce.events = EPOLLIN | EPOLLET;
                    ce.data.fd = cfd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ce);
                    conns[cfd].lastActiveMs = nowMs();
                }
                continue;
            }
            // 单连接处理异常护栏：资源耗尽等异常只丢弃该连接，绝不让异常逃逸到
            // reactor 线程触发 std::terminate/abort（保证高并发下进程可用性）。
            try {
            {
                bool isBusy = false;
                { std::lock_guard<std::mutex> lk(busyMtx); isBusy = busy.count(fd) > 0; }
                if (isBusy) continue;  // 异步转发进行中，交由 IO 线程回写
            }
            // 非阻塞回写排空：该连接此前 send EAGAIN，现 EPOLLOUT 可写，把剩余响应发完
            {
                auto cd = conns.find(fd);
                if (cd != conns.end() && !cd->second.outQ.empty()) {
                    ConnState& cs = cd->second;
                    bool werr = false;
                    while (cs.outPos < cs.outQ.size()) {
                        ssize_t w = send(fd, cs.outQ.data() + cs.outPos,
                                         cs.outQ.size() - cs.outPos, MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (w > 0) { cs.outPos += (size_t)w; }
                        else if (w < 0 && errno == EINTR) { continue; }
                        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { break; }
                        else { werr = true; break; }
                    }
                    if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) werr = true;
                    if (werr) { closeConn(fd); continue; }
                    if (cs.outPos < cs.outQ.size()) continue;  // 仍背压，等待下一次 EPOLLOUT
                    // 本响应已完整排空
                    bool doClose = cs.closeAfterFlush;
                    cs.outQ.clear(); cs.outPos = 0; cs.closeAfterFlush = false;
                    epoll_event ev{}; ev.events = EPOLLIN | EPOLLET; ev.data.fd = fd;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);  // 回到只关心可读
                    if (doClose) { closeConn(fd); continue; }
                    // 落到下面正常读/处理，顺带把背压期间已到达的请求 drain 掉（避免漏 ET 边沿）
                }
            }
            {
                char buf[8192];
                bool peerClosed = false, readErr = false;
                while (true) {
                    ssize_t r = read(fd, buf, sizeof(buf));
                    if (r > 0) conns[fd].inbuf.append(buf, (size_t)r);
                    else if (r == 0) { peerClosed = true; break; }
                    else if (r < 0 && errno != EAGAIN) { readErr = true; break; }
                    else break;
                }
                if (peerClosed || readErr) { closeConn(fd); continue; }
            }
            {
              // 每条连接可连续处理多个完整请求（keep-alive），畸形则关闭
              bool keepOpen = true;
              bool draining = false;  // 响应进入 outQ 由 EPOLLOUT 异步排空，fd 暂不关闭
              while (keepOpen && g_running) {
                {   // 空闲超时回收（惰性）
                    auto it = conns.find(fd);
                    if (it != conns.end() && nowMs() - it->second.lastActiveMs > kKeepAliveIdleMs) {
                        keepOpen = false; break;
                    }
                }
                std::string rawReq; size_t reqLen = 0;
                {
                    auto it = conns.find(fd);
                    if (it == conns.end()) { keepOpen = false; break; }
                    int nr = nextRequest(it->second.inbuf, rawReq, reqLen);
                    if (nr == 0) break;        // 数据不完整，等更多字节
                    if (nr < 0) { keepOpen = false; break; }  // 协议错误
                }
                bool keepAlive = false;
                const std::string data = rawReq;   // 检测/转发使用的完整请求字节
                {
                    ReactorReqScope _rs{idx};
                    uint64_t _mk[8]; int _mi=0;
                    auto _mark=[&](){ if(g_reactorStats && _mi<8) _mk[_mi++]=nowNs(); };
                    auto _flush=[&](const int idxm[8]){
                        if(!g_reactorStats || _mi<8) return;
                        for(int k=0;k<7;++k){ g_stNs[k].fetch_add(_mk[idxm[k+1]]-_mk[idxm[k]],std::memory_order_relaxed);
                                             g_stCnt[k].fetch_add(1,std::memory_order_relaxed); }
                    };
                    static const int SEQ[8]={0,1,2,3,4,5,6,7};
                    _mark();
                    // HTTP 解析仅一次：keep-alive 判定与后续检测共用同一份 req
                    HttpParser parser;
                    parser.feed(data);
                    if (parser.hasError()) { keepOpen = false; break; }
                    HttpRequest req = parser.request();
                    keepAlive = wantsKeepAlive(req);
                    // 直连对端 IP 按连接缓存（keep-alive 多请求只解析一次）
                    {
                        auto csIt = conns.find(fd);
                        if (csIt == conns.end()) { keepOpen = false; break; }
                        ConnState& _cs = csIt->second;
                        if (!_cs.peerReady) {
                            sockaddr_in peer{}; socklen_t plen = sizeof(peer);
                            if (getpeername(fd, (sockaddr*)&peer, &plen) == 0) {
                                char ip[32] = {0};
                                if (inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip))) _cs.peerIp = ip;
                            }
                            _cs.peerReady = true;
                        }
                        req.clientIp = _cs.peerIp;
                    }
                    const char* ipstr = req.clientIp.c_str();
                    // 防绕过：仅当直连对端是可信反向代理(NOVA_TRUSTED_PROXIES)时，才采信
                    // X-Forwarded-For/X-Real-IP 的最左原始 IP；否则忽略客户端伪造头，用真实对端 IP。
                    if (isTrustedProxy(ipstr)) {
                        for (auto& [k, v] : req.headers) {
                            std::string lk = k;
                            for (auto& c : lk) c = (char)tolower((unsigned char)c);
                            if (lk == "x-forwarded-for" || lk == "x-real-ip") {
                                std::string ff = v;
                                auto comma = ff.find(',');
                                if (comma != std::string::npos) ff = ff.substr(0, comma);
                                size_t a = 0; while (a < ff.size() && isspace((unsigned char)ff[a])) a++;
                                ff = ff.substr(a);
                                if (!ff.empty()) { req.clientIp = ff; break; }
                            }
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
                    // API 路径级防护策略：仅记录(log)/放行(pass)，按应用隔离 + 最长前缀匹配（控制台热配置）
                    PathPolicy::Match pathMatch = PathPolicy::instance().match(req.path, appId);
                    const std::string policyId = pathMatch.id;  // 命中策略 ID，用于按策略统计访问/拦截/放行次数
                    const bool policyPass = (pathMatch.verdict == PathPolicy::Verdict::PASS); // 跳过WAF检测
                    const bool policyLog  = (pathMatch.verdict == PathPolicy::Verdict::LOG);  // 命中只记录不拦截
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
                        static const std::string k502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                        if (app && g_upstream) {
                            UpstreamForwarder::Ctx ctx;
                            ctx.clientFd = fd; ctx.data = data;
                            ctx.upstreamHost = app->upstreamHost; ctx.upstreamPort = app->upstreamPort;
                            ctx.clientIp = req.clientIp; ctx.newSess = newSess; ctx.sid = sid;
                            ctx.appId = appId; ctx.statsEnabled = app->statsEnabled; ctx.reactorIdx = idx;
                            ctx.ua = hdrCi(req, "User-Agent"); ctx.host = hdrCi(req, "Host");
                            ctx.path = req.path; ctx.referer = hdrCi(req, "Referer");
                            ctx.country = geo.country(req.clientIp);
                            ctx.policyId = policyId;
                            ctx.keepAlive = keepAlive;
                            // 异步转发完成(在 IO 线程)：keep-alive 则重新挂回 epoll 复用，否则关闭。
                            // 注：ddos 并发计数由转发器的 onDisconnect 统一释放，此处不重复。
                            ctx.onComplete = [epfd, &busyMtx, &busy, &conns, nowMs]
                                             (int cfd, bool ka) {
                                if (ka) {
                                    { std::lock_guard<std::mutex> lk(busyMtx); busy.erase(cfd); }
                                    auto it = conns.find(cfd);
                                    if (it != conns.end()) it->second.lastActiveMs = nowMs();
                                    epoll_event e2{}; e2.events = EPOLLIN | EPOLLET; e2.data.fd = cfd;
                                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &e2) < 0 && errno == EEXIST)
                                        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &e2);  // 兜底：已注册则改事件
                                } else {
                                    { std::lock_guard<std::mutex> lk(busyMtx); busy.erase(cfd); }
                                    epoll_ctl(epfd, EPOLL_CTL_DEL, cfd, nullptr);
                                    conns.erase(cfd);
                                    ::close(cfd);
                                }
                            };
                            // 修复 keepalive 挂死竞态：必须先置 busy 并从 epoll 摘除，再入队。
                            // 否则 IO 线程可能在 reactor DEL 前就完成转发并执行 onComplete 的
                            // EPOLL_CTL_ADD(返回 EEXIST 被忽略)，随后 reactor 又 DEL —— 净效果
                            // fd 永久脱离 epoll、永不再 re-arm，4 个 IO 线程空转、连接挂死。
                            { std::lock_guard<std::mutex> lk(busyMtx); busy.insert(fd); }
                            epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                            if (g_upstream->submit(std::move(ctx))) return true;
                            // submit 失败(队列满/未运行)：回滚，恢复可读，回退同步转发
                            { std::lock_guard<std::mutex> lk(busyMtx); busy.erase(fd); }
                            epoll_event re{}; re.events = EPOLLIN | EPOLLET; re.data.fd = fd;
                            epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &re);
                        }
                        if (app && forwardToUpstream(app->upstreamHost, app->upstreamPort, data, outResp)) {
                            // 网页防篡改：同步回退路径同样过基线校验
                            if (data.compare(0, 4, "GET ") == 0) {
                                if (auto restored = TamperCache::instance().process(
                                        "GET", hdrCi(req, "Host"), req.path, outResp, req.clientIp))
                                    outResp = std::move(*restored);
                            }
                            setRespConnection(outResp, keepAlive);
                            return false;
                        }
                        outResp = k502;
                        setRespConnection(outResp, false);
                        return false;
                    };
                    _mark();  // [1] 解析+sid+app 结束，进入限流判定
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
                        _mark();  // [2] 限流通过，进入指纹/威胁情报
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
                        bool whitelisted = false;
                        // IP 黑白名单（最高优先级，联动管理控制台 novawaf:blacklist / whitelist）
                        switch (IpListFilter::instance().match(req.clientIp)) {
                            case IpListFilter::Verdict::WHITE: whitelisted = true; break;
                            case IpListFilter::Verdict::BLACK:
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 44\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, "IpList", "block", "IP-BLACK",
                                        std::string("blacklisted ip ") + req.clientIp);
                                blocked = true; tBlocked = true; tAttack = true;
                                break;
                            default: break;
                        }
                        if (!whitelisted && !policyPass && ti) {
                            auto tr = ti->match(req, ja4, httpFp);
                            if (tr && tr->isBlocked()) {
                                if (g_debugLog) std::printf("[reactor %d] BLOCK TI-%s from %s: %s\n",
                                            idx, tr->category.c_str(), ipstr, tr->matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 44\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, tr->category, "block", tr->ruleId, tr->matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        _mark();  // [3] 指纹+IP名单+威胁情报 结束，进入 CC/Geo/Bot
                        // CC 攻击防护
                        if (!whitelisted && !policyPass && !blocked) {
                            // 地理位置拦截（GeoIP 地理围栏）
                            auto gr = geo.assess(req.clientIp);
                            if (gr && gr->isBlocked()) {
                                if (g_debugLog) std::printf("[reactor %d] BLOCK Geo from %s: %s\n",
                                            idx, ipstr, gr->matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 44\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, "Geo", "block", gr->ruleId, gr->matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        if (!whitelisted && !policyPass && !blocked) {
                            DetectionResult cr = cc.assess(req.clientIp, req.path);
                            if (cr.action != Action::PASS) {
                                if (g_debugLog) std::printf("[reactor %d] %s CC from %s: %s\n",
                                            idx, cr.action == Action::BLOCK ? "BLOCK" : "CHAL",
                                            ipstr, cr.matched.c_str());
                                outResp = (cr.action == Action::BLOCK)
                                       ? "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 44\r\n\r\n"
                                         "<html><body>Blocked by NovaWAF</body></html>"
                                       : "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 0\r\n\r\n";
                                if (cr.action == Action::BLOCK) shield.recordBlock();
                                emitEvt(req.clientIp, "CC", cr.action == Action::BLOCK ? "block" : "challenge", cr.ruleId, cr.matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // Bot 行为防护
                        if (!whitelisted && !policyPass && !blocked) {
                            DetectionResult br = bot.assess(req, ja4);
                            if (br.action != Action::PASS) {
                                if (g_debugLog) std::printf("[reactor %d] %s Bot from %s: %s\n",
                                            idx, br.action == Action::BLOCK ? "BLOCK" : "CHAL",
                                            ipstr, br.matched.c_str());
                                outResp = (br.action == Action::BLOCK)
                                       ? "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 44\r\n\r\n"
                                         "<html><body>Blocked by NovaWAF</body></html>"
                                       : "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n"
                                         "Content-Length: 0\r\n\r\n";
                                if (br.action == Action::BLOCK) shield.recordBlock();
                                emitEvt(req.clientIp, "Bot", br.action == Action::BLOCK ? "block" : "challenge", br.ruleId, br.matched);
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        _mark();  // [4] Geo/CC/Bot 结束，进入规则+AI 检测流水线
                        // 规则 + AI 二阶复核
                        if (!whitelisted && !policyPass && !blocked) {
                            DetectionResult dr = detectWithAiReview(pipeline, ai, req);
                            if (dr.isBlocked()) {
                                if (g_debugLog) std::printf("[reactor %d] BLOCK %s from %s: %s\n",
                                            idx, dr.category.c_str(), ipstr, dr.matched.c_str());
                                outResp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                                       "Content-Length: 44\r\n\r\n"
                                       "<html><body>Blocked by NovaWAF</body></html>";
                                shield.recordBlock();
                                emitEvt(req.clientIp, dr.category, "block", dr.ruleId, dr.matched);
                                tBlocked = true; tAttack = true;
                            } else {
                                asyncHandled = forwardToApp();
                            }
                        }
                        // 白名单 或 路径放行策略：跳过全部检测，直接转发上游
                        if (whitelisted || policyPass) asyncHandled = forwardToApp();
                    }
                    _mark();  // [5] 检测/转发决策结束，进入后置处理
                    // 观察模式 / 路径“仅记录”策略：命中攻击仅记录事件(tAttack 已置位)，不拦截、不封禁，仍转发上游
                    if ((appMode == 1 || policyLog) && tAttack && app) {
                        tBlocked = false;
                        asyncHandled = forwardToApp();
                    }
                    if (asyncHandled) {
                        // fd 已从 epoll 摘除并标记 busy，交给异步转发器回写；
                        // 消费掉本请求字节，停止本连接的处理循环，等待完成回调 re-arm。
                        { auto ci = conns.find(fd); if (ci != conns.end()) ci->second.inbuf.erase(0, reqLen); }
                        keepOpen = false;
                        break;
                    }
                    // 确认攻击命中 → 投递防火墙联动封禁（观察模式 / 路径仅记录：只记录不封禁）
                    if (tAttack && appMode != 1 && !policyLog) FwBanPoster::instance()->enqueue(req.clientIp, "WAF", "attack");
                    if (newSess && !outResp.empty())
                        injectHeader(outResp, "Set-Cookie: novasid=" + sid + "; Path=/; HttpOnly");
                    // 流量统计埋点（已启用统计的应用，或命中 API 防护策略需按策略计数；热路径入队不阻塞）
                    if ((app && app->statsEnabled) || !policyId.empty()) {
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
                        tr.policyId = policyId;
                        TrafficSink::instance().emit(std::move(tr));
                    }
                    _mark();  // [6] 后置处理(封禁/事件/统计/注入Cookie)结束，进入回写
                    // 归一化 Connection 头，保证客户端能据 keep-alive 正确定界与复用
                    setRespConnection(outResp, keepAlive);
                    {
                        // 非阻塞回写：尽量一次发完；内核发送缓冲不足则把剩余响应排入 outQ、
                        // 由 EPOLLOUT 异步排空，reactor 立即转去处理其它连接，
                        // 消除"单个慢客户端的 send 阻塞拖垮整个 reactor"的串行点。
                        const char* p = outResp.data(); size_t left = outResp.size();
                        bool writeFail = false;
                        while (left > 0) {
                            ssize_t w = send(fd, p, left, MSG_NOSIGNAL | MSG_DONTWAIT);
                            if (w > 0) { p += w; left -= (size_t)w; }
                            else if (w < 0 && errno == EINTR) { continue; }
                            else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { break; }
                            else { writeFail = true; break; }
                        }
                        // 消费本请求字节（响应是否排队都不再需要它）
                        { auto ci = conns.find(fd); if (ci != conns.end()) ci->second.inbuf.erase(0, reqLen); }
                        if (writeFail) { keepOpen = false; break; }
                        if (left > 0) {
                            auto ci = conns.find(fd);
                            if (ci == conns.end()) { keepOpen = false; break; }
                            ci->second.outQ.assign(p, left);
                            ci->second.outPos = 0;
                            ci->second.closeAfterFlush = !keepAlive;
                            epoll_event ev{}; ev.events = EPOLLIN | EPOLLOUT | EPOLLET; ev.data.fd = fd;
                            epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
                            draining = true; keepOpen = false; break;  // 交 EPOLLOUT 排空，本连接暂停
                        }
                        if (!keepAlive) { keepOpen = false; break; }
                        if (auto ci = conns.find(fd); ci != conns.end()) ci->second.lastActiveMs = nowMs();
                        _mark();  // [7] 回写结束（响应已全部进入内核缓冲或已排队异步排空）
                        _flush(SEQ);
                    }
                }  // end per-request detection scope
              }    // end keep-alive request loop
              // 响应进入 outQ 时 fd 保持打开由 EPOLLOUT 排空；其余情况按 keep-alive/错误关闭
              if (!keepOpen && !draining) closeConn(fd);
            }      // end client-fd scope
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[reactor %d] fd=%d exception: %s -> drop conn\n", idx, fd, e.what());
                closeConn(fd);
            } catch (...) {
                std::fprintf(stderr, "[reactor %d] fd=%d unknown exception -> drop conn\n", idx, fd);
                closeConn(fd);
            }
        }          // end epoll events for
        // 周期空闲连接回收（即使无事件触发也能关闭超时 keep-alive 连接）
        {
            int64_t now = nowMs();
            std::vector<int> stale;
            {
                std::lock_guard<std::mutex> lk(busyMtx);
                for (auto& [cfd, st] : conns)
                    if (!busy.count(cfd) && now - st.lastActiveMs > kKeepAliveIdleMs) stale.push_back(cfd);
            }  // 先释放锁，再逐个关闭（closeConn 自身会加锁）
            for (int cfd : stale) closeConn(cfd);
        }
    }              // end while(g_running)
    close(tfd);
    close(epfd);
}

int main(int argc, char** argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    int threads = (argc > 2) ? atoi(argv[2]) : (int)std::thread::hardware_concurrency();
    signal(SIGPIPE, SIG_IGN);

    // 提升文件描述符软限到硬限，避免高并发连接（默认软限常为 1024）导致 accept EMFILE、
    // 资源分配抛异常而中断服务；提升失败不致命（沿用系统限制）。
    {
        struct rlimit rl{};
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
            rlim_t target = rl.rlim_max;
            if (target > 1048576) target = 1048576;  // 封顶，避免超大表的无谓内存
            struct rlimit nr = rl; nr.rlim_cur = target;
            if (setrlimit(RLIMIT_NOFILE, &nr) != 0) { nr.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &nr); }
        }
    }

    // 态势统计事件汇聚（异步写 Redis，可视化大屏数据源）
    EventSink::instance().start();
    TrafficSink::instance().start();

    // 网页防篡改缓存（页面基线学习/恢复，后台同步 Redis 持久化与配置热加载）
    TamperCache::instance().start();

    // 硬件加速运行时：探测 CPU SIMD / GPU-NPU，加载开关（默认关），周期上报设备与健康状态
    accel::AccelRuntime::instance().start();
    std::printf("  Accel: backend=%s simdHealthy=%d enabled=%d\n",
                accel::backendName(accel::activeBackend()),
                accel::AccelRuntime::instance().simdHealthy() ? 1 : 0,
                accel::enabled() ? 1 : 0);

    DetectionPipeline pipeline;
    int rlBurst = getenv("NOVA_RL_BURST") ? atoi(getenv("NOVA_RL_BURST")) : 100;   // 每 IP 突发
    int rlRate  = getenv("NOVA_RL_RATE")  ? atoi(getenv("NOVA_RL_RATE"))  : 1000;  // 每秒补充
    RateLimiter limiter(rlBurst, rlRate);

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

    // ---- IP 黑白名单：从 Redis novawaf:blacklist / novawaf:whitelist 热加载（联动管理控制台）----
    auto loadIpList = [](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        static std::string s_ver = "-";
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        auto ver = r.get("novawaf:iplist:version");
        std::string cur = ver.value_or("");
        if (cur == s_ver && !initial) return;
        auto bl = r.get("novawaf:blacklist");
        auto wh = r.get("novawaf:whitelist");
        s_ver = cur;
        auto cnt = IpListFilter::instance().reload(bl.value_or(""), wh.value_or(""));
        std::printf("  IpList: %s black=%zu white=%zu (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", cnt.first, cnt.second, cur.c_str());
    };
    loadIpList(true);
    std::thread([loadIpList]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadIpList(false);
        }
    }).detach();

    // ---- API 路径级防护策略：从 Redis novawaf:pathpolicy 热加载（联动控制台，保存即发布）----
    auto loadPathPolicy = [](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        static std::string s_ver = "-";
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        auto ver = r.get("novawaf:pathpolicy:version");
        std::string cur = ver.value_or("");
        if (cur == s_ver && !initial) return;
        auto blob = r.get("novawaf:pathpolicy");
        s_ver = cur;
        size_t n = PathPolicy::instance().reload(blob.value_or(""));
        std::printf("  PathPolicy: %s rules=%zu (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", n, cur.c_str());
    };
    loadPathPolicy(true);
    std::thread([loadPathPolicy]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadPathPolicy(false);
        }
    }).detach();

    // DDoS / 网络攻击防护配置（可通过环境变量覆盖，便于压测；默认仍为生产安全值）
    DdosGuard::Config ddosCfg;
    ddosCfg.maxConcurrentPerIp = getenv("NOVA_DDOS_MAXCONN") ? atoi(getenv("NOVA_DDOS_MAXCONN")) : 200;   // 单 IP 并发连接上限
    ddosCfg.newConnPerSec       = getenv("NOVA_DDOS_NEWCONN") ? atoi(getenv("NOVA_DDOS_NEWCONN")) : 200;  // 单 IP 新建连接速率
    ddosCfg.reqPerSec           = getenv("NOVA_DDOS_RPS")     ? atoi(getenv("NOVA_DDOS_RPS"))     : 1000; // 单 IP 请求速率
    ddosCfg.slowTimeoutMs       = 5000; // 慢速攻击判定超时
    ddosCfg.banThreshold        = 5;    // 违规 5 次触发封禁
    ddosCfg.banSeconds          = 300;  // 封禁 5 分钟，到期自动解封
    DdosGuard ddos(ddosCfg);

    // ---- 应用层防护：CC / Bot / 动态自适应 / 指纹威胁情报 ----
    CcGuard::Config ccCfg;
    ccCfg.maxReqPerWindow  = getenv("NOVA_CC_WINDOW") ? atoi(getenv("NOVA_CC_WINDOW")) : 300;   // 单 IP 10s 内（正常浏览远低于此）
    // 单 URL 突刺/全局热点阈值同样可由环境变量覆盖，便于压测时区分“引擎裸吞吐基线”
    // 与“CC 防护下性能”；不设置时保持生产安全默认 80/800。
    ccCfg.burstPerUrl      = getenv("NOVA_CC_BURST_URL") ? atoi(getenv("NOVA_CC_BURST_URL")) : 80;    // 单 IP 刷同 URL 上限
    ccCfg.hotUrlGlobal     = getenv("NOVA_CC_HOT_URL")   ? atoi(getenv("NOVA_CC_HOT_URL"))   : 800;   // 全局热点 URL 阈值
    CcGuard cc(ccCfg);
    BotGuard bot(BotGuard::Config{});
    DynamicShield shield(DynamicShield::Config{});

    // ---- 地理位置拦截（GeoIP 地理围栏）：优先 Redis，回退文件，copy-on-write 热更新 ----
    GeoFilter geo;
    const char* geoFile = getenv("NOVA_GEO_FILE");
    std::string geoPath = geoFile ? geoFile : "rules/geoip.txt";
    std::string geoCksum;      // GeoIP 数据 cksum（初始加载与热加载共享，供 loadDataLines 判等）
    bool geoFromRedis = false;
    {
        auto glines = loadDataLines("novawaf:geoip", "geoip_cksum", geoPath, geoCksum, geoFromRedis);
        if (!glines.empty() || geoFromRedis) {
            size_t gn = geo.loadFromLines(glines);
            std::printf("  GeoIP: loaded %zu CIDR ranges from %s\n", gn,
                        geoFromRedis ? "redis" : geoPath.c_str());
        }
    }
    // ---- GeoIP 数据热加载：novawaf:geoip cksum 变化时重建（配合 GeoIP 每周五定时更新，无需重启）----
    auto loadGeoData = [&geo, &geoPath](std::string& ck) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        bool fromRedis = false;
        auto glines = loadDataLines("novawaf:geoip", "geoip_cksum", geoPath, ck, fromRedis);
        // 仅接受 Redis 来源（避免 Redis 短暂不可用时被本地旧文件覆盖）；内容未变时 loadDataLines 返回空
        if (!glines.empty() && fromRedis) {
            size_t gn = geo.loadFromLines(glines);
            std::printf("  GeoIP: hot-reloaded %zu CIDR ranges\n", gn);
        }
    };
    std::thread([loadGeoData, &geoCksum]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (!g_running) break;
            loadGeoData(geoCksum);
        }
    }).detach();
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
    // ---- Geo 地域策略：从 Redis novawaf:geo:policy 热加载（管理后台保存即生效）----
    // JSON: {"enabled":bool,"mode":"whitelist"|"blacklist","countries":["CN",...]}
    // 版本键 novawaf:geo:policy:version 变化才重载；键缺失时保持上方环境变量配置（向后兼容）。
    auto loadGeoPolicy = [&geo](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        static std::string s_ver = "-";
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        auto ver = r.get("novawaf:geo:policy:version");
        std::string cur = ver.value_or("");
        if (cur == s_ver && !initial) return;
        auto blob = r.get("novawaf:geo:policy");
        s_ver = cur;
        if (!blob || blob->empty()) {
            std::printf("  GeoPolicy: %s (no redis policy, env config kept)\n",
                        initial ? "loaded" : "hot-reload checked");
            return;
        }
        JsonValue root;
        try { root = parseJson(*blob); } catch (...) { return; }
        if (!root.isObject()) return;
        bool enabled = false;
        if (root.at("enabled").isBool()) enabled = root.at("enabled").b;
        std::string mode = root.at("mode").isString() ? root.at("mode").str : "blacklist";
        std::vector<std::string> ccs;
        const JsonValue& cs = root.at("countries");
        if (cs.isArray())
            for (auto& c : cs.arr)
                if (c.isString() && !c.str.empty()) ccs.push_back(c.str);
        if (mode == "whitelist") {
            geo.setMode(GeoMode::WHITELIST);
            geo.setAllowedCountries(ccs);
        } else {
            geo.setMode(GeoMode::BLACKLIST);
            geo.setBlockedCountries(ccs);
        }
        geo.setEnabled(enabled);
        std::printf("  GeoPolicy: %s enabled=%d mode=%s countries=%zu (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", enabled ? 1 : 0, mode.c_str(),
                    ccs.size(), cur.c_str());
    };
    loadGeoPolicy(true);
    std::thread([loadGeoPolicy]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadGeoPolicy(false);
        }
    }).detach();
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
    // listen backlog 可配置(NOVA_BACKLOG)，默认 16384，承载高并发突发建连
    int backlog = getenv("NOVA_BACKLOG") ? std::atoi(getenv("NOVA_BACKLOG")) : 16384;
    std::printf("  listen backlog=%d\n", backlog);
    // per-reactor 负载观测（NOVA_REACTOR_STATS=1）：每 2s 打印 各 reactor req/s 与 忙碌占比
    if (g_reactorStats) {
        std::thread([threads] {
            uint64_t prevReq[64] = {0}, prevBusy[64] = {0};
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                std::string line = "[rstat] ";
                uint64_t sumRps = 0; double sumBusy = 0;
                for (int i = 0; i < threads; ++i) {
                    uint64_t r = g_rReq[i].load();
                    uint64_t b = g_rBusyNs[i].load();
                    uint64_t rps = (r - prevReq[i]) / 2;
                    double busyPct = (b - prevBusy[i]) * 100.0 / 2.0e9;
                    prevReq[i] = r; prevBusy[i] = b;
                    sumRps += rps; sumBusy += busyPct;
                    line += "R" + std::to_string(i) + ":" + std::to_string(rps) + "rps/" +
                            std::to_string((long long)busyPct) + "% ";
                }
                std::printf("%s | TOTAL %llurps busy=%.0f%%(of %d00)\n", line.c_str(),
                            (unsigned long long)sumRps, sumBusy, threads);
                static const char* sn[S__N]={"parse","guard","fp_ti","geo_cc_bot","pipeline","post","write"};
                static uint64_t pn[S__N]={0}, pc[S__N]={0};
                std::string sl="[stage-us] ";
                for(int s=0;s<S__N;++s){
                    uint64_t n=g_stNs[s].load(), c=g_stCnt[s].load();
                    uint64_t dn=n-pn[s], dc=c-pc[s]; pn[s]=n; pc[s]=c;
                    long us=dc?(long)(dn/1000.0/dc):0;
                    sl+=std::string(sn[s])+":"+std::to_string(us)+" ";
                }
                std::printf("%s\n", sl.c_str());
                std::fflush(stdout);
            }
        }).detach();
    }
    std::vector<std::thread> reactors;
    for (int i = 0; i < threads; ++i) {
        int lfd = createListenFd(port, backlog);
        if (lfd < 0) { std::perror("listen"); return 1; }
        reactors.emplace_back(reactorLoop, lfd, std::ref(pipeline),
                              std::ref(limiter), std::ref(ddos), ai,
                              std::ref(cc), std::ref(bot), threatIntel,
                              std::ref(shield), std::ref(geo), i);
    }
    for (auto& t : reactors) t.join();
    if (g_upstream) g_upstream->stop();  // 排空异步转发任务（ddos 此时仍存活）
    shield.stop();
    TamperCache::instance().stop();      // 停机前把脏基线落盘
    EventSink::instance().stop();
    TrafficSink::instance().stop();
    return 0;
}
