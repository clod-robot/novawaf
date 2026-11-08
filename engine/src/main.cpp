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
#include "novawaf/core/siem_exporter.h"
#include "novawaf/net/upstream_forwarder.h"
#include "novawaf/net/request_sanitizer.h"
#include "novawaf/protect/escalation_guard.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/detect/custom_rules.h"
#include "novawaf/detect/cve_patch.h"
#include "novawaf/detect/regex_patch.h"
#include "novawaf/detect/ips_engine.h"

// 引擎版本号：与仓库根 VERSION 文件一致，发版时同步更新
#define NOVAWAF_VERSION "1.2.0-rc.3"
#include "novawaf/detect/threat_intel.h"
#include "novawaf/detect/ransomware_detector.h"
#include "novawaf/av/clamav_client.h"
#include "novawaf/av/yara_detector.h"
#include "novawaf/av/magic_detector.h"
#include "novawaf/av/external_intel.h"
#include "novawaf/fw/fw_ban.h"
#include "novawaf/protect/cc_guard.h"
#include "novawaf/protect/behavior_guard.h"
#include "novawaf/protect/bot_guard.h"
#include "novawaf/protect/dynamic_shield.h"
#include "novawaf/protect/fingerprint.h"
#include "novawaf/protect/geo_filter.h"
#include "novawaf/protect/honeypot_guard.h"
#include "novawaf/protect/honeypot_decoy.h"
#include "novawaf/protect/iplist_filter.h"
#include "novawaf/protect/path_policy.h"
#include "novawaf/protect/rmi_guard.h"
#include "novawaf/core/waf_mode.h"
#include "novawaf/protect/block_page.h"
#include "novawaf/protect/brute_guard.h"
#include "novawaf/protect/mimic.h"
#include "novawaf/protect/tamper_cache.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/limit/endpoint_rate_guard.h"
#include "novawaf/net/http_parser.h"
#include "novawaf/net/tls_context.h"
#include "novawaf/net/bridge.h"
#include "novawaf/net/h2_session.h"
#include "novawaf/net/tls_conn.h"
#include "novawaf/net/h3_server.h"
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/http_transport.h"
#include "novawaf/api/api_asset.h"
#include "novawaf/api/api_guard.h"
#include "novawaf/ai/agentic_engine.h"
#include "novawaf/accel/accel_runtime.h"

#include <fstream>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <execinfo.h>   // debug-point segv-bt: 信号安全栈回溯
#include <sys/stat.h>
#include <time.h>
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
#include <sys/wait.h>
#include <poll.h>

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

// SIGQUIT/SIGTERM/SIGINT 优雅排空请求（drain）：各 reactor 停止接受新连接，
// 刷完在途响应后退出（零停机滚动重启由 master 先发 SIGQUIT 给旧 worker）。
static volatile sig_atomic_t g_drainReq = 0;
static void onDrainSignal(int) { g_drainReq = 1; }

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
// uri/host 随事件携带，归档后可按 API(host+uri) 维度统计拦截量
static void emitEvt(const std::string& ip, const std::string& cat,
                    const std::string& action, const std::string& ruleId,
                    const std::string& matched,
                    const std::string& uri = "", const std::string& host = "",
                    const std::string& traceId = "") {
    AttackEvent e;
    e.ts = (int64_t)std::time(nullptr);
    e.ip = ip; e.category = cat; e.action = action; e.ruleId = ruleId; e.matched = matched;
    e.uri = uri; e.host = host; e.traceId = traceId;
    EventBus<AttackEvent>::instance().publish(e);
}

// 为引擎直接构造的非拦截响应（502/429/维护页/跳转）注入统一 Server 头，
// 消除"无 Server 头"与拦截响应/静态页之间的指纹差异。拦截响应由 BlockPage 自带 Server 头，无需调用。
static void injectServerLine(std::string& resp) {
    if (WafMode::isPublic(WafMode::instance().current())) return;
    size_t p = resp.find("\r\n");
    if (p != std::string::npos)
        resp.insert(p + 2, "Server: " + MimicDefense::siteBanner() + "\r\n");
}

// 全站统一人格的通用错误页出口（413/429/400 等低频错误），
// extraHead 可携带 Retry-After 等附加响应头。
static std::string errResp(int status, const char* statusText,
                           const std::string& extraHead = "") {
    if (WafMode::isPublic(WafMode::instance().current())) {
        std::string r = "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n" +
                        extraHead + "Content-Length: 0\r\n\r\n";
        size_t p = r.find("\r\n");
        r.insert(p + 2, "Server: NovaWAF\r\nX-WAF: NovaWAF\r\n");
        return r;
    }
    return BlockPage::renderStatus(status, statusText, extraHead);
}

// 统一拦截/挑战响应出口：生成追踪ID → 事件上报（携带 trace 供溯源）→ 按指纹模式渲染独立拦截页。
// HIDDEN（默认）：无品牌通用页 + Server: nginx；PUBLIC：品牌页 + X-WAF 头（wafw00f 可识别）。
static std::string blockResp(const std::string& ip, const std::string& cat,
                             const std::string& ruleId, const std::string& matched,
                             const std::string& uri, const std::string& host,
                             bool challenge = false, bool scanner = false) {
    std::string tid = BlockPage::genTraceId();
    emitEvt(ip, cat, challenge ? "challenge" : "block", ruleId, matched, uri, host, tid);
    bool branded = WafMode::isPublic(WafMode::instance().current());
    // HIDDEN（默认）：全站统一固定 IIS 人格。第三方复测证实轮换人格会在
    // 静态/动态/拦截响应之间制造指纹分裂（比不伪装更易识破），故拦截页与
    // 转发响应、错误页收敛为同一画像。检测语义零影响：内部解析始终全维度最严。
    if (!branded) {
        const std::string banner = MimicDefense::siteBanner();
        if (challenge)
            return BlockPage::renderMimic(503, "Service Unavailable", 2, banner.c_str(), tid);
        return BlockPage::renderMimic(403, "Forbidden", 2, banner.c_str(), tid);
    }
    if (challenge)
        return BlockPage::render("503", "Service Unavailable", "访问频率异常",
                                 "系统检测到异常访问行为，请稍后重试", tid, branded);
    return BlockPage::render("403", "Forbidden", "请求已被拦截",
                             branded ? ("命中安全防护策略：" + cat) : "命中站点安全策略", tid, branded);
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

// bridge.h 声明的受信代理判断（单 TU 构建，桥接层回调用）
namespace novawaf {
bool novaTrustedProxy(const std::string& ip) { return isTrustedProxy(ip); }
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
    // 文件回退分支：以 mtime+size 作为签名短路。60s 轮询场景下文件几乎不变，
    // 无此短路则每轮全量重读重解析并打印 hot-reloaded 日志（日志刷屏根因）。
    struct stat fst{};
    if (::stat(filePath.c_str(), &fst) != 0) return {};  // 文件不存在
    std::string fsig = "F:" + std::to_string((long long)fst.st_mtime) +
                       ":" + std::to_string((long long)fst.st_size);
    if (fsig == inoutCksum) return {};  // 内容未变，跳过重解析
    std::ifstream in(filePath);
    if (!in) return {};
    std::vector<std::string> lines;
    std::string ln;
    while (std::getline(in, ln)) lines.push_back(ln);
    inoutCksum = fsig;
    return lines;
}

static int createListenFd(int port, int backlog, const char* bindAddr = nullptr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // NOVA_LISTEN_ADDR 指定绑定地址（默认 0.0.0.0 兼容旧部署）。生产应设 127.0.0.1：
    // 引擎只接受同机 nginx 反代流量，杜绝绕过 443 直连 WAF 端口的暴露面。
    // bindAddr 显式指定时优先（TLS 公网监听走 NOVA_TLS_ADDR，不回退 NOVA_LISTEN_ADDR）。
    const char* bindIp = (bindAddr && *bindAddr) ? bindAddr : getenv("NOVA_LISTEN_ADDR");
    addr.sin_addr.s_addr = (bindIp && *bindIp) ? inet_addr(bindIp) : htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, backlog) < 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

// UDP (QUIC/h3) 监听：SO_REUSEPORT 每 reactor 一个套接字，内核对 4 元组分流，
// 同一会话的数据包稳定落到同一 reactor（连接迁移不做）。
static int createUdpFd(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // h3 是公网入口，默认 0.0.0.0；NOVA_H3_ADDR 可收紧
    const char* bindIp = getenv("NOVA_H3_ADDR");
    addr.sin_addr.s_addr = (bindIp && *bindIp) ? inet_addr(bindIp) : htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
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
// 从请求头提取会话 cookie。可识别的名字 = 品牌名 novasid + 拟态人格池全部 cookie 名
// （跨窗轮换后旧窗签发的 cookie 仍可被识别，保证 UV 去重与行为分析连续）。
static std::string getCookieSid(const std::unordered_map<std::string,std::string>& headers) {
    static const char* kNames[] = {
        "novasid", "sid", "sess", "session", "token",
        "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId"
    };
    for (auto& [k, v] : headers) {
        std::string lk = k; for (auto& c : lk) c = (char)tolower((unsigned char)c);
        if (lk == "cookie") {
            size_t p = 0;
            while (p < v.size()) {
                size_t sc = v.find(';', p);
                std::string kv = (sc == std::string::npos) ? v.substr(p) : v.substr(p, sc - p);
                size_t a = 0; while (a < kv.size() && isspace((unsigned char)kv[a])) ++a;
                for (auto* n : kNames) {
                    size_t nl = std::strlen(n);
                    if (kv.compare(a, nl, n) == 0 && a + nl < kv.size() && kv[a + nl] == '=')
                        return kv.substr(a + nl + 1);
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

// 是否 API 接口请求：/api/ 前缀的 XHR/JSON 调用。
// Bot JS 挑战只对页面路由有意义；API 客户端（axios/脚本）不执行 JS，挑战等于永久误杀。
static bool isApiPath(const std::string& path) {
    return path.rfind("/api/", 0) == 0 || path == "/api";
}

// ---- HTTP keep-alive 支持 ----
// 从接收缓冲区切出一个完整请求。
// 返回 1=完整(rawReq/totalLen) 0=不完整 -1=协议错误
//      -2=声明的 Content-Length 超过请求体上限(应 413) -3=头部超限(应 400)
// maxHeaders：头部字段数量上限（默认 128）。第三方复测证实纯字节上限(16KB)下
// 约 500 个小头部才触发拒绝，数量级过宽；数量与字节双阈值收紧模糊测试空间。
static int nextRequest(const std::string& buf, std::string& rawReq, size_t& totalLen,
                       size_t maxBody, size_t maxHead, size_t maxHeaders) {
    size_t he = buf.find("\r\n\r\n");
    if (he == std::string::npos) {
        // 头部超上限仍不完整：按超限处理，拒绝并断连（防 Slowloris 型无限缓冲）
        return buf.size() > maxHead ? -3 : 0;
    }
    if (he > maxHead) return -3;  // 头区总长超限（16KB 默认，对齐评估基线）
    // 头部字段数量上限：请求行之后每个 "\r\n" 分隔一个头部字段
    size_t nHeaders = 0;
    for (size_t p = buf.find("\r\n"); p != std::string::npos && p < he;
         p = buf.find("\r\n", p + 2)) ++nHeaders;
    if (nHeaders > maxHeaders) return -3;
    std::string head = buf.substr(0, he);
    std::string low = head;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    // Transfer-Encoding: chunked 优先于 Content-Length（RFC 9112 §6.3）。
    // 逐 chunk 扫描出完整帧边界；解码后总长超 maxBody 按 -2 拒绝。
    bool chunked = false;
    {
        size_t p = low.find("transfer-encoding:");
        if (p != std::string::npos) {
            size_t e = low.find("\r\n", p);
            std::string v = low.substr(p + 18, (e == std::string::npos ? low.size() : e) - (p + 18));
            chunked = v.find("chunked") != std::string::npos;
        }
    }
    if (chunked) {
        size_t pos = he + 4;
        size_t decoded = 0;
        while (true) {
            size_t eol = buf.find("\r\n", pos);
            if (eol == std::string::npos) return 0;          // size 行未到齐
            if (eol == pos || eol - pos > 32) return -1;     // 空/畸形超长 size 行
            unsigned long long csz = 0;
            bool any = false;
            for (size_t i = pos; i < eol; ++i) {
                char ch = buf[i];
                if (ch == ';') break;                        // chunk 扩展忽略
                int d;
                if (ch >= '0' && ch <= '9') d = ch - '0';
                else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                else if (ch == ' ' || ch == '\t') continue;
                else return -1;
                csz = csz * 16 + (unsigned)d;
                any = true;
                if (csz > (1ULL << 40)) return -2;           // 防乘法溢出
            }
            if (!any) return -1;
            if (csz == 0) {
                // 末块后 trailer（可为空）：帧尾 = 首个空行结束
                size_t t = buf.find("\r\n\r\n", pos);
                if (t == std::string::npos) return 0;        // trailer 未到齐
                totalLen = t + 4;
                rawReq = buf.substr(0, totalLen);
                return 1;
            }
            decoded += (size_t)csz;
            if (decoded > maxBody) return -2;
            size_t dataEnd = eol + 2 + (size_t)csz;
            if (dataEnd + 2 > buf.size()) return 0;          // 数据+尾 CRLF 未到齐
            pos = dataEnd + 2;
        }
    }
    long long bodyLen = -1;
    {   // 解析 Content-Length（大小写不敏感）
        size_t p = low.find("content-length:");
        if (p != std::string::npos) {
            size_t e = low.find("\r\n", p);
            std::string v = low.substr(p + 15, (e == std::string::npos ? low.size() : e) - (p + 15));
            bodyLen = std::atoll(v.c_str());
        }
    }
    if (bodyLen < 0) bodyLen = 0;
    // 请求体大小限制：声明即超限直接拒绝，不再继续缓冲（防大 body 耗尽内存/连接池）
    if ((size_t)bodyLen > maxBody) return -2;
    totalLen = he + 4 + (size_t)bodyLen;
    if (buf.size() < totalLen) return 0;
    rawReq = buf.substr(0, totalLen);
    return 1;
}

// JSON 嵌套深度护栏（字符串状态机：跳过 "..." 字符串与 \ 转义内的括号，
// 只对结构字符 { [ 入栈计数，} ] 出栈）。深度超 limit 立即返回（O(n) 单次遍历
// + 提前退出，病态嵌套体不会拖慢热路径）。引号内的括号不计入，合法 JSON 零误判。
static bool jsonDepthExceeds(const std::string& body, size_t limit) {
    size_t depth = 0;
    bool inStr = false, esc = false;
    for (char ch : body) {
        if (inStr) {
            if (esc) esc = false;
            else if (ch == '\\') esc = true;
            else if (ch == '"') inStr = false;
            continue;
        }
        switch (ch) {
            case '"': inStr = true; break;
            case '{': case '[':
                if (++depth > limit) return true;
                break;
            case '}': case ']':
                if (depth > 0) --depth;
                break;
            default: break;
        }
    }
    return false;
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

// 单 Reactor 线程：h1 明文 + TLS(h1/h2) + QUIC(h3) 监听 + 读请求 + 检测 + 回包。
// TLS/QUIC 请求经 H1Bridge 回环进本 reactor 的 h1 检测端口（唯一检测真值源）。
static void reactorLoop(int listenFd, int tlsPort, int h3Port, SSL_CTX* tlsCtx, SSL_CTX* quicCtx,
                        int h1Port, DetectionPipeline& pipeline,
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

    // TLS (h1/h2) 公网监听：每 reactor SO_REUSEPORT 独立套接字
    int tlsFd = -1;
    if (tlsCtx && tlsPort > 0) {
        const char* ta = getenv("NOVA_TLS_ADDR");
        tlsFd = createListenFd(tlsPort, 16384, (ta && *ta) ? ta : "0.0.0.0");
        if (tlsFd >= 0) {
            epoll_event lev{};
            lev.events = EPOLLIN;
            lev.data.fd = tlsFd;
            epoll_ctl(epfd, EPOLL_CTL_ADD, tlsFd, &lev);
        } else {
            std::fprintf(stderr, "[reactor %d] tls listen :%d failed\n", idx, tlsPort);
        }
    }
    // QUIC (h3) 公网 UDP 监听
    int quicFd = -1;
    if (quicCtx && h3Port > 0) {
        quicFd = createUdpFd(h3Port);
        if (quicFd >= 0) {
            epoll_event qev{};
            qev.events = EPOLLIN;
            qev.data.fd = quicFd;
            epoll_ctl(epfd, EPOLL_CTL_ADD, quicFd, &qev);
        } else {
            std::fprintf(stderr, "[reactor %d] quic udp :%d failed\n", idx, h3Port);
        }
    }

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
        int64_t firstByteMs = 0;  // 当前不完整请求的首字节时间（慢速请求检测）
    };
    std::unordered_map<int, ConnState> conns;
    std::mutex busyMtx;
    std::unordered_set<int> busy;   // 已交给异步转发器、尚未回写完成的 fd
    constexpr int64_t kKeepAliveIdleMs = 15000;  // 空闲连接 15s 回收
    // 请求体/头部上限与慢速请求时限（环境变量可调的冷启动常量，多 reactor 共享只读）
    static const size_t kMaxBody = [] {
        const char* e = getenv("NOVA_MAX_BODY");
        return (e && *e) ? (size_t)std::atoll(e) : (size_t)1048576;  // 默认 1MB
    }();
    static const size_t kMaxHead = [] {
        const char* e = getenv("NOVA_MAX_HEAD");
        return (e && *e) ? (size_t)std::atoll(e) : (size_t)16384;    // 默认 16KB
    }();
    static const size_t kMaxHeaders = [] {
        const char* e = getenv("NOVA_MAX_HEADERS");
        return (e && *e) ? (size_t)std::atoll(e) : (size_t)128;      // 默认 128 个
    }();
    static const int64_t kSlowReqMs = [] {
        const char* e = getenv("NOVA_SLOW_REQ_MS");
        return (e && *e) ? (int64_t)std::atoll(e) : (int64_t)10000;  // 默认 10s（头部阶段绝对上限）
    }();
    // body 阶段最小速率（字节/秒）：body 时限与大小独立挂钩，预算 = 头时限 + CL/最小速率。
    // 4MB @ 1KB/s = 4096s 合法慢传不被绝对上限误杀；零进度滴灌由 front nginx
    // client_body_timeout(12s 空闲) + 本时限双层切断。
    static const int64_t kSlowMinBps = [] {
        const char* e = getenv("NOVA_SLOW_MIN_BPS");
        return (e && *e) ? (int64_t)std::atoll(e) : (int64_t)1024;   // 默认 1KB/s
    }();
    static const size_t kJsonMaxDepth = [] {
        const char* e = getenv("NOVA_JSON_MAX_DEPTH");
        return (e && *e) ? (size_t)std::atoll(e) : (size_t)100;      // 默认 100 层
    }();
    auto nowMs = [] { return std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch()).count(); };

    // ---- TLS/QUIC 桥接层（per-reactor，无锁，仅本线程驱动）----
    // TLS/QUIC 侧解析出的请求合成为标准 h1 字节，经回环连接池送入本 reactor 的
    // h1 检测端口（唯一检测真值源），响应按来源协议回帧。bridge 须先声明
    // （TlsConn/H3Server 持其引用）；回调统一带 weak 存活令牌，任意析构顺序安全。
    H1Bridge bridge(epfd, (uint16_t)h1Port);
    std::unordered_map<int, std::unique_ptr<TlsConn>> tlsConns;
    std::unique_ptr<H3Server> h3;
    if (quicFd >= 0 && quicCtx)
        h3 = std::make_unique<H3Server>(quicFd, quicCtx, bridge, kMaxBody);

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
            // 与 accept 侧对称：可信反代连接未计入 onConnect，此处不释放
            if (!isTrustedProxy(ipstr)) ddos.onDisconnect(ipstr);
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

    // 优雅排空（SIGQUIT/SIGTERM）：停接受新连接 → 刷完在途响应 → 退出（30s 兜底）
    // 命名 drainMode：内层请求写路径另有局部 draining（EPOLLOUT 背压语义），避免遮蔽。
    bool drainMode = false;
    int64_t drainStartMs = 0;
    while (g_running) {
        if (g_drainReq && !drainMode) {
            drainMode = true;
            drainStartMs = nowMs();
            epoll_ctl(epfd, EPOLL_CTL_DEL, listenFd, nullptr);
            close(listenFd);
            listenFd = -1;
            if (tlsFd >= 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, tlsFd, nullptr);
                close(tlsFd);
                tlsFd = -1;
            }
            // quicFd 只从 epoll 摘除不 close：h3->sweep() 仍需它 sendto 刷写在途响应
            if (quicFd >= 0) epoll_ctl(epfd, EPOLL_CTL_DEL, quicFd, nullptr);
            std::printf("[reactor %d] draining\n", idx);
        }
        if (drainMode) {
            bool h1Idle;
            {
                std::lock_guard<std::mutex> lk(busyMtx);
                h1Idle = conns.empty() && busy.empty();
            }
            bool drained = h1Idle && tlsConns.empty() && bridge.inFlight() == 0 &&
                           (!h3 || h3->connCount() == 0);
            if (drained || nowMs() - drainStartMs > 30000) break;
        }
        // epoll 超时向 h3 最近到期时间收敛（QUIC 重传/idle 定时器）
        int epTimeout = 200;
        if (h3) {
            int ms = h3->msToNextExpiry();
            if (ms >= 0 && ms < epTimeout) epTimeout = ms;
        }
        int n = epoll_wait(epfd, events.data(), (int)events.size(), epTimeout);
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == tfd) { uint64_t exp; while (read(tfd, &exp, 8) > 0) {} continue; }
            if (fd == listenFd) {
                while (true) {
                    sockaddr_in caddr{};
                    socklen_t clen = sizeof(caddr);
                    int cfd = accept(listenFd, (sockaddr*)&caddr, &clen);
                    if (cfd < 0) break;
                    // DDoS 防护：取源 IP，检查并发上限/连接速率/黑名单。
                    // 可信反代豁免：前置 nginx 部署下 accept 对端恒为回环地址，全站流量会
                    // 挤进单一计数桶；且释放路径键不对称（短连接由转发器按真实客户端 IP
                    // 释放）导致计数只增不减，泄漏累积后误封回环地址造成全站自我 DoS。
                    // 可信代理入口的连接级防护前置到 nginx limit_conn / nft connlimit，
                    // 真实客户端的速率/封禁在请求层按 XFF 解析后的 clientIp 键控（不受影响）。
                    char ipstr[32] = {0};
                    inet_ntop(AF_INET, &caddr.sin_addr, ipstr, sizeof(ipstr));
                    if (!isTrustedProxy(ipstr) && !ddos.onConnect(ipstr)) {
                        // 复测 P1：封禁期黑洞（accept 后静默关闭，客户端只能等 8s
                        // 超时）。已封禁 IP 连接级即回 429 + 真实 Retry-After
                        // （封禁剩余秒数），快速失败且给出可信恢复时间；
                        // 纯并发超限仍快速关闭，不消耗应用层资源。
                        if (ddos.isBanned(ipstr)) {
                            std::string resp = errResp(429, "Too Many Requests",
                                "Retry-After: " + std::to_string(std::max(1, ddos.bannedRemainSec(ipstr))) + "\r\n");
                            ::send(cfd, resp.data(), resp.size(), MSG_NOSIGNAL);
                        }
                        close(cfd);
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
                    { std::lock_guard<std::mutex> lk(busyMtx); conns[cfd].lastActiveMs = nowMs(); }
                }
                continue;
            }
            // TLS 公网入口 accept：ALPN 协商 h2 / http/1.1，会话委托 TlsConn
            if (tlsFd >= 0 && fd == tlsFd) {
                while (true) {
                    sockaddr_in caddr{};
                    socklen_t clen = sizeof(caddr);
                    int cfd = accept(tlsFd, (sockaddr*)&caddr, &clen);
                    if (cfd < 0) break;
                    char ipstr[32] = {0};
                    inet_ntop(AF_INET, &caddr.sin_addr, ipstr, sizeof(ipstr));
                    // 与 h1 accept 对称：受信反代豁免连接级计数（前置代理见 h1 分支注释）
                    if (!isTrustedProxy(ipstr) && !ddos.onConnect(ipstr)) {
                        close(cfd);
                        continue;
                    }
                    setNonblock(cfd);
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    SSL* ssl = SSL_new(tlsCtx);
                    if (!ssl) {
                        if (!isTrustedProxy(ipstr)) ddos.onDisconnect(ipstr);
                        close(cfd);
                        continue;
                    }
                    SSL_set_fd(ssl, cfd);
                    epoll_event ce{};
                    ce.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    ce.data.fd = cfd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ce) < 0) {
                        if (!isTrustedProxy(ipstr)) ddos.onDisconnect(ipstr);
                        SSL_free(ssl);
                        close(cfd);
                        continue;
                    }
                    auto tc = std::make_unique<TlsConn>(cfd, ssl, epfd, bridge,
                                                        std::string(ipstr), kMaxBody);
                    TlsConn* raw = tc.get();
                    tlsConns[cfd] = std::move(tc);
                    raw->onEvent(EPOLLIN);  // 触发非阻塞握手（内部按 WANT_READ/WRITE 订阅）
                    if (raw->closed()) {    // 握手立即失败
                        if (!isTrustedProxy(ipstr)) ddos.onDisconnect(ipstr);
                        tlsConns.erase(cfd);
                    }
                }
                continue;
            }
            // QUIC 数据报入口（h3）
            if (quicFd >= 0 && fd == quicFd) {
                if (h3) h3->onReadable();
                continue;
            }
            // 桥回环连接事件
            if (bridge.owns(fd)) {
                bridge.onEvent(fd, events[i].events);
                continue;
            }
            // TLS 会话事件
            {
                auto tit = tlsConns.find(fd);
                if (tit != tlsConns.end()) {
                    tit->second->onEvent(events[i].events);
                    if (tit->second->closed()) {
                        const std::string& pip = tit->second->peerIp();
                        if (!isTrustedProxy(pip)) ddos.onDisconnect(pip);
                        tlsConns.erase(tit);
                    }
                    continue;
                }
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
            // 并发约束：conns 同时被异步转发完成回调(IO 线程)访问，所有访问必须持 busyMtx；
            // closeConn 内部会加锁，须在锁外调用。
            {
                bool werr = false, doClose = false, backpressured = false, flushed = false, found = false;
                {
                    std::lock_guard<std::mutex> lk(busyMtx);
                    auto cd = conns.find(fd);
                    if (cd != conns.end() && !cd->second.outQ.empty()) {
                        found = true;
                        ConnState& cs = cd->second;
                        while (cs.outPos < cs.outQ.size()) {
                            ssize_t w = send(fd, cs.outQ.data() + cs.outPos,
                                             cs.outQ.size() - cs.outPos, MSG_NOSIGNAL | MSG_DONTWAIT);
                            if (w > 0) { cs.outPos += (size_t)w; }
                            else if (w < 0 && errno == EINTR) { continue; }
                            else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { break; }
                            else { werr = true; break; }
                        }
                        if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) werr = true;
                        if (!werr) {
                            if (cs.outPos < cs.outQ.size()) {
                                backpressured = true;  // 仍背压，等待下一次 EPOLLOUT
                            } else {
                                // 本响应已完整排空
                                flushed = true;
                                doClose = cs.closeAfterFlush;
                                cs.outQ.clear(); cs.outPos = 0; cs.closeAfterFlush = false;
                                epoll_event ev{}; ev.events = EPOLLIN | EPOLLET; ev.data.fd = fd;
                                epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);  // 回到只关心可读
                            }
                        }
                    }
                }
                if (werr) { closeConn(fd); continue; }
                if (backpressured) continue;
                if (flushed && doClose) { closeConn(fd); continue; }
                // 完整排空且 keep-alive：落到下面正常读/处理，顺带把背压期间已到达的请求 drain 掉（避免漏 ET 边沿）
                (void)found;
            }
            {
                char buf[8192];
                bool peerClosed = false, readErr = false;
                while (true) {
                    ssize_t r = read(fd, buf, sizeof(buf));
                    if (r > 0) {
                        std::lock_guard<std::mutex> lk(busyMtx);
                        ConnState& cs = conns[fd];
                        if (cs.inbuf.empty()) cs.firstByteMs = nowMs();  // 新请求首字节
                        cs.inbuf.append(buf, (size_t)r);
                    }
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
                {   // 空闲超时回收（惰性）：仅对无在途请求的连接；
                    // 有未完成请求(inbuf 非空)的连接交给 sweep 慢速判定回 408，
                    // 否则滴灌 body 到 15s 时会被此处按 idle 静默断连（V6 P0 复现点）。
                    std::lock_guard<std::mutex> lk(busyMtx);
                    auto it = conns.find(fd);
                    if (it != conns.end() && it->second.inbuf.empty() &&
                        nowMs() - it->second.lastActiveMs > kKeepAliveIdleMs) {
                        keepOpen = false; break;
                    }
                }
                std::string rawReq; size_t reqLen = 0;
                int nr = 0;
                {
                    std::lock_guard<std::mutex> lk(busyMtx);
                    auto it = conns.find(fd);
                    if (it == conns.end()) { keepOpen = false; break; }
                    nr = nextRequest(it->second.inbuf, rawReq, reqLen, kMaxBody, kMaxHead, kMaxHeaders);
                    if (nr == 0) break;        // 数据不完整，等更多字节
                }
                // 请求体/头部超限：立即统一错误页拒绝并断连，不再缓冲
                if (nr == -2 || nr == -3) {
                    std::string e = (nr == -2)
                        ? errResp(413, "Request Entity Too Large")
                        : errResp(400, "Bad Request");
                    setRespConnection(e, false);
                    // 取连接对端 IP 记录事件（解析前拒绝，拿不到 req）
                    std::string peer;
                    {
                        sockaddr_in pa{}; socklen_t pl = sizeof(pa);
                        if (getpeername(fd, (sockaddr*)&pa, &pl) == 0) {
                            char ipb[32] = {0};
                            if (inet_ntop(AF_INET, &pa.sin_addr, ipb, sizeof(ipb))) peer = ipb;
                        }
                    }
                    emitEvt(peer, nr == -2 ? "BodyLimit" : "HeadLimit", "block", "",
                            nr == -2 ? "body too large" : "header too large");
                    const char* wp = e.data(); size_t wl = e.size();
                    while (wl > 0) {
                        ssize_t w = ::send(fd, wp, wl, MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (w > 0) { wp += w; wl -= (size_t)w; }
                        else if (w < 0 && errno == EINTR) continue;
                        else break;
                    }
                    keepOpen = false; break;
                }
                if (nr < 0) { keepOpen = false; break; }  // 协议错误
                bool keepAlive = false;
                std::string data = rawReq;   // 检测/转发使用的完整请求字节（转发前做代理头清洗，故非 const）
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
                    // 统一错误页保留端点：nginx 解析层直返的 400/408/413/414/429 等错误
                    // 带 Server: nginx 真实指纹（本机 nginx 无 headers_more 无法改写），
                    // nac.conf 用 error_page 劫持到此路径，由 WAF 按全站人格渲染出口，
                    // 消除「畸形请求零载荷拿真实指纹」的旁路（V6 复测：9 条畸形 4 条 nginx 直返）。
                    // nginx 私有码 494-497 不外露，统一按 400 渲染。
                    if (req.path.compare(0, 15, "/__novawaf-err/") == 0) {
                        int code = std::atoi(req.path.c_str() + 15);
                        const char* txt = "Bad Request";
                        switch (code) {
                            case 400: break;
                            case 404: txt = "Not Found"; break;
                            case 408: txt = "Request Timeout"; break;
                            case 413: txt = "Request Entity Too Large"; break;
                            case 414: txt = "Request-URI Too Large"; break;
                            case 429: txt = "Too Many Requests"; break;
                            case 502: txt = "Bad Gateway"; break;
                            case 505: txt = "HTTP Version Not Supported"; break;
                            default:  code = 400; break;
                        }
                        std::string e = errResp(code, txt, code == 429 ? "Retry-After: 30\r\n" : "");
                        setRespConnection(e, false);
                        const char* wp = e.data(); size_t wl = e.size();
                        while (wl > 0) {
                            ssize_t w = ::send(fd, wp, wl, MSG_NOSIGNAL | MSG_DONTWAIT);
                            if (w > 0) { wp += w; wl -= (size_t)w; }
                            else if (w < 0 && errno == EINTR) continue;
                            else break;
                        }
                        keepOpen = false; break;
                    }
                    keepAlive = wantsKeepAlive(req);
                    // 拟态探测干扰：扫描器 UA 特征的拦截响应每次随机人格（同窗内亦矛盾）
                    const bool scannerUa = MimicDefense::looksLikeScanner(hdrCi(req, "User-Agent"));
                    // 直连对端 IP 按连接缓存（keep-alive 多请求只解析一次）
                    {
                        std::lock_guard<std::mutex> lk(busyMtx);
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
                    const std::string peerIp = req.clientIp;  // 直连对端（XFF 解析前）
                    const bool trustedPeer = isTrustedProxy(ipstr);
                    // 防绕过：仅当直连对端是可信反向代理(NOVA_TRUSTED_PROXIES)时，才采信
                    // X-Forwarded-For/X-Real-IP 的最左原始 IP；否则忽略客户端伪造头，用真实对端 IP。
                    if (trustedPeer) {
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
                    // 转发头清洗：剥离客户端可自报的代理族头（X-Client-IP/Forwarded/
                    // X-Forwarded-Host 等），防其穿透至上游应用被采信；检测模型
                    // req.headers 不受影响（含 X-Original-* 伪造取证头仍可检测）。
                    RequestSanitizer::sanitizeForwardHeaders(data, peerIp, trustedPeer);

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
                    // 全局防护模式（指纹三态）：OFF=旁路，全站降级为观察（仅记录不拦截不封禁）；
                    // HIDDEN/PUBLIC 仅影响拦截页品牌与会话 cookie 指纹，不影响检测语义。
                    const WafMode::Mode wafMode = WafMode::instance().current();
                    if (wafMode == WafMode::OFF) appMode = 1;
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
                    // fw L3 封禁上报闸门：仅真实攻击命中（黑名单/TI/Geo/规则管线）置位。
                    // 限流族（CC/端点分级/行为锁/DDoS/慢速）为自愈型 429 语义，不升级 L3 封禁，
                    // 否则会出现 RA 失真、封禁递增、封禁期黑洞（复测 P0/P1 根因）。
                    bool fwEscalate = false;

                    std::string outResp;
                    bool asyncHandled = false;  // 异步转发器接管后，reactor 跳过回写与关闭
                    // 上游不可达时的劫持目标：仅对浏览器页面导航生效（GET + Accept: text/html），
                    // 接口/XHR 调用保持 502，避免客户端拿到 HTML 跳转页而解析失败。
                    // 优先用应用配置的登录页，未配置则退化到同源 /login。
                    std::string failRedirect;
                    // API 资产键（观测登记后填充）：同步与异步转发路径都用它回写响应状态码
                    std::string apiAssetKey;
                    {
                        std::string acc = hdrCi(req, "Accept");
                        bool navReq = req.method == "GET" &&
                                      acc.find("text/html") != std::string::npos &&
                                      hdrCi(req, "X-Requested-With").empty();
                        if (app && navReq) failRedirect = app->loginUrl.empty() ? "/login" : app->loginUrl;
                    }
                    auto buildRedirect = [](const std::string& url) {
                        std::string body =
                            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                            "<meta http-equiv=\"refresh\" content=\"0;url=" + url + "\">"
                            "<title>正在跳转登录</title></head><body>"
                            "<p>应用暂不可用，正在跳转到登录页…</p>"
                            "<p><a href=\"" + url + "\">点此继续</a></p></body></html>";
                        return "HTTP/1.1 302 Found\r\nLocation: " + url + "\r\n"
                               "Content-Type: text/html; charset=utf-8\r\n"
                               "Content-Length: " + std::to_string(body.size()) + "\r\n"
                               "Cache-Control: no-store\r\n\r\n" + body;
                    };
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
                            ctx.apiAssetKey = apiAssetKey;
                            ctx.keepAlive = keepAlive;
                            ctx.failRedirect = failRedirect;
                            // 异步转发完成(在 IO 线程)：keep-alive 则重新挂回 epoll 复用，否则关闭。
                            // 注：ddos 并发计数由转发器的 onDisconnect 统一释放，此处不重复。
                            ctx.onComplete = [epfd, &busyMtx, &busy, &conns, nowMs]
                                             (int cfd, bool ka) {
                                epoll_event e2{}; e2.events = EPOLLIN | EPOLLET; e2.data.fd = cfd;
                                if (ka) {
                                    // 先挂回 epoll 再解锁 busy，避免 reactor 在间隙看到未注册的非 busy fd
                                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &e2) < 0 && errno == EEXIST)
                                        epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &e2);  // 兜底：已注册则改事件
                                    std::lock_guard<std::mutex> lk(busyMtx);
                                    busy.erase(cfd);
                                    auto it = conns.find(cfd);   // conns 跨线程共享，必须持 busyMtx
                                    if (it != conns.end()) it->second.lastActiveMs = nowMs();
                                } else {
                                    epoll_ctl(epfd, EPOLL_CTL_DEL, cfd, nullptr);
                                    { std::lock_guard<std::mutex> lk(busyMtx);
                                      busy.erase(cfd);
                                      conns.erase(cfd); }        // conns 跨线程共享，必须持 busyMtx
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
                            // 复测新增项：上游 nginx 默认错误页正文人格化（同步回退路径）
                            BlockPage::rewriteUpstreamErrorBody(outResp);
                            // 行为识别响应侧记账（404/301 频次信号，同步回退路径）
                            BehaviorGuard::instance().noteStatus(req.clientIp, respStatus(outResp));
                            // API 资产状态码记账（同步回退路径）
                            if (!apiAssetKey.empty())
                                ApiAssetRegistry::instance().noteStatus(apiAssetKey, respStatus(outResp));
                            // 网页防篡改：同步回退路径同样过基线校验
                            if (data.compare(0, 4, "GET ") == 0) {
                                if (auto restored = TamperCache::instance().process(
                                        "GET", hdrCi(req, "Host"), req.path, outResp, req.clientIp))
                                    outResp = std::move(*restored);
                            }
                            setRespConnection(outResp, keepAlive);
                            return false;
                        }
                        outResp = failRedirect.empty() ? k502 : buildRedirect(failRedirect);
                        setRespConnection(outResp, false);
                        injectServerLine(outResp);
                        return false;
                    };
                    _mark();  // [1] 解析+sid+app 结束，进入限流判定
                    if (appMode == 2) {
                        // 维护模式：所有请求返回维护页，不检测、不转发
                        outResp = kMaint;
                        injectServerLine(outResp);
                    } else if (!ddos.onRequest(req.clientIp)) {
                        // 请求速率超限 → 429 + 真实 Retry-After。
                        // 复测 P0 根因：此处曾联动 fw L3 封禁——限流本为秒级自愈，
                        // 却触发 120/240/480s 阶梯黑洞（RA 恒 30/60，实测恢复
                        // 210–469s，偏差 7–16 倍）。限流不再上报 fw 封禁，
                        // fw 保留给真实攻击（蜜罐升级/WAF 规则命中）。
                        int ra = ddos.isBanned(req.clientIp)
                               ? std::max(1, ddos.bannedRemainSec(req.clientIp)) : 1;
                        outResp = errResp(429, "Too Many Requests",
                                          "Retry-After: " + std::to_string(ra) + "\r\n");
                        shield.recordBlock();
                        emitEvt(req.clientIp, "DDoS", "block", "", "conn/rate limit", req.path, hdrCi(req, "Host"));
                        tBlocked = true;
                    } else if (!limiter.allow(req.clientIp)) {
                        // 令牌桶 50/s 回充，最坏 1s 后必有可用令牌
                        outResp = errResp(429, "Too Many Requests", "Retry-After: 1\r\n");
                        shield.recordBlock();
                        emitEvt(req.clientIp, "RateLimit", "block", "", "rate limit", req.path, hdrCi(req, "Host"));
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
                                outResp = blockResp(req.clientIp, "IpList", "IP-BLACK",
                                                    std::string("blacklisted ip ") + req.clientIp,
                                                    req.path, hdrCi(req, "Host"), false, scannerUa);
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true; fwEscalate = true;
                                break;
                            default: break;
                        }
                        // ---- API 资产自动发现 + API 级防护（Token 合法性 / 频率限制）----
                        // 顺序：资产登记（影子 API 首次发现）→ Token 校验 → API 限流 → Agentic 威胁索引。
                        // 全部 fail-open：策略未下发/Redis 不可用时规则表为空即放行。
                        bool apiShadow = false;
                        bool apiTokenIssue = false;
                        std::string apiTokenState;
                        std::string apiCtype = hdrCi(req, "Content-Type");
                        if (!whitelisted && !policyPass) {
                            ApiAssetRegistry::ObserveIn oi;
                            oi.appId = appId;
                            oi.method = req.method;
                            oi.contentType = apiCtype;
                            oi.hasAuth = !hdrCi(req, "Authorization").empty();
                            oi.hasCookie = !hdrCi(req, "Cookie").empty();
                            oi.query = &req.queryParams;
                            oi.paramCount = req.queryParams.size();
                            oi.ipHash = ((uint64_t)ipU(req.clientIp) * 0x9E3779B97F4A7C15ULL) >> 40;
                            apiAssetKey = ApiAssetRegistry::instance().observe(oi, req.path);
                            apiShadow = !ApiAssetRegistry::instance().isRegisteredPath(
                                appId, req.method, req.path);

                            // 令牌提取：Authorization: Bearer > X-API-Token/X-API-Key > 查询参数（泄露信号）
                            std::string apiToken;
                            bool tokenFromQuery = false;
                            {
                                std::string auth = hdrCi(req, "Authorization");
                                if (!auth.empty()) {
                                    size_t p = auth.find("Bearer ");
                                    apiToken = (p == std::string::npos) ? auth : auth.substr(p + 7);
                                }
                                if (apiToken.empty()) apiToken = hdrCi(req, "X-API-Token");
                                if (apiToken.empty()) apiToken = hdrCi(req, "X-API-Key");
                                if (apiToken.empty()) {
                                    static const char* kQN[] = {"access_token", "token", "jwt",
                                                                "id_token", "apikey", "api_key"};
                                    for (auto& [k, v] : req.queryParams) {
                                        std::string lk;
                                        lk.reserve(k.size());
                                        for (char c : k) lk.push_back((char)std::tolower((unsigned char)c));
                                        bool hit = false;
                                        for (auto* n : kQN) if (lk == n) { hit = true; break; }
                                        if (hit && !v.empty()) { apiToken = v; tokenFromQuery = true; break; }
                                    }
                                }
                            }
                            auto apiDec = ApiRateGuard::instance().assess(
                                req.clientIp, appId, req.method, req.path, apiToken, tokenFromQuery);
                            if (apiDec && apiDec->status == 401) {
                                apiTokenIssue = true;
                                apiTokenState = apiDec->reason;
                                outResp = errResp(401, "Unauthorized",
                                                  "WWW-Authenticate: Bearer realm=\"api\"\r\n");
                                emitEvt(req.clientIp, "APIAuth", "block", apiDec->ruleId,
                                        apiDec->detail, req.path, hdrCi(req, "Host"));
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true;
                            } else if (apiDec && apiDec->status == 429) {
                                outResp = errResp(429, "Too Many Requests",
                                                  "Retry-After: " +
                                                      std::to_string(apiDec->retryAfterSec) + "\r\n");
                                emitEvt(req.clientIp, "APILimit", "block", apiDec->ruleId,
                                        apiDec->detail, req.path, hdrCi(req, "Host"));
                                shield.recordBlock();
                                blocked = true; tBlocked = true;
                            } else if (AgenticAiEngine::instance().threatKnown(
                                           AgenticAiEngine::assetSig(appId, req.method, req.path))) {
                                // Agentic AI 异步研判结论落到威胁索引 → 同步拒绝同类后续请求
                                outResp = blockResp(req.clientIp, "AgenticAI", "API-AGENTIC-KNOWN",
                                                    "agentic-confirmed threat",
                                                    req.path, hdrCi(req, "Host"));
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true; fwEscalate = true;
                                emitEvt(req.clientIp, "AgenticAI", "block", "API-AGENTIC-KNOWN",
                                        "async verdict hit", req.path, hdrCi(req, "Host"));
                            }
                            // Agentic AI 异步研判：热路径只入队（候选判定过滤普通流量）
                            if (AgenticAiEngine::instance().enabled()) {
                                AgenticAiEngine::Signal sg;
                                sg.ip = req.clientIp;
                                sg.appId = appId;
                                sg.method = req.method;
                                sg.path = req.path.size() > 1024 ? req.path.substr(0, 1024) : req.path;
                                sg.query = req.query.size() > 1024 ? req.query.substr(0, 1024) : req.query;
                                sg.body = req.body.size() > 1024 ? req.body.substr(0, 1024) : req.body;
                                sg.ua = hdrCi(req, "User-Agent");
                                sg.contentType = apiCtype;
                                sg.tokenState = apiTokenState;
                                sg.tokenIssue = apiTokenIssue;
                                sg.shadow = apiShadow;
                                sg.ts = (int64_t)std::time(nullptr);
                                if (AgenticAiEngine::candidate(sg, apiShadow))
                                    AgenticAiEngine::instance().submit(sg);
                            }
                        }
                        // 蜜罐诱捕（观察模式，复测设计评审整改）：诱饵路径正常流量
                        // 永不触达（不在站点地图、无页面链接、业务从不引用），访问即
                        // 恶意探测——但「命中即封禁」让攻击者立刻知晓被处置、取证链
                        // 中断，且命中响应与 WAF 拦截页同构、无诱饵特征。改为：
                        //   记录（observe 事件）+ 打标（按不同诱饵滑窗计数）+ 诱饵放行
                        //   （返回仿真 .git/.env/wp-login 内容，诱使攻击者深入）；
                        //   窗口内触达 ≥N 个不同诱饵（NOVA_HONEY_ESCALATE_N，默认 3，
                        //   正常用户数学上不可能踩中多个无链接路径）才升级 403+fw 封禁。
                        if (!whitelisted && !policyPass && !blocked) {
                            std::string bait = HoneypotGuard::instance().keyFor(req.path);
                            if (!bait.empty()) {
                                auto hit = HoneypotGuard::instance().noteHit(req.clientIp, bait);
                                if (hit.distinct >= HoneypotGuard::escalateN()) {
                                    // 升级：触达足够多不同诱饵 → 确定性扫描器，封禁
                                    if (g_debugLog) std::printf("[reactor %d] BLOCK Honeypot(escalate %d) from %s: %s\n",
                                                idx, hit.distinct, ipstr, req.path.c_str());
                                    outResp = blockResp(req.clientIp, "Honeypot", "HONEYPOT-001",
                                                        bait + " x" + std::to_string(hit.distinct),
                                                        req.path, hdrCi(req, "Host"), false, scannerUa);
                                    shield.recordBlock();
                                    FwBanPoster::instance()->enqueue(req.clientIp, "Honeypot", "HONEYPOT-001");
                                    blocked = true; tBlocked = true; tAttack = true;
                                } else {
                                    // 观察：记录事件 + 放行仿真诱饵内容（不阻断、不封禁）。
                                    // 仅窗口内首次触达该诱饵记事件——同一攻击者对同一诱饵的
                                    // 高频重复访问不再逐条刷屏（曾 1s 304 条相同事件灌满事件流）。
                                    if (g_debugLog) std::printf("[reactor %d] OBSERVE Honeypot(%d/%d) from %s: %s\n",
                                                idx, hit.distinct, HoneypotGuard::escalateN(), ipstr, req.path.c_str());
                                    if (hit.isNew)
                                        emitEvt(req.clientIp, "Honeypot", "observe", "HONEYPOT-001",
                                                bait + " x" + std::to_string(hit.distinct),
                                                req.path, hdrCi(req, "Host"));
                                    outResp = HoneypotDecoy::render(req.path, MimicDefense::siteBanner());
                                    setRespConnection(outResp, keepAlive);
                                    shield.recordRequest();
                                    blocked = true;  // 本地已应答，不再转发上游（非拦截语义）
                                }
                            }
                        }
                        if (!whitelisted && !policyPass && ti) {
                            auto tr = ti->match(req, ja4, httpFp);
                            if (tr && tr->isBlocked()) {
                                if (g_debugLog) std::printf("[reactor %d] BLOCK TI-%s from %s: %s\n",
                                            idx, tr->category.c_str(), ipstr, tr->matched.c_str());
                                outResp = blockResp(req.clientIp, tr->category, tr->ruleId,
                                                    tr->matched, req.path, hdrCi(req, "Host"),
                                                    false, scannerUa);
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true; fwEscalate = true;
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
                                outResp = blockResp(req.clientIp, "Geo", gr->ruleId,
                                                    gr->matched, req.path, hdrCi(req, "Host"),
                                                    false, scannerUa);
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true; fwEscalate = true;
                            }
                        }
                        // 行为维度异常识别（跨请求关联）：低速 CC/同前缀枚举/路径扫描。
                        // 规则引擎对"每条合法、整体恶意"无感，此层补行为关联（V6 E 组缺口）。
                        // 先记账（所有请求，含将被拦截的）再判定；白名单/路径放行豁免。
                        if (!whitelisted && !policyPass) {
                            BehaviorGuard::instance().noteRequest(req.clientIp, req.path);
                            if (!blocked) {
                                DetectionResult bh = BehaviorGuard::instance().assess(req.clientIp);
                                if (bh.action != Action::PASS) {
                                    if (g_debugLog) std::printf("[reactor %d] CHAL Behavior from %s\n", idx, ipstr);
                                    // 与 CC 一致的 429 限流语义，RA 透出锁定真实剩余
                                    outResp = errResp(429, "Too Many Requests",
                                        "Retry-After: " + std::to_string(std::max(1, bh.retryAfterSec)) + "\r\n");
                                    emitEvt(req.clientIp, "Behavior", "challenge", bh.ruleId,
                                            bh.matched, req.path, hdrCi(req, "Host"));
                                    shield.recordBlock();
                                    blocked = true; tBlocked = true; tAttack = true;
                                }
                            }
                        }
                        // Bot 指纹评分前置（复测 P0 整改：原实现裸头首请求即 429，
                        // 判定几乎全压指纹——复制一套浏览器头即拿 38 倍配额）。
                        // 改为配额系数：指纹不再一票否决，只收紧 CC 配额
                        // （<15 全量 / 15–29 减半 / ≥30 四分之一），可疑流量仍有
                        // 非零配额，头部复制收益收敛到 4 倍以内；分数同时透出供观察。
                        double botQuotaFactor = 1.0;
                        int botScore = 0;
                        std::string botReason;
                        if (!whitelisted && !policyPass && !blocked && !isApiPath(req.path)) {
                            DetectionResult br = bot.assess(req, ja4);
                            botScore = br.score;
                            botReason = br.matched;
                            if (botScore >= 30) botQuotaFactor = 0.25;
                            else if (botScore >= 15) botQuotaFactor = 0.5;
                            if (botScore >= 30)  // 高可疑：观察事件（scanner-ua/裸头组合）
                                emitEvt(req.clientIp, "Bot", "observe", br.ruleId,
                                        botReason + " score=" + std::to_string(botScore),
                                        req.path, hdrCi(req, "Host"));
                        }
                        if (!whitelisted && !policyPass && !blocked) {
                            DetectionResult cr = cc.assess(req.clientIp, req.path, botQuotaFactor);
                            if (cr.action != Action::PASS) {
                                if (g_debugLog) std::printf("[reactor %d] %s CC from %s: %s\n",
                                            idx, cr.action == Action::BLOCK ? "BLOCK" : "CHAL",
                                            ipstr, cr.matched.c_str());
                                // 限流语义 429 + Retry-After 真实恢复时间（窗口内最早
                                // 过量请求老化出窗的时刻），取代恒 30/60——复测实测
                                // 恢复 210–469s 与 RA30 偏差 7–16 倍的根因修复之一。
                                int cra = std::max(1, cr.retryAfterSec);
                                if (cr.action == Action::BLOCK) {
                                    outResp = errResp(429, "Too Many Requests",
                                        "Retry-After: " + std::to_string(cra) + "\r\n");
                                    emitEvt(req.clientIp, "CC", "block", cr.ruleId, cr.matched,
                                            req.path, hdrCi(req, "Host"));
                                    shield.recordBlock();
                                } else {
                                    // CHALLENGE 与 BLOCK 统一 429 限流语义：复测证实先 503 后 429
                                    // 的混合出栈会被读作"后端过载"，且 503 拟态页不携带重试信息。
                                    outResp = errResp(429, "Too Many Requests",
                                        "Retry-After: " + std::to_string(cra) + "\r\n");
                                    emitEvt(req.clientIp, "CC", "challenge", cr.ruleId, cr.matched,
                                            req.path, hdrCi(req, "Host"));
                                    shield.recordBlock();
                                }
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // 端点分级限流（read/write/upload/auth/static 五类独立配额）：
                        // monitor-only 阶段只记账不处置；enforce 阶段超限 429 +
                        // Retry-After 真实剩余窗口；stage>=3 触发封禁阶梯 L2（URL+方法
                        // 临时封禁，不开 L4 全端口）。auth 类优先按用户名计数（NAT 友好）。
                        if (!whitelisted && !policyPass && !blocked) {
                            std::string uname;
                            for (auto& [k, v] : req.queryParams)
                                if (k == "username" || k == "user" || k == "email") { uname = v; break; }
                            long clen = 0;
                            std::string clv = hdrCi(req, "Content-Length");
                            if (!clv.empty()) clen = std::atol(clv.c_str());
                            auto erd = EndpointRateGuard::instance().assess(
                                req.clientIp, req.method, req.path, uname,
                                hdrCi(req, "Content-Type"), clen);
                            if (erd) {
                                if (g_debugLog) std::printf("[reactor %d] %s RateLimit(%s) from %s: %s\n",
                                            idx, erd->l2Ban ? "BAN" : "LIMIT",
                                            erd->cls.c_str(), ipstr, req.path.c_str());
                                outResp = errResp(429, "Too Many Requests",
                                    "Retry-After: " + std::to_string(erd->retryAfterSec) + "\r\n");
                                emitEvt(req.clientIp, "RateLimit",
                                        erd->l2Ban ? "block" : "challenge",
                                        erd->l2Ban ? "RL-L2" : "RL-L1",
                                        "endpoint quota exceeded: " + erd->cls,
                                        req.path, hdrCi(req, "Host"));
                                shield.recordBlock();
                                blocked = true; tBlocked = true; tAttack = true;
                            }
                        }
                        // Bot 指纹处置已前置（CC 配额系数 + observe 事件），
                        // 此处不再二次评估、不再直接 429。
                        _mark();  // [4] Geo/CC/Bot 结束，进入规则+AI 检测流水线
                        // JSON 嵌套深度结构护栏：超深 JSON 按 400 拒绝（结构性限制，
                        // tAttack 保持 false —— 不记攻击、不封禁、不上报 FwBan，
                        // 观察模式下也不放行，与 413/头部超限同语义）。背景：5000 层
                        // 嵌套曾触发 SSTI-001 误拦(AC 裸 "}}" 模式，已改成对共现判定)，
                        // 此处独立护栏防止递归解析型上游被病态 JSON 打爆。
                        if (!whitelisted && !policyPass && !blocked && !req.body.empty()) {
                            std::string ct = hdrCi(req, "Content-Type");
                            for (auto& c : ct) c = (char)tolower((unsigned char)c);
                            if (ct.find("json") != std::string::npos &&
                                jsonDepthExceeds(req.body, kJsonMaxDepth)) {
                                outResp = errResp(400, "Bad Request");
                                emitEvt(req.clientIp, "JsonDepth", "block", "JSON-DEPTH",
                                        "json nesting too deep", req.path, hdrCi(req, "Host"));
                                shield.recordBlock();
                                blocked = true; tBlocked = true;
                            }
                        }
                        // 规则 + AI 二阶复核
                        if (!whitelisted && !policyPass && !blocked) {
                            DetectionResult dr = detectWithAiReview(pipeline, ai, req);
                            if (dr.isBlocked()) {
                                if (g_debugLog) std::printf("[reactor %d] BLOCK %s from %s: %s\n",
                                            idx, dr.category.c_str(), ipstr, dr.matched.c_str());
                                outResp = blockResp(req.clientIp, dr.category, dr.ruleId,
                                                    dr.matched, req.path, hdrCi(req, "Host"),
                                                    false, scannerUa);
                                shield.recordBlock();
                                tBlocked = true; tAttack = true;
                                // 分级处置：单笔命中仅阻断当次请求；同 IP 滑窗内累计
                                // N 次规则命中才升级 fw L3 封禁（误报/单探针不封全站）
                                fwEscalate = EscalationGuard::instance().noteHit(req.clientIp)
                                             >= EscalationGuard::escalateN();
                            } else {
                                // 认证爆破防护（检测流水线之后、转发上游之前）：
                                // 登录等认证接口的尝试计数与源 IP 锁定。响应侧无法区分
                                // 成败（业务失败也回 200），故按尝试次数独立限流。
                                // 只对通过全部检测的请求计数——此前位于流水线之前，
                                // 被 CSRF/规则误拦的请求也占窗口，正常用户会被误推入锁定。
                                int lockSec = BruteGuard::instance().hit(
                                    req.clientIp, req.path, req.method);
                                if (lockSec > 0) {
                                    if (g_debugLog) std::printf("[reactor %d] BLOCK BruteForce from %s: %s\n",
                                                idx, ipstr, req.path.c_str());
                                    outResp = errResp(429, "Too Many Requests",
                                                      "Retry-After: " + std::to_string(lockSec) + "\r\n");
                                    shield.recordBlock();
                                    emitEvt(req.clientIp, "BruteForce", "block", "BF-001",
                                            "auth attempts exceeded, locked", req.path, hdrCi(req, "Host"));
                                    // 本地 429 锁定即可，不上报防火墙全端口封禁（避免误伤 SSH 等管理通道）
                                    blocked = true; tBlocked = true;
                                } else {
                                    asyncHandled = forwardToApp();
                                }
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
                        { std::lock_guard<std::mutex> lk(busyMtx); auto ci = conns.find(fd); if (ci != conns.end()) { ci->second.inbuf.erase(0, reqLen); if (ci->second.inbuf.empty()) ci->second.firstByteMs = 0; } }
                        keepOpen = false;
                        break;
                    }
                    // 确认真实攻击命中 → 投递防火墙联动封禁（观察模式 / 路径仅记录：只记录不封禁；
                    // 限流族 429 不自检 fwEscalate，蜜罐升级分支已自行 enqueue，均不在此重复上报）
                    if (fwEscalate && appMode != 1 && !policyLog) FwBanPoster::instance()->enqueue(req.clientIp, "WAF", "attack");
                    // 会话 cookie（UV 去重）。指纹三态：公开=novasid 品牌名；隐藏=全站固定
                    // 人格（默认 ASP.NET_SessionId，与 banner/拦截页一致，避免分裂指纹）；关闭=不注入。
                    if (newSess && !outResp.empty() && wafMode != WafMode::OFF)
                        injectHeader(outResp, std::string("Set-Cookie: ") +
                            (WafMode::isPublic(wafMode) ? "novasid"
                                                        : MimicDefense::siteCookie()) +
                            "=" + sid + "; Path=/; HttpOnly");
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
                        { std::lock_guard<std::mutex> lk(busyMtx); auto ci = conns.find(fd); if (ci != conns.end()) { ci->second.inbuf.erase(0, reqLen); if (ci->second.inbuf.empty()) ci->second.firstByteMs = 0; } }
                        if (writeFail) { keepOpen = false; break; }
                        if (left > 0) {
                            std::lock_guard<std::mutex> lk(busyMtx);
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
                        { std::lock_guard<std::mutex> lk(busyMtx); if (auto ci = conns.find(fd); ci != conns.end()) ci->second.lastActiveMs = nowMs(); }
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
            std::vector<std::pair<int, bool>> stale;  // (fd, isSlowReq)
            {
                std::lock_guard<std::mutex> lk(busyMtx);
                for (auto& [cfd, st] : conns) {
                    if (busy.count(cfd)) continue;
                    // 有在途请求的连接：头部阶段受绝对上限约束（Slowloris 防御不变式：
                    // inbuf 非空则 firstByteMs 必已设置；防御性回退 lastActiveMs）。
                    // body 阶段时限与大小独立计算：预算 = 头时限 + Content-Length/最小速率，
                    // 合法慢速大上传（4MB @ 1KB/s = 4096s）不被绝对上限误杀。
                    // 慢速判定必须先于 idle 回收：否则 15s idle 会抢在慢速之前
                    // 静默断连（lastActiveMs 不随 body 滴灌更新），408 永远发不出。
                    if (!st.inbuf.empty()) {
                        int64_t base = st.firstByteMs ? st.firstByteMs : st.lastActiveMs;
                        int64_t budget = kSlowReqMs;
                        size_t he = st.inbuf.find("\r\n\r\n");
                        if (he != std::string::npos && kSlowMinBps > 0) {
                            // 头已齐：从头部解析 Content-Length（大小写不敏感）计算 body 时限
                            std::string head = st.inbuf.substr(0, he);
                            for (auto& c : head) c = (char)std::tolower((unsigned char)c);
                            size_t p = head.find("content-length:");
                            if (p != std::string::npos) {
                                long long cl = std::atoll(head.c_str() + p + 15);
                                if (cl > 0) budget += cl * 1000LL / kSlowMinBps;
                            }
                        }
                        if (now - base > budget) stale.push_back({cfd, true});
                        continue;
                    }
                    // 无在途请求的空闲 keep-alive 连接回收
                    if (now - st.lastActiveMs > kKeepAliveIdleMs) stale.push_back({cfd, false});
                    // drain 模式：无在途请求的连接立即关闭（不等 15s idle），加速排空
                    else if (drainMode && st.inbuf.empty() && st.outQ.empty())
                        stale.push_back({cfd, false});
                }
            }  // 先释放锁，再逐个关闭（closeConn 自身会加锁）
            for (auto [cfd, slow] : stale) {
                // 慢速超时回 408 全站人格页（而非直接 RST 断连）：此前直接杀连接会让
                // 前端 nginx 向客户端回 502 + Server: nginx，绕过 WAF 响应头归一化，
                // 零载荷慢连接即可拿到真实指纹（V6 P0）。408 + IIS 人格后正常 FIN，
                // 内核 linger 默认会把已拷贝进发送缓冲的响应发完再断。
                if (slow) {
                    std::string r = errResp(408, "Request Timeout");
                    send(cfd, r.data(), r.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                    // 先半关闭发 FIN 把 408 交付完毕，再 drain 接收缓冲：残留滴灌字节
                    // 会让 close 发 RST，对端内核随 RST 丢弃已缓冲的 408（实测丢响应）。
                    shutdown(cfd, SHUT_WR);
                    char dbuf[4096];
                    while (recv(cfd, dbuf, sizeof(dbuf), MSG_DONTWAIT) > 0) {}
                }
                closeConn(cfd);
            }
        }
        // 桥回环连接池周期回收（超时在途 + 闲置连接）
        bridge.sweep(nowMs());
        // h3 到期处理/刷写/回收（drain 期间 quicFd 已摘出 epoll，此处继续把在途响应发完）
        if (h3) h3->sweep();
        // drain 模式：无在途请求的 TLS 空闲连接立即关闭
        if (drainMode) {
            for (auto it = tlsConns.begin(); it != tlsConns.end();) {
                if (it->second->idle()) {
                    const std::string& pip = it->second->peerIp();
                    if (!isTrustedProxy(pip)) ddos.onDisconnect(pip);
                    it = tlsConns.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }              // end while(g_running)
    // 收尾：先关桥（触发在途失败回调，此时 tlsConns/h3 仍存活、回调可安全落地），
    // 再销毁 TLS/h3 会话；weak 存活令牌兜底任意顺序。
    bridge.closeAll();
    tlsConns.clear();
    h3.reset();
    if (tlsFd >= 0) close(tlsFd);
    if (quicFd >= 0) close(quicFd);
    close(tfd);
    close(epfd);
}

// ---- master/worker 监管（nginx 式零停机滚动重启）----
// master 不监听业务端口：spawn worker（pipe + NOVA_READY_FD 等 "READY"），
// SIGUSR2 → 滚动重启（先启新 worker，READY 后 SIGQUIT 旧 worker 排空；
// 新旧 worker 经 SO_REUSEPORT 重叠监听，切换零丢包）；
// SIGCHLD → worker 意外退出自动拉起；SIGTERM/INT/QUIT → SIGQUIT worker 后退出。
static pid_t spawnWorker(char** argv, int port, int threads) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        // 子进程：就绪通知写端保留为 NOVA_READY_FD（注意不能用 CLOEXEC）
        close(pipefd[0]);
        char fdStr[16];
        std::snprintf(fdStr, sizeof(fdStr), "%d", pipefd[1]);
        setenv("NOVA_READY_FD", fdStr, 1);
        char p[16], t[16];
        std::snprintf(p, sizeof(p), "%d", port);
        std::snprintf(t, sizeof(t), "%d", threads);
        char* args[] = {argv[0], (char*)"--worker", p, t, nullptr};
        execvp(argv[0], args);
        _exit(127);
    }
    close(pipefd[1]);
    // 父进程：等 worker 全 reactor 监听就绪（最多 30s）
    pollfd pfd{};
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    int rv = poll(&pfd, 1, 30000);
    char buf[32] = {0};
    if (rv > 0 && (pfd.revents & POLLIN)) (void)!read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    if (std::strstr(buf, "READY") == nullptr) {
        kill(pid, SIGKILL);
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
        return -1;
    }
    return pid;
}

static int superviseMain(int argc, char** argv) {
    int port = (argc > 2) ? atoi(argv[2]) : 8080;
    int threads = (argc > 3) ? atoi(argv[3]) : (int)std::thread::hardware_concurrency();
    signal(SIGPIPE, SIG_IGN);

    // pidfile：ops 脚本/管理端据此发 SIGUSR2（滚动重启）/SIGTERM（停机）。
    // NOVA_RUN_DIR 显式指定运维目录（生产 /opt/novawaf/run）；缺省回退 $HOME/novawaf/run。
    const char* rd = getenv("NOVA_RUN_DIR");
    std::string runDir = (rd && *rd)
        ? rd
        : std::string(getenv("HOME") ? getenv("HOME") : "/tmp") + "/novawaf/run";
    mkdir(runDir.c_str(), 0755);  // 多级目录由部署脚本保证，此处兜底单层
    std::string pidPath = runDir + "/engine-master.pid";
    {
        std::ofstream pf(pidPath);
        pf << (int)getpid() << "\n";
    }

    static volatile sig_atomic_t gotUsr2 = 0, gotChld = 0, gotTerm = 0;
    struct sigaction sa{};
    sa.sa_handler = [](int) { gotUsr2 = 1; };
    sigaction(SIGUSR2, &sa, nullptr);
    sa.sa_handler = [](int) { gotChld = 1; };
    sigaction(SIGCHLD, &sa, nullptr);
    sa.sa_handler = [](int) { gotTerm = 1; };
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);

    pid_t worker = spawnWorker(argv, port, threads);
    if (worker < 0) {
        std::fprintf(stderr, "[master] initial worker spawn failed\n");
        unlink(pidPath.c_str());
        return 1;
    }
    std::printf("[master] pid=%d worker=%d port=%d threads=%d (SIGUSR2=滚动重启)\n",
                (int)getpid(), (int)worker, port, threads);
    std::fflush(stdout);

    pid_t retiring = -1;  // 滚动期被替换、正在排空的旧 worker
    while (true) {
        if (gotTerm) {
            if (worker > 0) kill(worker, SIGQUIT);
            if (retiring > 0) kill(retiring, SIGQUIT);
            int st;
            while (worker > 0 && waitpid(worker, &st, 0) < 0 && errno == EINTR) {}
            if (retiring > 0)
                while (waitpid(retiring, &st, 0) < 0 && errno == EINTR) {}
            unlink(pidPath.c_str());
            std::printf("[master] shutdown\n");
            return 0;
        }
        if (gotUsr2) {
            gotUsr2 = 0;
            std::printf("[master] rolling restart: spawn new worker (old=%d)\n", (int)worker);
            std::fflush(stdout);
            pid_t nw = spawnWorker(argv, port, threads);
            if (nw > 0) {
                if (retiring > 0) kill(retiring, SIGKILL);  // 上次滚动残留（极端），强杀
                retiring = worker;
                worker = nw;
                kill(retiring, SIGQUIT);  // 旧 worker 排空后自退，由 SIGCHLD 收尸
                std::printf("[master] rolling: new worker=%d, retiring=%d\n",
                            (int)worker, (int)retiring);
                std::fflush(stdout);
            } else {
                std::fprintf(stderr, "[master] rolling spawn failed, keep old worker=%d\n",
                             (int)worker);
            }
            continue;
        }
        if (gotChld) {
            gotChld = 0;
            int st;
            pid_t p;
            while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
                if (p == retiring) {
                    std::printf("[master] retiring worker %d exited\n", (int)p);
                    retiring = -1;
                    continue;
                }
                if (p == worker) {
                    std::fprintf(stderr, "[master] worker %d exited (status=0x%x), respawn\n",
                                 (int)p, st);
                    worker = -1;
                }
            }
        }
        if (worker <= 0) {  // 意外退出自动拉起（失败每秒重试）
            worker = spawnWorker(argv, port, threads);
            if (worker > 0)
                std::printf("[master] worker respawned pid=%d\n", (int)worker);
            else
                sleep(1);
            continue;
        }
        sleep(1);
    }
}

int main(int argc, char** argv) {
    // --version 打印退出（升级脚本校验用）；--supervise 进入 master 监管模式；
    // --worker <port> <threads> 由 master fork+exec 拉起（内部接口）。
    if (argc > 1 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("%s\n", NOVAWAF_VERSION);
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "--supervise") == 0)
        return superviseMain(argc, argv);
    int port;
    int threads;
    if (argc > 1 && std::strcmp(argv[1], "--worker") == 0) {
        port = (argc > 2) ? atoi(argv[2]) : 8080;
        threads = (argc > 3) ? atoi(argv[3]) : (int)std::thread::hardware_concurrency();
    } else {
        port = (argc > 1) ? atoi(argv[1]) : 8080;
        threads = (argc > 2) ? atoi(argv[2]) : (int)std::thread::hardware_concurrency();
    }
    signal(SIGPIPE, SIG_IGN);
    // SIGQUIT/SIGTERM/SIGINT → 各 reactor 优雅排空后退出（drain，30s 兜底）
    signal(SIGQUIT, onDrainSignal);
    signal(SIGTERM, onDrainSignal);
    signal(SIGINT, onDrainSignal);

// region debug-point segv-bt
    // SIGSEGV/SIGBUS 自取证：崩溃瞬间把带时间戳的符号化栈回溯追加到 /tmp/novawaf-crash.log，
    // 然后恢复默认处理重新抛出（systemd 记 SIGSEGV、内核照常可产 core）。
    // 依赖编译参数 -rdynamic 使 backtrace_symbols_fd 能解析函数名。
    auto segvHandler = [](int sig) {
        int fd = ::open("/tmp/novawaf-crash.log", O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
        if (fd >= 0) {
            char ts[48] = {0};
            time_t t = ::time(nullptr);
            struct tm tmv{};
            localtime_r(&t, &tmv);
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
            dprintf(fd, "==== signal %d at %s pid=%d ====\n", sig, ts, (int)getpid());
            void* bt[48];
            int n = backtrace(bt, 48);
            backtrace_symbols_fd(bt, n, fd);
            dprintf(fd, "==== end ====\n");
            ::close(fd);
        }
        signal(sig, SIG_DFL);
        raise(sig);
    };
    signal(SIGSEGV, segvHandler);
    signal(SIGBUS, segvHandler);
// endregion

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

    // L4 RMI 反序列化防护（JRMP 前置代理，命中断连+封 IP；未配置 NOVA_RMI_GUARD_LISTEN/BACKEND 则不启动）
    RmiGuard::instance().start();

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

    // ---- CVE 虚拟补丁：从 Redis 键 novawaf:cve_patch 热加载（JSON 模板数组），
    //      管理控制台按 CVE 编号批量下发应急防护规则；copy-on-write 与 CustomRules 同通道风格 ----
    auto cvePatch = std::make_shared<CvePatchDetector>();
    auto cveVersion = std::make_shared<std::string>("-");
    auto loadCvePatch = [cvePatch, cveVersion](bool initial) -> size_t {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return initial ? cvePatch->reload("") : (size_t)-1;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db))
            return initial ? cvePatch->reload("") : (size_t)-1;
        auto ver = r.get("novawaf:cve_patch:version");
        std::string cur = ver.value_or("");
        if (cur == *cveVersion && !initial) return (size_t)-1;  // 版本未变，跳过重解析
        auto blob = r.get("novawaf:cve_patch");
        *cveVersion = cur;
        size_t n = cvePatch->reload(blob.value_or(""));
        std::printf("  CvePatch: %s %zu patches from redis (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", n, cur.c_str());
        return n;
    };
    loadCvePatch(true);
    pipeline.addDetector(std::unique_ptr<CvePatchDetector>(
        static_cast<CvePatchDetector*>(cvePatch->clone().release())));
    int cveInterval = getenv("NOVA_CVE_PATCH_INTERVAL") ? atoi(getenv("NOVA_CVE_PATCH_INTERVAL")) : 60;

    // ---- 正则虚拟补丁：Redis 键 novawaf:regex_patch，与字面量补丁互补（复杂指纹），同通道热更 ----
    auto regexPatch = std::make_shared<RegexPatchDetector>();
    auto regexVersion = std::make_shared<std::string>("-");
    auto loadRegexPatch = [regexPatch, regexVersion](bool initial) -> size_t {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return initial ? regexPatch->reload("") : (size_t)-1;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db))
            return initial ? regexPatch->reload("") : (size_t)-1;
        auto ver = r.get("novawaf:regex_patch:version");
        std::string cur = ver.value_or("");
        if (cur == *regexVersion && !initial) return (size_t)-1;  // 版本未变，跳过重解析
        auto blob = r.get("novawaf:regex_patch");
        *regexVersion = cur;
        size_t n = regexPatch->reload(blob.value_or(""));
        std::printf("  RegexPatch: %s %zu patches from redis (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", n, cur.c_str());
        return n;
    };
    loadRegexPatch(true);
    pipeline.addDetector(std::unique_ptr<RegexPatchDetector>(
        static_cast<RegexPatchDetector*>(regexPatch->clone().release())));

    std::thread([loadCvePatch, loadRegexPatch, cveInterval]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(cveInterval));
            if (!g_running) break;
            loadCvePatch(false);
            loadRegexPatch(false);
        }
    }).detach();

    // ---- 自研 IPS：深度检测（协议异常/HTTP 走私、编码绕过、参数污染、无文件执行/C2、
    //      敏感端点探测）→ 加权评分实时阻断 + 高危联动防火墙封禁 + 告警入 Redis。
    //      策略经 novawaf:ips:policy 热加载（copy-on-write，热路径无锁）----
    auto ipsVersion = std::make_shared<std::string>("-");
    auto loadIpsPolicy = [ipsVersion](bool initial) -> size_t {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) {
            if (initial) {
                auto p = IpsEngine::instance().policy();
                std::printf("  IPS: builtin policy modules=%zu block=%d log=%d fwBan=%d mode=%s\n",
                            IpsEngine::instance().moduleCount(), p->blockScore, p->logScore,
                            p->fwBanScore, p->blockMode ? "block" : "observe");
            }
            return IpsEngine::instance().moduleCount();
        }
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return IpsEngine::instance().moduleCount();
        auto ver = r.get("novawaf:ips:policy:version");
        std::string cur = ver.value_or("");
        if (cur == *ipsVersion && !initial) return (size_t)-1;  // 版本未变，跳过重解析
        auto blob = r.get("novawaf:ips:policy");
        *ipsVersion = cur;
        size_t n = IpsEngine::instance().loadPolicy(blob.value_or(""));
        auto p = IpsEngine::instance().policy();
        std::printf("  IPS: %s policy modules=%zu block=%d log=%d fwBan=%d mode=%s (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", n, p->blockScore, p->logScore,
                    p->fwBanScore, p->blockMode ? "block" : "observe", cur.c_str());
        return n;
    };
    loadIpsPolicy(true);
    pipeline.addDetector(std::make_unique<IpsDetector>());
    int ipsInterval = getenv("NOVA_IPS_INTERVAL") ? atoi(getenv("NOVA_IPS_INTERVAL")) : 60;
    std::thread([loadIpsPolicy, ipsInterval]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(ipsInterval));
            if (!g_running) break;
            loadIpsPolicy(false);
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

    // ---- 蜜罐诱饵路径：从 Redis novawaf:honeypot:paths 热加载（联动控制台，保存即发布）。
    // 内置默认诱饵集始终生效，Redis 清单为增量补充；COW 原子换表，reactor 热路径无锁读 ----
    auto loadHoneypot = [](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) {
            if (initial)
                std::printf("  Honeypot: loaded defaults=%zu (redis off)\n",
                            HoneypotGuard::instance().tableCount());
            return;
        }
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        static std::string s_ver = "-";
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        auto ver = r.get("novawaf:honeypot:version");
        std::string cur = ver.value_or("");
        if (cur == s_ver && !initial) return;
        auto blob = r.get("novawaf:honeypot:paths");
        s_ver = cur;
        size_t n = HoneypotGuard::instance().reload(blob.value_or(""));
        std::printf("  Honeypot: %s traps=%zu (ver=%s)\n",
                    initial ? "loaded" : "hot-reloaded", n, cur.c_str());
    };
    loadHoneypot(true);
    std::thread([loadHoneypot]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadHoneypot(false);
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

    // ---- 端点分级限流策略：Redis novawaf:ratelimit:policy 热加载（控制台保存即发布）----
    // 阈值管理后台写入 policy JSON 并 INCR version；引擎 3s 轮询版本号，变化即 COW 换配置。
    auto loadRatePolicy = [](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
        static std::string s_ver = "-";
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        auto ver = r.get("novawaf:ratelimit:version");
        std::string cur = ver.value_or("");
        if (cur == s_ver && !initial) return;
        auto blob = r.get("novawaf:ratelimit:policy");
        try {
            EndpointRateGuard::instance().configure(
                EndpointRateGuard::parsePolicy(blob.value_or("")));
            s_ver = cur;
            std::printf("  RateLimit: %s stage=%d (ver=%s)\n",
                        initial ? "loaded" : "hot-reloaded",
                        EndpointRateGuard::instance().stage(), cur.c_str());
        } catch (...) {
            if (initial) std::printf("  RateLimit: policy parse failed, using defaults\n");
        }
    };
    loadRatePolicy(true);
    std::thread([loadRatePolicy]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            if (!g_running) break;
            loadRatePolicy(false);
        }
    }).detach();

    // ---- 限流分布采集上报：每分钟快照每 IP 每类 QPS 分布（P50/P99/P99.9、3s 峰值、
    // 桶利用率、would-block），写 Redis 供阈值管理标定（7 天 hist，LTRIM 10080 分钟）----
    std::thread([] {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (!g_running) break;
            const char* rh = getenv("NOVA_REDIS_HOST");
            if (!rh || !*rh) continue;
            int port = getenv("NOVA_REDIS_PORT") ? atoi(getenv("NOVA_REDIS_PORT")) : 6379;
            const char* pass = getenv("NOVA_REDIS_PASS");
            int db = getenv("NOVA_REDIS_DB") ? atoi(getenv("NOVA_REDIS_DB")) : 0;
            auto dist = EndpointRateGuard::instance().snapshot();
            long ts = (long)time(nullptr);
            char mbuf[512];
            std::snprintf(mbuf, sizeof mbuf,
                "{\"stage\":%d,\"l1LastMin\":%ld,\"bansLastMin\":%ld,\"ts\":%ld}",
                EndpointRateGuard::instance().stage(),
                EndpointRateGuard::instance().l1LastMin(),
                EndpointRateGuard::instance().bansLastMin(), ts);
            RedisClient r;
            if (!r.connect(rh, port, pass ? pass : "", db)) continue;
            r.set("novawaf:ratelimit:metrics", mbuf);
            for (auto& d : dist) {
                char jbuf[768];
                std::snprintf(jbuf, sizeof jbuf,
                    "{\"class\":\"%s\",\"ts\":%ld,\"keys\":%d,\"p50\":%.3f,\"p99\":%.3f,"
                    "\"p999\":%.3f,\"burstP999\":%.3f,\"utilP95\":%.3f,"
                    "\"suggestQps\":%.3f,\"suggestBurst\":%d,\"wouldBlock1m\":%ld}",
                    d.cls.c_str(), ts, d.keys, d.p50, d.p99, d.p999, d.burstP999,
                    d.utilP95, d.suggestQps, d.suggestBurst, d.wouldBlock1m);
                std::string key = std::string("novawaf:ratelimit:dist:") + d.cls;
                r.set(key, jbuf);
                r.rpush(key + ":hist", jbuf);
                r.ltrim(key + ":hist", 0, 10079);  // 7 天 × 1440 分钟
            }
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
    // CC 阈值（V6 复测后收紧并文档化，均可由环境变量覆盖）：
    //   单 IP 120 次/10s（12/s 持续即挑战，正常浏览器复用连接远低于此）
    //   单 IP+URL 30 次/10s（同 URL 高频刷新突刺）
    //   全局热点 URL 500 次/10s；429 + Retry-After 处置语义见 CC 判定分支
    CcGuard::Config ccCfg;
    ccCfg.maxReqPerWindow  = getenv("NOVA_CC_WINDOW") ? atoi(getenv("NOVA_CC_WINDOW")) : 120;
    ccCfg.burstPerUrl      = getenv("NOVA_CC_BURST_URL") ? atoi(getenv("NOVA_CC_BURST_URL")) : 30;
    ccCfg.hotUrlGlobal     = getenv("NOVA_CC_HOT_URL")   ? atoi(getenv("NOVA_CC_HOT_URL"))   : 500;
    CcGuard cc(ccCfg);
    // 行为维度统计评分（低速CC/枚举/路径扫描：策略信号加权 + 漏桶衰减 +
    // 长窗低速直判 + 64 片分片锁，V6 行为识别缺口整改，env 可覆盖）
    {
        BehaviorGuard::Config bhCfg;
        if (getenv("NOVA_BEH_SCORE"))     bhCfg.scoreThreshold = atof(getenv("NOVA_BEH_SCORE"));
        if (getenv("NOVA_BEH_DECAY"))     bhCfg.decayPerSec    = atof(getenv("NOVA_BEH_DECAY"));
        if (getenv("NOVA_BEH_W_404"))     bhCfg.wNotFound      = atof(getenv("NOVA_BEH_W_404"));
        if (getenv("NOVA_BEH_W_ENUM"))    bhCfg.wEnumId        = atof(getenv("NOVA_BEH_W_ENUM"));
        if (getenv("NOVA_BEH_W_APIENUM")) bhCfg.wApiEnum       = atof(getenv("NOVA_BEH_W_APIENUM"));
        if (getenv("NOVA_BEH_W_REQ"))     bhCfg.wRequest       = atof(getenv("NOVA_BEH_W_REQ"));
        if (getenv("NOVA_BEH_ENUM_WIN"))  bhCfg.enumWinSec     = atoi(getenv("NOVA_BEH_ENUM_WIN"));
        if (getenv("NOVA_BEH_SLOW_MAX"))  bhCfg.slowMax        = atoi(getenv("NOVA_BEH_SLOW_MAX"));
        if (getenv("NOVA_BEH_SLOW_WIN"))  bhCfg.slowWinSec     = atoi(getenv("NOVA_BEH_SLOW_WIN"));
        if (getenv("NOVA_BEH_LOCK"))      bhCfg.lockSec        = atoi(getenv("NOVA_BEH_LOCK"));
        BehaviorGuard::instance().configure(bhCfg);
    }
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

    // ---- API 资产自动发现 / API 级防护 / Agentic AI：配置热加载 + 周期快照 ----
    // Redis 契约（管理端写入、引擎读取；均带 :version 版本键，变化才重载）：
    //   novawaf:api:inventory  已登记 API 清单 {"items":[{"appId","method","path"}]}
    //   novawaf:api:guard      API 限流 / Token 校验 / 脱敏开关策略
    //   novawaf:api:tokens     不透明令牌白名单 ["token", ...]
    //   novawaf:ai:agentic     Agentic AI 引擎（模型端点、阈值、预算、熔断）
    //   novawaf:dlp:config     响应敏感数据脱敏动作
    // 引擎写出：novawaf:api:assets（资产目录快照）、novawaf:ai:agentic:traces（研判轨迹）
    int apiZombieDays = getenv("NOVA_API_ZOMBIE_DAYS") ? std::atoi(getenv("NOVA_API_ZOMBIE_DAYS")) : 30;
    if (apiZombieDays < 1) apiZombieDays = 1;
    AgenticAiEngine::instance().start(2);
    if (const char* ae = getenv("NOVA_AGENTIC_ENABLE")) {
        if (std::string(ae) == "1") {
            // 环境变量兜底配置（Redis 未下发时生效）：模型端点复用 NOVAAI_* 变量
            std::string llmOn = (getenv("NOVAAI_ENABLE") && std::string(getenv("NOVAAI_ENABLE")) == "1")
                                    ? "true" : "false";
            std::string js = "{\"enabled\":true,\"block\":false,\"threshold\":0.6,"
                             "\"budgetPerMin\":20,\"llm\":{\"enabled\":" + llmOn +
                             ",\"endpoint\":\"" + (getenv("NOVAAI_ENDPOINT") ? getenv("NOVAAI_ENDPOINT") : "") +
                             "\",\"apiKey\":\"" + (getenv("NOVAAI_APIKEY") ? getenv("NOVAAI_APIKEY") : "") +
                             "\",\"model\":\"" + (getenv("NOVAAI_MODEL") ? getenv("NOVAAI_MODEL") : "") +
                             "\",\"timeoutMs\":1500}}";
            AgenticAiEngine::instance().configure(js);
        }
    }
    auto loadApiConfigs = [](bool initial) {
        const char* rh = getenv("NOVA_REDIS_HOST");
        if (!rh || !*rh) return;
        int port = getenv("NOVA_REDIS_PORT") ? std::atoi(getenv("NOVA_REDIS_PORT")) : 6379;
        const char* pass = getenv("NOVA_REDIS_PASS");
        int db = getenv("NOVA_REDIS_DB") ? std::atoi(getenv("NOVA_REDIS_DB")) : 0;
        RedisClient r;
        if (!r.connect(rh, port, pass ? pass : "", db)) return;
        // 首轮：从上次快照还原资产目录（避免重启后影子/僵尸资产清空）
        static bool assetsRestored = false;
        if (initial && !assetsRestored) {
            assetsRestored = true;
            auto snap = r.get("novawaf:api:assets");
            if (snap && !snap->empty()) {
                ApiAssetRegistry::instance().restore(*snap);
                std::printf("  APIAsset: restored %zu assets from snapshot\n",
                            ApiAssetRegistry::instance().size());
            }
        }
        static std::string invVer = "-", guardVer = "-", tokenVer = "-", agentVer = "-", dlpVer = "-";
        auto reload = [&r, initial](const char* verKey, std::string& last, const char* dataKey) -> bool {
            auto v = r.get(verKey);
            std::string cur = v.value_or("");
            if (!initial && cur == last) return false;
            last = cur;
            auto b = r.get(dataKey);
            if (!b || b->empty()) return false;
            (void)dataKey;
            return true;
        };
        if (reload("novawaf:api:inventory:version", invVer, "novawaf:api:inventory")) {
            auto b = r.get("novawaf:api:inventory");
            if (b) {
                ApiAssetRegistry::instance().configureInventory(*b);
                std::printf("  APIAsset: inventory %s, registered=%zu\n",
                            initial ? "loaded" : "hot-reloaded",
                            ApiAssetRegistry::instance().inventorySize());
            }
        }
        if (reload("novawaf:api:guard:version", guardVer, "novawaf:api:guard")) {
            auto b = r.get("novawaf:api:guard");
            if (b) {
                try {
                    auto pol = ApiRateGuard::parsePolicy(*b);
                    TokenGuard::instance().configure(pol->token);
                    ApiRateGuard::instance().configure(pol);
                    std::printf("  APIGuard: %s rules=%zu token=%d stage=%d\n",
                                initial ? "loaded" : "hot-reloaded", pol->rules.size(),
                                pol->token.enabled ? 1 : 0, pol->stage);
                } catch (...) {
                    std::printf("  APIGuard: invalid policy json, keep previous\n");
                }
            }
        }
        if (reload("novawaf:api:tokens:version", tokenVer, "novawaf:api:tokens")) {
            auto b = r.get("novawaf:api:tokens");
            if (b) {
                std::vector<std::string> toks;
                try {
                    JsonValue root = parseJson(*b);
                    if (root.isArray())
                        for (auto& e : root.arr)
                            if (e.isString() && !e.str.empty()) toks.push_back(e.str);
                } catch (...) {}
                TokenGuard::instance().setWhitelist(toks);
                std::printf("  APIToken: whitelist %s, size=%zu\n",
                            initial ? "loaded" : "hot-reloaded",
                            TokenGuard::instance().whitelistSize());
            }
        }
        if (reload("novawaf:ai:agentic:version", agentVer, "novawaf:ai:agentic")) {
            auto b = r.get("novawaf:ai:agentic");
            if (b) {
                AgenticAiEngine::instance().configure(*b);
                auto ac = AgenticAiEngine::instance().config();
                std::printf("  AgenticAI: %s enabled=%d block=%d threshold=%.2f llm=%d\n",
                            initial ? "loaded" : "hot-reloaded", ac->enabled ? 1 : 0,
                            ac->block ? 1 : 0, ac->threshold, ac->llm.enabled ? 1 : 0);
            }
        }
        if (reload("novawaf:dlp:config:version", dlpVer, "novawaf:dlp:config")) {
            auto b = r.get("novawaf:dlp:config");
            if (b) {
                ResponseDlp::instance().configure(*b);
                std::printf("  ResponseDLP: %s action=%d maxBytes=%zu\n",
                            initial ? "loaded" : "hot-reloaded",
                            ResponseDlp::instance().action(), ResponseDlp::instance().maxBytes());
            }
        }
    };
    loadApiConfigs(true);
    std::thread([loadApiConfigs]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!g_running) break;
            loadApiConfigs(false);
        }
    }).detach();
    // 资产目录周期快照（60s；首轮 10s 让管理端尽快看到数据）+ Agentic 轨迹落 Redis
    std::thread([apiZombieDays]() {
        const char* rh = getenv("NOVA_REDIS_HOST");
        int interval = 10;
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(interval));
            if (!g_running) break;
            interval = 60;
            std::string snap = ApiAssetRegistry::instance().snapshotJson(apiZombieDays, true);
            auto traces = AgenticAiEngine::instance().drainTraces(200);
            if (!rh || !*rh) continue;
            int port = getenv("NOVA_REDIS_PORT") ? std::atoi(getenv("NOVA_REDIS_PORT")) : 6379;
            const char* pass = getenv("NOVA_REDIS_PASS");
            int db = getenv("NOVA_REDIS_DB") ? std::atoi(getenv("NOVA_REDIS_DB")) : 0;
            RedisClient r;
            if (!r.connect(rh, port, pass ? pass : "", db)) continue;
            r.set("novawaf:api:assets", snap);
            for (auto& t : traces) r.rpush("novawaf:ai:agentic:traces", t);
            if (!traces.empty()) r.ltrim("novawaf:ai:agentic:traces", 0, 1999);
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

    // ---- 攻击事件总线订阅（观察者模式）：态势落库 + 外部 SIEM 出口 ----
    EventBus<AttackEvent>::instance().subscribe(
        [](const AttackEvent& e) { EventSink::instance().emit(e); });
    // SIEM 出口（webhook/syslog）：订阅同一总线，异步批量投递，未配置出口时 no-op
    SiemExporter::instance().start();

    // ---- 异步上游转发：独立 IO 线程池 + 连接池，reactor 不再被上游阻塞 ----
    int ioThreads = getenv("NOVA_IO_THREADS") ? std::atoi(getenv("NOVA_IO_THREADS"))
                                              : (int)std::thread::hardware_concurrency();
    g_upstream = std::make_shared<UpstreamForwarder>((size_t)ioThreads, 1 << 16);
    g_upstream->setOnDisconnect([&ddos](const std::string& ip) { ddos.onDisconnect(ip); });
    std::printf("  Upstream async forwarder: io_threads=%d (pool + keep-alive reuse)\n", ioThreads);

    std::printf("NovaWAF engine v%s starting on port %d with %d reactors\n", NOVAWAF_VERSION, port, threads);
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
    // ---- TLS / HTTP/3 配置 ----
    // NOVA_TLS_CERT + NOVA_TLS_KEY 同时设置才启用；NOVA_TLS_PORT 默认 8443。
    // NOVA_H3_PORT 默认同 TLS 端口（UDP），显式设 0 禁用 h3。证书加载失败降级仅明文 h1。
    int tlsPort = 0, h3Port = 0;
    SSL_CTX* tlsCtx = nullptr;
    SSL_CTX* quicCtx = nullptr;
    {
        const char* cert = getenv("NOVA_TLS_CERT");
        const char* key = getenv("NOVA_TLS_KEY");
        if (cert && *cert && key && *key) {
            tlsPort = getenv("NOVA_TLS_PORT") ? atoi(getenv("NOVA_TLS_PORT")) : 8443;
            if (TlsContext::instance().initTcp(cert, key)) {
                tlsCtx = TlsContext::instance().tcp();
                std::printf("  TLS: port=%d ALPN=h2,http/1.1 cert=%s\n", tlsPort, cert);
            } else {
                std::fprintf(stderr, "  [tls] init failed, TLS disabled\n");
                tlsPort = 0;
            }
            const char* h3p = getenv("NOVA_H3_PORT");
            h3Port = h3p ? atoi(h3p) : tlsPort;
            if (h3Port > 0 && tlsCtx) {
                if (TlsContext::instance().initQuic(cert, key)) {
                    quicCtx = TlsContext::instance().quic();
                    std::printf("  HTTP/3: udp port=%d ALPN=h3\n", h3Port);
                } else {
                    std::fprintf(stderr, "  [h3] quic init failed, h3 disabled\n");
                    h3Port = 0;
                }
            } else {
                h3Port = 0;
            }
        }
    }
    std::vector<std::thread> reactors;
    for (int i = 0; i < threads; ++i) {
        int lfd = createListenFd(port, backlog);
        if (lfd < 0) { std::perror("listen"); return 1; }
        reactors.emplace_back(reactorLoop, lfd, tlsPort, h3Port, tlsCtx, quicCtx, port,
                              std::ref(pipeline),
                              std::ref(limiter), std::ref(ddos), ai,
                              std::ref(cc), std::ref(bot), threatIntel,
                              std::ref(shield), std::ref(geo), i);
    }
    // master 监管模式：全部 reactor 监听就绪后通知 master（pipe 写 "READY"）
    {
        const char* rfd = getenv("NOVA_READY_FD");
        if (rfd && *rfd) {
            int wfd = atoi(rfd);
            const char* msg = "READY\n";
            if (write(wfd, msg, strlen(msg)) > 0) {}
            close(wfd);
        }
    }
    for (auto& t : reactors) t.join();
    RmiGuard::instance().stop();         // 停 RMI 反代监听线程（必须 join，否则静态析构 terminate）
    if (g_upstream) g_upstream->stop();  // 排空异步转发任务（ddos 此时仍存活）
    shield.stop();
    TamperCache::instance().stop();      // 停机前把脏基线落盘
    SiemExporter::instance().stop();     // 停 SIEM 出口线程（排空残留事件）
    EventSink::instance().stop();
    TrafficSink::instance().stop();
    return 0;
}
