// NovaWAF - L4 RMI 反序列化实时防护（JRMP/TCP 前置代理）
// 部署形态：真实 RMI 服务改绑 127.0.0.1，本模块监听对外端口做 TCP 反代；
// C→S 方向做流式特征扫描（滚动窗口 + 跨包重叠），命中恶意反序列化特征即：
//   1) SO_LINGER=0 双向 RST 断连
//   2) FwBanPoster 投递源 IP 封禁（iptables 联动）
//   3) EventSink 上报攻击事件（控制台可视化）
// 设计要点：
//   - 独立 listener 线程 + 每连接一个 worker 线程（RMI 管理流量小，正确性优先于极致性能）
//   - 扫描仅在客户端→服务端方向（攻击载荷方向），S→C 直通零拷贝转发
//   - 滚动窗口 128KB，保留 64B 重叠防止跨包特征断裂漏检
//   - 全程 fail-open：Redis 不可用不影响转发；本模块未配置则不启动
// 配置（环境变量）：
//   NOVA_RMI_GUARD_LISTEN   监听地址，如 0.0.0.0:29174（不配置则不启动）
//   NOVA_RMI_GUARD_BACKEND  真实 RMI 服务地址，如 127.0.0.1:29173（必填）
//   NOVA_RMI_GUARD_DISABLE=1  强制禁用
#pragma once

#include "novawaf/core/event_sink.h"
#include "novawaf/fw/fw_ban.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace novawaf {

class RmiGuard {
public:
    static RmiGuard& instance() {
        static RmiGuard inst;
        return inst;
    }

    void start() {
        const char* dis = std::getenv("NOVA_RMI_GUARD_DISABLE");
        if (dis && *dis == '1') return;
        const char* listenAddr = std::getenv("NOVA_RMI_GUARD_LISTEN");
        const char* backend = std::getenv("NOVA_RMI_GUARD_BACKEND");
        if (!listenAddr || !*listenAddr || !backend || !*backend) return;
        if (!parseAddr(listenAddr, listenIp_, listenPort_)) return;
        if (!parseAddr(backend, backendIp_, backendPort_)) return;
        running_ = true;
        acceptThread_ = std::thread([this] { acceptLoop(); });
    }

    void stop() {
        running_ = false;
        if (listenFd_ >= 0) { ::shutdown(listenFd_, SHUT_RDWR); ::close(listenFd_); listenFd_ = -1; }
        if (acceptThread_.joinable()) acceptThread_.join();
    }

    int64_t blockedCount() const { return blocked_.load(); }
    int64_t connCount() const { return accepted_.load(); }

private:
    RmiGuard() = default;

    // ---- 反序列化攻击特征库（JRMP/Java 序列化流中类名与协议串为明文，子串匹配即可）----
    struct Rule {
        const char* id;
        const char* needle;
        const char* name;
        const char* severity;
    };
    static const Rule* rules() {
        static const Rule kRules[] = {
            // JNDI 注入外连协议（Log4Shell/JdbcRowSet/RMI 回连通用特征）
            {"RMI-001", "ldap://",   "JNDI LDAP 远程类加载",      "critical"},
            {"RMI-002", "ldaps://",  "JNDI LDAPS 远程类加载",     "critical"},
            {"RMI-003", "dns://",    "JNDI DNS 探测外连",         "high"},
            {"RMI-004", "corbaname", "JNDI CORBA 远程引用",       "high"},
            {"RMI-005", "iiop://",   "JNDI IIOP 远程引用",        "high"},
            // 经典反序列化 gadget 类名（ysoserial 全谱系）
            {"RMI-101", "org.apache.commons.collections.functors", "CommonsCollections gadget 链", "critical"},
            {"RMI-102", "org.apache.commons.collections4.functors", "CommonsCollections4 gadget 链", "critical"},
            {"RMI-103", "org.apache.commons.beanutils",            "CommonsBeanutils gadget 链",   "critical"},
            {"RMI-104", "com.sun.rowset.JdbcRowSetImpl",           "JdbcRowSetImpl JNDI gadget",   "critical"},
            {"RMI-105", "TemplatesImpl",                           "TemplatesImpl 字节码加载 gadget", "critical"},
            {"RMI-106", "org.codehaus.groovy",                     "Groovy gadget 链",             "critical"},
            {"RMI-107", "groovy.lang.GroovyShell",                 "GroovyShell 代码执行",         "critical"},
            {"RMI-108", "bsh.Interpreter",                         "BeanShell 脚本执行 gadget",    "critical"},
            {"RMI-109", "com.mchange.v2.c3p0",                     "C3P0 JNDI gadget 链",          "critical"},
            {"RMI-110", "org.mozilla.javascript",                  "Rhino 脚本执行 gadget",        "high"},
            {"RMI-111", "org.apache.commons.configuration",        "CommonsConfiguration gadget",  "high"},
            {"RMI-112", "clojure.core$",                           "Clojure gadget 链",            "high"},
            {"RMI-113", "BadAttributeValueExpException",           "BADAttrValExp 触发器 gadget",  "high"},
            {"RMI-114", "javax.script.ScriptEngineManager",        "ScriptEngine gadget 链",       "high"},
            {"RMI-115", "ysoserial",                               "ysoserial 工具指纹",           "high"},
        };
        return kRules;
    }
    static size_t ruleCount() { return 18; }

    static bool parseAddr(const std::string& s, std::string& ip, uint16_t& port) {
        auto pos = s.rfind(':');
        if (pos == std::string::npos) return false;
        ip = s.substr(0, pos);
        port = (uint16_t)std::atoi(s.substr(pos + 1).c_str());
        return port > 0 && !ip.empty();
    }

    void acceptLoop() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) { running_ = false; return; }
        int one = 1;
        setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(listenPort_);
        addr.sin_addr.s_addr = (listenIp_ == "0.0.0.0") ? INADDR_ANY : inet_addr(listenIp_.c_str());
        if (::bind(listenFd_, (sockaddr*)&addr, sizeof(addr)) < 0 ||
            ::listen(listenFd_, 128) < 0) {
            ::close(listenFd_);
            listenFd_ = -1;
            running_ = false;
            return;
        }
        while (running_) {
            sockaddr_in ca{};
            socklen_t cl = sizeof(ca);
            int cfd = ::accept(listenFd_, (sockaddr*)&ca, &cl);
            if (cfd < 0) {
                if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            accepted_.fetch_add(1);
            char ipbuf[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &ca.sin_addr, ipbuf, sizeof(ipbuf));
            // 每连接一个 worker 线程（detach），RMI 管理面连接数极少
            std::thread([this, cfd, ip = std::string(ipbuf)] { handleConn(cfd, ip); }).detach();
        }
    }

    int connectBackend() {
        int bfd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (bfd < 0) return -1;
        sockaddr_in ba{};
        ba.sin_family = AF_INET;
        ba.sin_port = htons(backendPort_);
        ba.sin_addr.s_addr = inet_addr(backendIp_.c_str());
        timeval tv{5, 0};
        setsockopt(bfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (::connect(bfd, (sockaddr*)&ba, sizeof(ba)) < 0) { ::close(bfd); return -1; }
        return bfd;
    }

    // 命中处置：RST 断连 + 封 IP + 事件上报
    void onAttack(const std::string& ip, const Rule& rule, const std::string& matched) {
        blocked_.fetch_add(1);
        FwBanPoster::instance()->enqueue(ip, "RMI", rule.id);
        AttackEvent ev{};
        ev.ts = std::time(nullptr);
        ev.ip = ip;
        ev.action = "block";
        ev.category = "RMI";
        ev.ruleId = rule.id;
        ev.matched = std::string(rule.name) + " | " + matched;
        ev.severity = rule.severity;
        ev.uri = "tcp://" + backendIp_ + ":" + std::to_string(backendPort_);
        ev.host = "rmi-guard";
        EventSink::instance().emit(ev);
    }

    static void rstClose(int fd) {
        linger ling{1, 0};  // RST 立即断连，不进 TIME_WAIT
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
        ::close(fd);
    }

    void handleConn(int cfd, const std::string& clientIp) {
        int bfd = -1;  // 惰性连接：首次 C→S 数据通过检测后才建立（支持无后端的蜜罐模式）

        std::string win;  // C→S 检测滚动窗口
        win.reserve(140 * 1024);
        bool blocked = false;

        while (running_) {
            pollfd fds[2] = {{cfd, POLLIN, 0}, {bfd, POLLIN, 0}};
            nfds_t nfds = (bfd >= 0) ? 2 : 1;
            int n = ::poll(fds, nfds, 30000);
            if (n < 0) break;
            if (n == 0) continue;  // 空闲保活
            for (nfds_t i = 0; i < nfds; ++i) {
                if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                char buf[16384];
                ssize_t r = ::recv(fds[i].fd, buf, sizeof(buf), 0);
                if (r <= 0) goto done;  // 对端关闭或错误
                if (i == 0) {
                    // C→S：先检测后转发
                    win.append(buf, (size_t)r);
                    const Rule* hit = scanWindow(win);
                    if (hit) {
                        onAttack(clientIp, *hit, hit->needle);
                        rstClose(cfd);
                        if (bfd >= 0) ::close(bfd);
                        blocked = true;
                        goto done;
                    }
                    // 惰性建立后端连接；连不上则关闭（蜜罐模式下永远连不上，连接自然终止，
                    // 但攻击特征已在连接存续期间完成检测）
                    if (bfd < 0) {
                        bfd = connectBackend();
                        if (bfd < 0) { ::close(cfd); return; }
                    }
                    if (::send(bfd, buf, (size_t)r, MSG_NOSIGNAL) <= 0) goto done;
                    // 滚动窗口裁剪：保留尾部 64KB + 64B 重叠防跨包断裂
                    if (win.size() > 128 * 1024)
                        win.erase(0, win.size() - 64 * 1024);
                } else {
                    // S→C：直通转发
                    if (::send(cfd, buf, (size_t)r, MSG_NOSIGNAL) <= 0) goto done;
                }
            }
        }
    done:
        if (!blocked) {
            ::close(cfd);
            if (bfd >= 0) ::close(bfd);
        }
    }

    // 只扫描新增区域 + 64B 重叠（needle 最长 < 48B，重叠足够覆盖跨包断裂）
    const Rule* scanWindow(const std::string& win) {
        // 简化策略：窗口上限 128KB，全量 contains 扫描成本低（18 条短特征，memmem 级别）
        const Rule* rs = rules();
        for (size_t i = 0; i < ruleCount(); ++i) {
            if (containsBytes(win, rs[i].needle)) return &rs[i];
        }
        return nullptr;
    }

    static bool containsBytes(const std::string& hay, const char* needle) {
        size_t nl = std::strlen(needle);
        if (hay.size() < nl) return false;
        return std::search(hay.begin(), hay.end(), needle, needle + nl,
                           [](char a, char b) { return a == b; }) != hay.end();
    }

    bool running_{false};
    int listenFd_{-1};
    std::string listenIp_;
    uint16_t listenPort_{0};
    std::string backendIp_;
    uint16_t backendPort_{0};
    std::thread acceptThread_;
    std::atomic<int64_t> blocked_{0};
    std::atomic<int64_t> accepted_{0};
};

}  // namespace novawaf
