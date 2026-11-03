// NovaWAF - 外部 SIEM 出口（观察者模式：订阅攻击事件总线 -> webhook / syslog）
// 设计：
//   * 订阅 EventBus<AttackEvent>，回调只做无锁 MPMC 入队（满则丢弃计数），热路径零阻塞。
//   * 单后台线程批量出队，按 flushMs 聚合后分别投递：
//       - webhook：HTTP POST JSON（NOVA_SIEM_WEBHOOK=http://host[:port][/path]，
//                  可选 NOVA_SIEM_WEBHOOK_AUTH=Bearer token），批量 events 数组；
//       - syslog ：UDP RFC3164 头 + CEF 扩展（NOVA_SIEM_SYSLOG=host[:port]，默认 514），
//                  每事件一个数据报，可直接对接 rsyslog/Splunk/QRadar/ArcSight。
//   * fail-open：未配置出口则不订阅不起线程（零开销）；发送失败静默丢弃并计数，
//     绝不影响引擎拦截与转发主链路。
#pragma once

#include "novawaf/core/event_bus.h"
#include "novawaf/core/event_sink.h"  // AttackEvent
#include "novawaf/core/mpmc_queue.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <vector>

namespace novawaf {

class SiemExporter {
public:
    static SiemExporter& instance() {
        static SiemExporter inst;
        return inst;
    }

    // 解析配置并启动出口线程；两个出口都未配置时为 no-op。
    void start() {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;
        flushMs_ = envInt("NOVA_SIEM_FLUSH_MS", 500);
        const char* wh = std::getenv("NOVA_SIEM_WEBHOOK");
        if (wh && *wh) webhookOk_ = parseWebhook(wh);
        const char* auth = std::getenv("NOVA_SIEM_WEBHOOK_AUTH");
        if (auth && *auth) authHeader_ = "Authorization: " + std::string(auth) + "\r\n";
        const char* sl = std::getenv("NOVA_SIEM_SYSLOG");
        if (sl && *sl) syslogOk_ = parseSyslog(sl);
        if (!webhookOk_ && !syslogOk_) {
            running_.store(false, std::memory_order_release);
            return;  // 未配置出口：零开销 no-op
        }
        subId_ = EventBus<AttackEvent>::instance().subscribe(
            [this](const AttackEvent& e) {
                if (!queue_.enqueue(e)) dropped_.fetch_add(1, std::memory_order_relaxed);
            });
        thread_ = std::thread([this] { loop(); });
        std::printf("  SIEM exporter: webhook=%s syslog=%s flush=%dms\n",
                    webhookOk_ ? webhookUrl_.c_str() : "off",
                    syslogOk_ ? syslogTarget_.c_str() : "off", flushMs_);
    }

    void stop() {
        if (!running_.load(std::memory_order_acquire)) return;
        running_.store(false, std::memory_order_release);
        if (subId_) EventBus<AttackEvent>::instance().unsubscribe(subId_);
        if (thread_.joinable()) thread_.join();
        if (syslogFd_ >= 0) { ::close(syslogFd_); syslogFd_ = -1; }
    }

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    SiemExporter() : queue_(8192) {}
    SiemExporter(const SiemExporter&) = delete;
    SiemExporter& operator=(const SiemExporter&) = delete;

    static int envInt(const char* k, int def) {
        const char* v = std::getenv(k);
        return (v && *v) ? std::atoi(v) : def;
    }

    // ---- 配置解析 ----
    bool parseWebhook(const std::string& url) {
        std::string u = url;
        auto scheme = u.find("://");
        if (scheme != std::string::npos) u = u.substr(scheme + 3);  // 仅支持 http
        auto slash = u.find('/');
        std::string hp = slash == std::string::npos ? u : u.substr(0, slash);
        webhookPath_ = slash == std::string::npos ? "/" : u.substr(slash);
        auto colon = hp.rfind(':');
        if (colon != std::string::npos) {
            webhookHost_ = hp.substr(0, colon);
            webhookPort_ = std::atoi(hp.substr(colon + 1).c_str());
        } else {
            webhookHost_ = hp;
            webhookPort_ = 80;
        }
        if (webhookHost_.empty() || webhookPort_ <= 0) return false;
        webhookUrl_ = url;
        return true;
    }

    bool parseSyslog(const std::string& target) {
        auto colon = target.rfind(':');
        if (colon != std::string::npos) {
            syslogHost_ = target.substr(0, colon);
            syslogPort_ = std::atoi(target.substr(colon + 1).c_str());
        } else {
            syslogHost_ = target;
            syslogPort_ = 514;
        }
        if (syslogHost_.empty() || syslogPort_ <= 0) return false;
        syslogFd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (syslogFd_ < 0) return false;
        syslogAddr_ = {};
        syslogAddr_.sin_family = AF_INET;
        syslogAddr_.sin_port = htons((uint16_t)syslogPort_);
        if (::inet_pton(AF_INET, syslogHost_.c_str(), &syslogAddr_.sin_addr) != 1) {
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            if (::getaddrinfo(syslogHost_.c_str(), nullptr, &hints, &res) == 0 && res) {
                syslogAddr_.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
                ::freeaddrinfo(res);
            } else {
                ::close(syslogFd_);
                syslogFd_ = -1;
                return false;
            }
        }
        syslogTarget_ = syslogHost_ + ":" + std::to_string(syslogPort_);
        return true;
    }

    // ---- 后台批量循环 ----
    void loop() {
        auto last = std::chrono::steady_clock::now();
        while (running_.load(std::memory_order_acquire)) {
            drain();
            auto now = std::chrono::steady_clock::now();
            if (!pending_.empty() &&
                (pending_.size() >= 200 ||
                 std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() >= flushMs_)) {
                flush();
                last = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        drain();
        if (!pending_.empty()) flush();  // 停机前排空
        uint64_t d = dropped_.load(std::memory_order_relaxed);
        if (d) std::printf("  SIEM exporter: dropped=%llu (queue full / send fail)\n",
                           (unsigned long long)d);
    }

    void drain() {
        AttackEvent e;
        int n = 0;
        while (queue_.dequeue(e) && n < 5000) {
            pending_.push_back(e);
            ++n;
        }
    }

    void flush() {
        if (syslogOk_) {
            for (auto& e : pending_) sendSyslog(e);
        }
        if (webhookOk_) {
            // 分批 POST，单批最多 200 条，避免单包过大
            for (size_t off = 0; off < pending_.size(); off += 200) {
                size_t end = off + 200 < pending_.size() ? off + 200 : pending_.size();
                if (!postJson(pending_.data() + off, end - off))
                    dropped_.fetch_add(end - off, std::memory_order_relaxed);
            }
        }
        pending_.clear();
    }

    // ---- webhook：HTTP/1.0 POST JSON（短连接，1.5s 超时，失败丢弃）----
    bool postJson(const AttackEvent* evs, size_t n) {
        std::string body = "{\"source\":\"novawaf\",\"events\":[";
        for (size_t i = 0; i < n; ++i) {
            if (i) body += ",";
            body += eventJson(evs[i]);
        }
        body += "]}";
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)webhookPort_);
        bool hostOk = ::inet_pton(AF_INET, webhookHost_.c_str(), &addr.sin_addr) == 1;
        if (!hostOk) {
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (::getaddrinfo(webhookHost_.c_str(), nullptr, &hints, &res) == 0 && res) {
                addr.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
                ::freeaddrinfo(res);
                hostOk = true;
            }
        }
        if (!hostOk) { ::close(fd); return false; }
        int rc = ::connect(fd, (sockaddr*)&addr, sizeof(addr));
        if (rc < 0 && errno != EINPROGRESS) { ::close(fd); return false; }
        if (rc < 0) {
            struct pollfd pfd{};
            pfd.fd = fd; pfd.events = POLLOUT;
            if (::poll(&pfd, 1, 1500) <= 0) { ::close(fd); return false; }
            int err = 0; socklen_t el = sizeof(err);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
            if (err != 0) { ::close(fd); return false; }
        }
        ::fcntl(fd, F_SETFL, flags);  // 恢复阻塞写
        std::string req = "POST " + webhookPath_ + " HTTP/1.0\r\n"
                          "Host: " + webhookHost_ + "\r\n" +
                          authHeader_ +
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        bool ok = sendAllFd(fd, req.data(), req.size());
        ::close(fd);  // 不等响应：SIEM 出口绝不能阻塞引擎
        return ok;
    }

    static bool sendAllFd(int fd, const char* d, size_t n) {
        size_t s = 0;
        while (s < n) {
            ssize_t w = ::send(fd, d + s, n - s, MSG_NOSIGNAL);
            if (w <= 0) { if (errno == EINTR) continue; return false; }
            s += (size_t)w;
        }
        return true;
    }

    // ---- syslog：RFC3164 + CEF ----
    static int severityRank(const std::string& sev) {  // CEF 0-10
        if (sev == "high") return 8;
        if (sev == "low")  return 2;
        if (sev == "info") return 1;
        return 5;  // medium / 空
    }
    static int priOf(const std::string& sev) {  // facility=user(1)*8 + level
        if (sev == "high") return 11;   // err
        if (sev == "low" || sev == "info") return 13;  // notice
        return 12;                      // warning
    }
    // CEF 头字段转义：\ 与 |
    static std::string cefEscHead(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '\\') o += "\\\\";
            else if (c == '|') o += "\\|";
            else if (c != '\n' && c != '\r') o += c;
        }
        return o;
    }
    // CEF 扩展字段转义：\ = 与换行
    static std::string cefEscExt(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '\\') o += "\\\\";
            else if (c == '=') o += "\\=";
            else if (c == '\n' || c == '\r') o += ' ';
            else o += c;
        }
        return o;
    }

    void sendSyslog(const AttackEvent& e) {
        char ts[32];
        std::time_t t = e.ts > 0 ? (std::time_t)e.ts : std::time(nullptr);
        std::tm lt{};
        localtime_r(&t, &lt);
        std::strftime(ts, sizeof(ts), "%b %e %T", &lt);
        char host[64] = {0};
        if (::gethostname(host, sizeof(host) - 1) != 0) std::strcpy(host, "novawaf");
        std::string sev = e.severity.empty() ? "medium" : e.severity;
        std::string sig = e.ruleId.empty() ? "GENERIC" : e.ruleId;
        std::string name = e.category.empty() ? "attack" : e.category;
        std::string msg =
            "<" + std::to_string(priOf(sev)) + ">" + ts + " " + host +
            " novawaf[" + std::to_string((long)::getpid()) + "]: " +
            "CEF:0|NovaWAF|NovaWAF-Engine|1.0|" + cefEscHead(sig) + "|" + cefEscHead(name) +
            "|" + std::to_string(severityRank(sev)) + "|" +
            "src=" + cefEscExt(e.ip) + " act=" + cefEscExt(e.action) +
            " request=" + cefEscExt(e.uri) + " requestHost=" + cefEscExt(e.host) +
            " msg=" + cefEscExt(e.matched);
        if (!e.traceId.empty())
            msg += " cs1=" + cefEscExt(e.traceId) + " cs1Label=traceId";
        ssize_t w = ::sendto(syslogFd_, msg.data(), msg.size(), MSG_NOSIGNAL,
                             (sockaddr*)&syslogAddr_, sizeof(syslogAddr_));
        if (w <= 0) dropped_.fetch_add(1, std::memory_order_relaxed);
    }

    // ---- JSON 序列化（与 EventSink 事件同构，便于 SIEM 侧统一解析）----
    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 2);
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        o += buf;
                    } else o += c;
            }
        }
        return o;
    }

    static std::string eventJson(const AttackEvent& e) {
        std::string o = "{\"ts\":" + std::to_string(e.ts) +
                        ",\"ip\":\"" + esc(e.ip) + "\"" +
                        ",\"action\":\"" + esc(e.action) + "\"" +
                        ",\"category\":\"" + esc(e.category) + "\"" +
                        ",\"ruleId\":\"" + esc(e.ruleId) + "\"" +
                        ",\"matched\":\"" + esc(e.matched) + "\"" +
                        ",\"severity\":\"" + esc(e.severity) + "\"" +
                        ",\"uri\":\"" + esc(e.uri) + "\"" +
                        ",\"host\":\"" + esc(e.host) + "\"";
        if (!e.traceId.empty()) o += ",\"trace\":\"" + esc(e.traceId) + "\"";
        o += "}";
        return o;
    }

    MpmcQueue<AttackEvent> queue_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> dropped_{0};
    std::thread thread_;
    size_t subId_ = 0;
    int flushMs_ = 500;

    // webhook 配置
    bool webhookOk_ = false;
    std::string webhookUrl_;
    std::string webhookHost_;
    int webhookPort_ = 80;
    std::string webhookPath_ = "/";
    std::string authHeader_;

    // syslog 配置
    bool syslogOk_ = false;
    std::string syslogTarget_;
    std::string syslogHost_;
    int syslogPort_ = 514;
    int syslogFd_ = -1;
    sockaddr_in syslogAddr_{};

    std::vector<AttackEvent> pending_;  // 仅后台线程访问
};

}  // namespace novawaf
