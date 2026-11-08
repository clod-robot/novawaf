// NovaWAF - 洪泛检测数据面：内核计数器采样 + 联动计数器中继 + 评估线程
//
// 引擎以非 root 运行，拿不到 raw socket / nft，因此 L3/L4 洪泛的"观测量"分两路：
//   1) 本地 /proc（永远可用，fail-open）：
//        /proc/net/snmp    Icmp.InMsgs / Udp.InDatagrams
//        /proc/net/netstat TcpExt.SyncookiesSent / ListenOverflows / ListenDrops /
//                          TCPReqQFullDrop（SYN 洪泛在代理层的真实痕迹：
//                          半开队列溢出后内核改用 syncookie 或直接丢弃）
//      注意：/proc 的行格式是"表头行 + 数值行"，列序随内核版本变化，
//      必须按表头名建索引，硬编码列号会在换内核后静默读错列。
//   2) root 侧 fw_enforcer.py 用 nft counter 精确采集并每秒写入 Redis
//      novawaf:fw:flood:counters（已归一为 pps），用于补足 /proc 无法区分
//      的 ACK 洪泛、DNS(UDP/53) 洪泛，以及 TCP 层 SYN 的精确 pps。
//      存在且新鲜（≤5s）时覆盖 /proc 的近似值。
//
// 评估线程（FloodMonitor）每秒：
//   采样 → FloodGuard::observeL4 → FloodGuard::tick → 取处置名单投递 FwBanPoster
//   → 把 Verdict 写入 Redis（供 fw_enforcer 下发协议级限速、供控制台展示）。
#pragma once

#include "novawaf/core/redis_client.h"
#include "novawaf/ddos/flood_guard.h"
#include "novawaf/fw/fw_ban.h"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sstream>

namespace novawaf {

// ======================= /proc 计数器增量采样 =======================
class KernelCounters {
public:
    struct Sample {
        double icmpPps = 0, udpPps = 0, synPps = 0;
        bool valid = false;   // 首个样本只建基线，不产出速率
    };

    Sample sample(int64_t nowMs) {
        Sample s;
        std::unordered_map<std::string, double> snmp, netstat;
        if (!readProc("/proc/net/snmp", snmp)) return s;
        const bool haveNet = readProc("/proc/net/netstat", netstat);
        // ICMP 洪泛以 echo 类为主：用 InEchos+InEchoReps 而非 InMsgs。
        // InMsgs 含 DestUnreach 等差错报文，UDP 打关闭端口会刷出大量 ICMP 差错，
        // 直接看 InMsgs 会把"UDP 洪泛"误判成"ICMP 洪泛"。旧内核无这两列时回退 InMsgs。
        const bool hasEchoCols = snmp.count("Icmp.InEchos") || snmp.count("Icmp.InEchoReps");
        const double icmp = hasEchoCols
                                ? pick(snmp, "Icmp.InEchos") + pick(snmp, "Icmp.InEchoReps")
                                : pick(snmp, "Icmp.InMsgs");
        // UDP 总量：InDatagrams 只统计投递到套接字的报文，打关闭端口的洪泛进的是
        // NoPorts；两者相加才是"入向 UDP 报文总量"。
        const double udp = pick(snmp, "Udp.InDatagrams") + pick(snmp, "Udp.NoPorts");
        double syn = 0;
        if (haveNet) {
            syn = pick(netstat, "TcpExt.SyncookiesSent") +
                  pick(netstat, "TcpExt.ListenOverflows") +
                  pick(netstat, "TcpExt.ListenDrops") +
                  pick(netstat, "TcpExt.TCPReqQFullDrop");
        }
        if (!prevValid_) {
            prevIcmp_ = icmp; prevUdp_ = udp; prevSyn_ = syn; prevMs_ = nowMs;
            prevValid_ = true;
            return s;
        }
        double dt = (double)(nowMs - prevMs_) / 1000.0;
        if (dt < 0.2) dt = 1.0;   // 时钟抖动保护
        s.icmpPps = rate(icmp, prevIcmp_, dt);
        s.udpPps  = rate(udp,  prevUdp_,  dt);
        s.synPps  = rate(syn,  prevSyn_,  dt);
        prevIcmp_ = icmp; prevUdp_ = udp; prevSyn_ = syn; prevMs_ = nowMs;
        s.valid = true;
        return s;
    }

private:
    static double rate(double cur, double prev, double dt) {
        const double d = cur - prev;
        return d > 0 ? d / dt : 0.0;   // 计数器回绕/重置按 0 处理（宁可漏一拍，不可误报）
    }
    static double pick(const std::unordered_map<std::string, double>& m, const char* k) {
        auto it = m.find(k);
        return it == m.end() ? 0.0 : it->second;
    }

    // 解析 /proc/net/{snmp,netstat}："Proto: 列名..." 与 "Proto: 数值..." 成对出现。
    // 统一输出 "Proto.列名" → 数值，列序变化不影响结果。
    static bool readProc(const char* path, std::unordered_map<std::string, double>& out) {
        std::ifstream f(path);
        if (!f) return false;
        std::unordered_map<std::string, std::vector<std::string>> heads;
        std::unordered_set<std::string> filled;
        std::string line;
        while (std::getline(f, line)) {
            const size_t c = line.find(':');
            if (c == std::string::npos || c == 0) continue;
            const std::string proto = line.substr(0, c);
            std::istringstream is(line.substr(c + 1));
            std::vector<std::string> tok;
            std::string t;
            while (is >> t) tok.push_back(t);
            if (tok.empty()) continue;
            auto h = heads.find(proto);
            if (h == heads.end()) { heads.emplace(proto, std::move(tok)); continue; }
            if (filled.count(proto)) continue;      // 每个协议只取第一组数值行
            const auto& names = h->second;
            const size_t n = std::min(names.size(), tok.size());
            for (size_t i = 0; i < n; ++i) {
                const char* p = tok[i].c_str();
                if (!std::isdigit((unsigned char)*p) && *p != '-') continue;  // 跳过非数值列
                out[proto + "." + names[i]] = std::atof(p);
            }
            filled.insert(proto);
        }
        return !out.empty();
    }

    bool prevValid_ = false;
    int64_t prevMs_ = 0;
    double prevIcmp_ = 0, prevUdp_ = 0, prevSyn_ = 0;
};

// ==================== root 侧 nft 计数器中继（精确 ACK/DNS/SYN） ====================
// fw_enforcer.py 每秒写：
//   novawaf:fw:flood:counters = {"ts":<unix>,"icmp":<pps>,"syn":<pps>,"ack":<pps>,
//                                "udp":<pps>,"dns":<pps>}
class RedisFloodCounters {
public:
    struct Pps { double icmp = 0, syn = 0, ack = 0, udp = 0, dns = 0; };

    // 返回 false 表示无数据/过期（调用方回退 /proc）
    bool fetch(RedisClient& r, int64_t nowUnix, Pps& out) {
        auto v = r.get("novawaf:fw:flood:counters");
        if (!v) return false;
        const std::string& js = *v;
        const double ts = num(js, "ts");
        if (ts <= 0 || (double)nowUnix - ts > 5.0) return false;   // 过期视为不可用
        out.icmp = num(js, "icmp");
        out.syn  = num(js, "syn");
        out.ack  = num(js, "ack");
        out.udp  = num(js, "udp");
        out.dns  = num(js, "dns");
        return true;
    }

private:
    static double num(const std::string& js, const char* key) {
        const std::string k = std::string("\"") + key + "\"";
        size_t p = js.find(k);
        if (p == std::string::npos) return 0;
        p = js.find(':', p + k.size());
        if (p == std::string::npos) return 0;
        return std::atof(js.c_str() + p + 1);
    }
};

// ============================== 评估线程 ==============================
class FloodMonitor {
public:
    static FloodMonitor& instance() {
        static FloodMonitor inst;
        return inst;
    }

    void start() {
        if (running_.exchange(true)) return;
        thread_ = std::thread([this] { run(); });
    }
    void stop() {
        if (!running_.exchange(false)) return;
        if (thread_.joinable()) thread_.join();
    }
    // 进程退出路径多样（监听失败/异常 return 都可能跳过显式 stop），
    // joinable thread 在静态析构时会直接 terminate，故析构兜底 join。
    ~FloodMonitor() { stop(); }

private:
    void run() {
        FloodGuard& flood = FloodGuard::instance();
        auto poster = FwBanPoster::instance();
        const char* rh = std::getenv("NOVA_REDIS_HOST");
        const bool redisWanted = rh && *rh;
        RedisClient r;
        bool connected = false;
        int64_t lastConnTry = 0;
        int64_t lastTickMs = 0, lastBanMs = 0, lastPubMs = 0;
        int lastLevel = 0;
        FloodGuard::Kind lastKind = FloodGuard::Kind::NONE;
        KernelCounters kc;
        RedisFloodCounters rc;

        auto nowMsFn = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch()).count();
        };
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            const int64_t now = nowMsFn();
            if (now - lastTickMs < 1000) continue;   // 1s 评估节拍
            lastTickMs = now;
            const int64_t sec = now / 1000;

            // ---- 采样 ----
            double icmp = 0, udp = 0, syn = 0, ack = 0, dns = 0;
            KernelCounters::Sample ks = kc.sample(now);
            if (ks.valid) { icmp = ks.icmpPps; udp = ks.udpPps; syn = ks.synPps; }

            // Redis 中继（更精确，含 ACK/DNS）；每 5s 重建一次连接
            if (redisWanted) {
                if (!connected && now - lastConnTry > 5000) {
                    lastConnTry = now;
                    const char* pass = std::getenv("NOVA_REDIS_PASS");
                    const int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
                    const int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
                    connected = r.connect(rh, port, pass ? pass : "", db, 500);
                }
                if (connected && !r.connected()) connected = false;
                if (connected) {
                    RedisFloodCounters::Pps p;
                    if (rc.fetch(r, (int64_t)std::time(nullptr), p)) {
                        icmp = p.icmp; syn = p.syn; ack = p.ack; udp = p.udp; dns = p.dns;
                    }
                }
            }

            flood.observeL4(FloodGuard::Kind::ICMP, icmp);
            flood.observeL4(FloodGuard::Kind::SYN,  syn);
            flood.observeL4(FloodGuard::Kind::ACK,  ack);
            flood.observeL4(FloodGuard::Kind::UDP,  udp);
            flood.observeL4(FloodGuard::Kind::DNS,  dns);

            // ---- 评估 ----
            flood.tick(sec);
            const FloodGuard::Verdict v = flood.verdict();
            if ((int)v.kind != (int)lastKind || v.level != lastLevel) {
                std::fprintf(stderr,
                    "[flood] kind=%s level=%d obs=%.1f thr=%.1f conf=%.2f entropy=%.2f top=%.2f %s\n",
                    FloodGuard::kindName(v.kind), v.level, v.observed, v.threshold,
                    v.confidence, v.entropy, v.topShare, v.detail.c_str());
                lastKind = v.kind;
                lastLevel = v.level;
            }

            // ---- 处置：已确认攻击源投递 fw 封禁（5s 一批）----
            if (now - lastBanMs > 5000) {
                lastBanMs = now;
                if (v.level >= 2) {
                    auto ips = flood.takeOffenders(now);
                    for (auto& ip : ips)
                        poster->enqueue(ip, "Flood", FloodGuard::kindName(v.kind));
                }
            }

            // ---- 上报：Verdict 供 fw_enforcer 做协议级限速、供控制台展示 ----
            if (redisWanted && connected && now - lastPubMs > 1000) {
                lastPubMs = now;
                const auto s = flood.stats();
                char js[768];
                std::snprintf(js, sizeof js,
                    "{\"ts\":%lld,\"kind\":\"%s\",\"level\":%d,\"confidence\":%.3f,"
                    "\"observed\":%.1f,\"threshold\":%.1f,\"entropy\":%.2f,\"topShare\":%.2f,"
                    "\"connPerSec\":%.1f,\"halfOpenPerSec\":%.1f,\"reqPerSec\":%.1f,"
                    "\"errPerSec\":%.1f,\"uniqueSources\":%.0f,\"trackedIps\":%lld}",
                    (long long)std::time(nullptr), FloodGuard::kindName(s.verdict.kind),
                    s.verdict.level, s.verdict.confidence, s.verdict.observed, s.verdict.threshold,
                    s.entropy, s.topShare, s.connPerSec, s.halfOpenPerSec, s.reqPerSec,
                    s.errPerSec, s.uniqueSources, (long long)s.trackedIps);
                r.set("novawaf:fw:flood:verdict", js);
            }
        }
        if (r.connected()) r.disconnect();
    }

    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace novawaf
