// NovaWAF - 自研 IPS（入侵防御系统）引擎
// 设计要点：
//  1) 深度检测：在通用规则检测器之外，对 HTTP 协议层与攻击行为链做结构化分析——
//     协议异常 / HTTP 走私、编码绕过、参数污染、无文件执行与 C2 特征、敏感端点探测。
//  2) 实时阻断：加权评分（弱信号累计、强信号直达阈值），命中即在请求路径上拦截，
//     不依赖响应侧或离线分析。
//  3) 联动防护：高危命中直接投递防火墙封禁队列（FwBanPoster，含去重与信誉衰减），
//     告警异步写入 Redis novawaf:ips:alerts（LTRIM 保留最近 2000 条，供控制台展示）。
//  4) 性能：策略与签名集只读共享（copy-on-write 原子替换）；热路径零锁、零拷贝遍历
//     payload；AC 预筛 + 语义二次确认；单字段扫描窗口限长，防大包 CPU 放大。
//  5) 可运维：策略经 Redis 键 novawaf:ips:policy（+ :version 脏检查）热加载，
//     支持 block/observe 双模式、阈值与模块开关；内置默认策略保证零配置可用。
#pragma once

#include "novawaf/core/json.h"
#include "novawaf/core/redis_client.h"
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"
#include "novawaf/fw/fw_ban.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace novawaf {

// ---------------- IPS 策略（不可变对象，热更时整体原子替换） ----------------
struct IpsPolicy {
    bool enabled = true;
    bool blockMode = true;         // false = 观察模式：只告警不拦截
    int blockScore = 60;           // 总分达到该值即实时阻断
    int logScore = 30;             // 达到该值记录告警（不阻断）
    int fwBanScore = 80;           // 达到该值立即联动防火墙封禁（高危直达）
    int maxTargetBytes = 16384;    // 请求行（path+query）超长记弱信号
    // 检测模块开关
    bool protocol = true;          // 协议异常 / HTTP 走私
    bool encoding = true;          // 编码绕过（双重编码 / 超长 UTF-8 / %u / %00）
    bool hpp = true;               // HTTP 参数污染
    bool toolC2 = true;            // 无文件执行 / C2 / 反弹 shell / WebShell
    bool sensitivePath = true;     // 敏感端点探测
};

// ---------------- IPS 策略中心（单例，原子指针读，无锁热路径） ----------------
class IpsEngine {
public:
    static IpsEngine& instance() {
        static IpsEngine e;
        return e;
    }

    // 热路径：一次原子 load 拿到只读策略快照（shared_ptr 拷贝，无锁）
    std::shared_ptr<const IpsPolicy> policy() const {
        return policy_.load(std::memory_order_acquire);
    }

    // 从 Redis JSON 热加载策略；空串/解析失败 → 内置默认（fail-open，不影响检测）
    // 返回当前启用模块数，供启动日志与运维核对。
    size_t loadPolicy(const std::string& blob) {
        auto p = std::make_shared<IpsPolicy>();
        if (!blob.empty()) {
            try {
                JsonValue root = parseJson(blob);
                if (root.isObject()) {
                    p->enabled = boolOr(root.at("enabled"), p->enabled);
                    const JsonValue& mode = root.at("mode");
                    if (mode.isString())
                        p->blockMode = !(mode.str == "observe" || mode.str == "log" ||
                                         mode.str == "monitor");
                    p->blockScore = intOr(root.at("blockScore"), p->blockScore, 10, 100);
                    p->logScore = intOr(root.at("logScore"), p->logScore, 1, 100);
                    p->fwBanScore = intOr(root.at("fwBanScore"), p->fwBanScore, 10, 100);
                    p->maxTargetBytes = intOr(root.at("maxTargetBytes"), p->maxTargetBytes,
                                              1024, 65536);
                    const JsonValue& m = root.at("modules");
                    if (m.isObject()) {
                        p->protocol = boolOr(m.at("protocol"), p->protocol);
                        p->encoding = boolOr(m.at("encoding"), p->encoding);
                        p->hpp = boolOr(m.at("hpp"), p->hpp);
                        p->toolC2 = boolOr(m.at("toolC2"), p->toolC2);
                        p->sensitivePath = boolOr(m.at("sensitivePath"), p->sensitivePath);
                    }
                }
            } catch (...) {
                // 策略格式非法：保留内置默认，绝不影响检测链路
            }
        }
        // 配置自洽修正：告警阈值不得高于阻断阈值，联动阈值不得低于阻断阈值
        if (p->logScore > p->blockScore) p->logScore = p->blockScore;
        if (p->fwBanScore < p->blockScore) p->fwBanScore = p->blockScore;
        policy_.store(std::move(p), std::memory_order_release);
        return moduleCount();
    }

    size_t moduleCount() const {
        auto p = policy();
        return (size_t)p->protocol + (size_t)p->encoding + (size_t)p->hpp +
               (size_t)p->toolC2 + (size_t)p->sensitivePath;
    }

private:
    IpsEngine() : policy_(std::make_shared<IpsPolicy>()) {}

    static int intOr(const JsonValue& v, int def, int lo, int hi) {
        int x = v.isNumber() ? (int)v.num : def;
        if (x < lo) x = lo;
        if (x > hi) x = hi;
        return x;
    }
    static bool boolOr(const JsonValue& v, bool def) { return v.isBool() ? v.b : def; }

    std::atomic<std::shared_ptr<const IpsPolicy>> policy_;
};

// ---------------- IPS 告警投递（热路径零阻塞） ----------------
// 命中只入内存队列；后台线程批量 RPUSH 到 Redis 列表 novawaf:ips:alerts，
// 并 LTRIM 保留最近 2000 条。同 IP+规则 30s 去重，队列有界，Redis 不可用全程 fail-open。
class IpsAlertSink {
public:
    static IpsAlertSink& instance() {
        static IpsAlertSink s;
        return s;
    }

    void post(const std::string& ip, const std::string& action, const std::string& ruleId,
              int score, const std::string& path, const std::string& host,
              const std::string& matched) {
        std::string key = ip;
        key.push_back('|');
        key += ruleId;
        std::string line = buildJson(ip, action, ruleId, score, path, host, matched);
        std::lock_guard<std::mutex> lk(mtx_);
        int64_t now = nowSec();
        auto it = lastSent_.find(key);
        if (it != lastSent_.end() && now - it->second < kDedupSec) {
            ++suppressed_;
            return;
        }
        lastSent_[key] = now;
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(line));
    }

    uint64_t posted() const { return posted_.load(std::memory_order_relaxed); }
    size_t queueDepth() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return queue_.size();
    }

private:
    static constexpr const char* kKey = "novawaf:ips:alerts";
    static constexpr int64_t kMaxAlerts = 2000;
    static constexpr int64_t kDedupSec = 30;
    static constexpr size_t kMaxQueue = 4096;

    IpsAlertSink() {
        thread_ = std::thread([this] { run(); });
    }
    ~IpsAlertSink() {
        running_.store(false, std::memory_order_relaxed);
        if (thread_.joinable()) thread_.join();
    }

    static int64_t nowSec() {
        return (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    // JSON 字符串转义（控制字符 → \u00xx），并限长，避免告警体被大包撑爆
    static std::string esc(const std::string& s, size_t maxLen) {
        size_t n = std::min(s.size(), maxLen);
        std::string o;
        o.reserve(n + 16);
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)s[i];
            switch (c) {
                case '"':  o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof buf, "\\u%04x", c);
                        o += buf;
                    } else {
                        o += (char)c;
                    }
            }
        }
        return o;
    }

    static std::string buildJson(const std::string& ip, const std::string& action,
                                 const std::string& ruleId, int score,
                                 const std::string& path, const std::string& host,
                                 const std::string& matched) {
        std::string j;
        j.reserve(256);
        j += "{\"ts\":" + std::to_string(nowSec());
        j += ",\"ip\":\"" + esc(ip, 64) + "\"";
        j += ",\"action\":\"" + esc(action, 16) + "\"";
        j += ",\"rule\":\"" + esc(ruleId, 32) + "\"";
        j += ",\"score\":" + std::to_string(score);
        j += ",\"path\":\"" + esc(path, 256) + "\"";
        j += ",\"host\":\"" + esc(host, 128) + "\"";
        j += ",\"matched\":\"" + esc(matched, 200) + "\"";
        j += "}";
        return j;
    }

    void run() {
        RedisClient r;
        bool connected = false;
        while (running_.load(std::memory_order_relaxed)) {
            std::vector<std::string> batch;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (!queue_.empty()) batch.swap(queue_);
                // 去重表惰性回收，防长期运行内存增长
                int64_t now = nowSec();
                for (auto it = lastSent_.begin(); it != lastSent_.end();) {
                    if (now - it->second > 300) it = lastSent_.erase(it);
                    else ++it;
                }
            }
            if (!batch.empty()) {
                if (!connected || !r.connected()) {
                    const char* rh = std::getenv("NOVA_REDIS_HOST");
                    if (rh && *rh) {
                        int port = std::getenv("NOVA_REDIS_PORT")
                                       ? std::atoi(std::getenv("NOVA_REDIS_PORT"))
                                       : 6379;
                        const char* pass = std::getenv("NOVA_REDIS_PASS");
                        int db = std::getenv("NOVA_REDIS_DB")
                                     ? std::atoi(std::getenv("NOVA_REDIS_DB"))
                                     : 0;
                        connected = r.connect(rh, port, pass ? pass : "", db, 1000);
                    }
                }
                if (connected) {
                    auto len = r.rpushMulti(kKey, batch);
                    if (len) {
                        posted_.fetch_add(batch.size(), std::memory_order_relaxed);
                        if (*len > kMaxAlerts) r.ltrim(kKey, -kMaxAlerts, -1);
                    } else {
                        connected = false;  // 连接失效：下轮重连，告警不阻塞业务
                    }
                }
            }
            for (int i = 0; i < 5 && running_.load(std::memory_order_relaxed); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::atomic<bool> running_{true};
    std::atomic<uint64_t> posted_{0};
    mutable std::mutex mtx_;
    std::vector<std::string> queue_;
    std::unordered_map<std::string, int64_t> lastSent_;
    uint64_t suppressed_ = 0;
    uint64_t dropped_ = 0;
    std::thread thread_;
};

// ---------------- IPS 检测器（策略模式接入检测流水线） ----------------
class IpsDetector : public IDetector {
public:
    const char* name() const override { return "IPS"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<IpsDetector>(); }

    DetectionResult detect(const HttpRequest& req) override {
        const IpsPolicy& p = *IpsEngine::instance().policy();
        if (!p.enabled) return {};

        Scoreboard sb;
        // 结构层最便宜，先判；命中高危后跳过昂贵的签名扫描（CPU 保护）
        if (p.protocol) checkProtocol(req, p, sb);
        if (p.sensitivePath) checkSensitivePath(req, sb);
        if (p.encoding) checkEncoding(req, sb);
        if (p.hpp) checkHpp(req, sb);
        if (p.toolC2 && sb.total() < p.blockScore) checkToolC2(req, sb);

        const int score = sb.total();
        if (score < p.logScore) return {};
        const Hit* top = sb.strongest();
        if (!top) return {};

        const std::string host = headerCi(req, "host");
        const bool block = p.blockMode && score >= p.blockScore;
        if (block) {
            // 联动防护：高危直达阈值 → 立即投递防火墙封禁（内部去重 + 信誉衰减，
            // 与主流程 EscalationGuard 的升级封禁互不冲突）
            if (score >= p.fwBanScore && !req.clientIp.empty())
                FwBanPoster::instance()->enqueue(req.clientIp, "IPS", top->ruleId);
            IpsAlertSink::instance().post(req.clientIp, "block", top->ruleId, score,
                                          req.path, host, top->evidence);
            DetectionResult r;
            r.action = Action::BLOCK;
            r.ruleId = top->ruleId;
            r.category = "IPS";
            r.description = top->desc;
            r.matched = top->evidence;
            r.score = score;
            return r;
        }
        // 观察模式 / 低于阻断阈值：只记录告警，放行由后续流程决定
        IpsAlertSink::instance().post(req.clientIp, "alert", top->ruleId, score,
                                      req.path, host, top->evidence);
        return {};
    }

private:
    struct Hit {
        std::string ruleId;
        std::string desc;
        int score = 0;
        std::string evidence;
    };

    // 评分板：同一规则只计一次（取最高分），总分封顶 100；固定数组零动态扩容
    class Scoreboard {
    public:
        void add(const char* ruleId, const char* desc, int score, std::string_view ev) {
            for (int i = 0; i < n_; ++i) {
                if (items_[i].ruleId == ruleId) {
                    if (score > items_[i].score) {
                        items_[i].score = score;
                        items_[i].evidence.assign(ev.data(), std::min(ev.size(), kEvMax));
                    }
                    return;
                }
            }
            if (n_ >= kMax) return;
            items_[n_].ruleId = ruleId;
            items_[n_].desc = desc;
            items_[n_].score = score;
            items_[n_].evidence.assign(ev.data(), std::min(ev.size(), kEvMax));
            ++n_;
        }
        int total() const {
            int t = 0;
            for (int i = 0; i < n_; ++i) t += items_[i].score;
            return t > 100 ? 100 : t;
        }
        const Hit* strongest() const {
            const Hit* best = nullptr;
            for (int i = 0; i < n_; ++i)
                if (!best || items_[i].score > best->score) best = &items_[i];
            return best;
        }

    private:
        static constexpr int kMax = 16;
        static constexpr size_t kEvMax = 200;
        Hit items_[kMax];
        int n_ = 0;
    };

    // ---- 通用工具 ----
    static bool ieq(const std::string& a, const char* b) {
        size_t n = std::strlen(b);
        if (a.size() != n) return false;
        for (size_t i = 0; i < n; ++i)
            if ((char)std::tolower((unsigned char)a[i]) != b[i]) return false;
        return true;
    }
    static const std::string* headerPtr(const HttpRequest& req, const char* lowerName) {
        size_t n = std::strlen(lowerName);
        for (const auto& kv : req.headers) {
            if (kv.first.size() != n) continue;
            bool eq = true;
            for (size_t i = 0; i < n; ++i) {
                if ((char)std::tolower((unsigned char)kv.first[i]) != lowerName[i]) {
                    eq = false;
                    break;
                }
            }
            if (eq) return &kv.second;
        }
        return nullptr;
    }
    static std::string headerCi(const HttpRequest& req, const char* lowerName) {
        const std::string* v = headerPtr(req, lowerName);
        return v ? *v : std::string();
    }
    static bool isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    // 大小写不敏感的位置比较（用于编码特征字面量）
    static bool ieqAt(const std::string& s, size_t pos, const char* pat) {
        size_t n = std::strlen(pat);
        if (pos + n > s.size()) return false;
        for (size_t i = 0; i < n; ++i)
            if ((char)std::tolower((unsigned char)s[pos + i]) != pat[i]) return false;
        return true;
    }
    static bool containsI(const std::string& s, const char* pat) {
        size_t n = std::strlen(pat);
        if (n == 0 || s.size() < n) return false;
        for (size_t i = 0; i + n <= s.size(); ++i)
            if (ieqAt(s, i, pat)) return true;
        return false;
    }

    // 零拷贝遍历检测字段：path / query / body / 各请求头值
    // （query 已含 queryParams，故不重复遍历；避免 collectPayloads() 的整包拷贝）
    template <typename F>
    static void forEachPayload(const HttpRequest& req, F&& fn) {
        if (!req.path.empty()) fn(req.path);
        if (!req.query.empty()) fn(req.query);
        if (!req.body.empty()) fn(req.body);
        for (const auto& kv : req.headers)
            if (!kv.second.empty()) fn(kv.second);
    }

    // 长字段双窗口扫描（头部 8KB + 尾部 8KB），防大包 CPU 放大又不漏尾部载荷
    template <typename F>
    static void scanText(const std::string& s, F&& fn) {
        static constexpr size_t kWin = 8192;
        if (s.size() <= kWin) {
            fn(s);
            return;
        }
        fn(s.substr(0, kWin));
        fn(s.substr(s.size() - kWin));
    }

    // ---- 模块 1：协议异常 / HTTP 走私 ----
    static void checkProtocol(const HttpRequest& req, const IpsPolicy& p, Scoreboard& sb) {
        const bool http11 = (req.version == "HTTP/1.1");
        const std::string* host = headerPtr(req, "host");
        if (http11 && (!host || host->empty()))
            sb.add("IPS-1001", "HTTP/1.1 request without Host header", 20, req.path);

        const std::string* cl = headerPtr(req, "content-length");
        const std::string* te = headerPtr(req, "transfer-encoding");
        // CL + TE 同时出现：经典请求走私（CL.TE / TE.CL）前置条件，直达阻断阈值
        if (cl && !cl->empty() && te && !te->empty()) {
            std::string ev = *cl;
            ev += " / ";
            ev += *te;
            sb.add("IPS-1002", "Content-Length and Transfer-Encoding conflict (HTTP smuggling)",
                   70, ev);
        }
        // TE 混淆：合法请求只允许裸 chunked（chunked,identity / xchunked 等均属规避）
        if (te && !te->empty()) {
            std::string t = *te;
            for (auto& c : t) c = (char)std::tolower((unsigned char)c);
            // 去掉首尾空白后严格比较
            size_t a = t.find_first_not_of(" \t");
            size_t b = t.find_last_not_of(" \t");
            std::string core = (a == std::string::npos) ? "" : t.substr(a, b - a + 1);
            if (core != "chunked")
                sb.add("IPS-1003", "Transfer-Encoding obfuscation", 55, *te);
        }
        // Content-Length 非法：非数字 / 逗号多值（重复头被合并的典型形态）/ 溢出
        if (cl && !cl->empty()) {
            const std::string& c = *cl;
            bool bad = false;
            for (char ch : c) {
                if (ch == ',') { bad = true; break; }
                if (ch == ' ' || ch == '\t') continue;
                if (!std::isdigit((unsigned char)ch)) { bad = true; break; }
            }
            if (!bad && c.size() > 18) bad = true;
            if (bad) sb.add("IPS-1004", "Invalid or duplicated Content-Length", 50, *cl);
        }
        // 方法名：字母/连字符/下划线，长度 ≤16（异常字符常见于协议模糊测试）
        bool mok = !req.method.empty() && req.method.size() <= 16;
        for (char ch : req.method) {
            if (!std::isalpha((unsigned char)ch) && ch != '-' && ch != '_') {
                mok = false;
                break;
            }
        }
        if (!mok) sb.add("IPS-1005", "Malformed HTTP method", 40, req.method);
        // 版本：仅接受 1.0/1.1（h2/h3 在桥接层统一合成为 HTTP/1.1）
        if (!(req.version == "HTTP/1.1" || req.version == "HTTP/1.0"))
            sb.add("IPS-1006", "Malformed HTTP version", 30, req.version);
        // 请求路径控制字符（NUL / CR / LF / DEL）
        for (char ch : req.path) {
            unsigned char c = (unsigned char)ch;
            if (c < 0x20 || c == 0x7f) {
                sb.add("IPS-1007", "Control character in request path", 45, req.path);
                break;
            }
        }
        // 超长请求行：弱信号（部分正常搜索/回调 URL 也会较长）
        if ((int)(req.path.size() + req.query.size()) > p.maxTargetBytes)
            sb.add("IPS-1008", "Oversized request target", 15, req.path);
    }

    // ---- 模块 2：编码绕过 ----
    static void checkEncoding(const HttpRequest& req, Scoreboard& sb) {
        auto inspect = [&sb](const std::string& s) {
            static constexpr size_t kScan = 16384;
            size_t n = std::min(s.size(), kScan);
            for (size_t i = 0; i + 4 < n; ++i) {
                if (s[i] != '%') continue;
                // 双重 URL 编码：%25 + 两位十六进制（如 %252e → %2e）
                if (s[i + 1] == '2' && s[i + 2] == '5' && isHex(s[i + 3]) && isHex(s[i + 4])) {
                    sb.add("IPS-2001", "Double URL encoding detected", 30, s.substr(i, 3));
                    continue;
                }
                // 超长 UTF-8 编码（绕过目录/字符校验）：%c0%ae / %c0%af / %c1%9c 等
                static const char* kOverlong[] = {"%c0%ae", "%c0%af", "%c0%2e", "%c0%5c",
                                                  "%c1%9c", "%e0%80%ae", "%e0%80%af"};
                for (const char* pat : kOverlong) {
                    if (ieqAt(s, i, pat)) {
                        sb.add("IPS-2002", "Overlong UTF-8 encoding evasion", 60,
                               s.substr(i, 9));
                        break;
                    }
                }
                // IIS %u 编码绕过
                if ((s[i + 1] == 'u' || s[i + 1] == 'U') && isHex(s[i + 2]) &&
                    isHex(s[i + 3]) && i + 5 < n && isHex(s[i + 4]) && isHex(s[i + 5])) {
                    sb.add("IPS-2003", "IIS %u unicode encoding evasion", 50, s.substr(i, 6));
                    continue;
                }
                // 编码 NUL：截断校验的经典手法
                if (s[i + 1] == '0' && s[i + 2] == '0') {
                    sb.add("IPS-2004", "Encoded NUL byte in request", 40, s.substr(i, 3));
                }
            }
        };
        if (!req.path.empty()) inspect(req.path);
        if (!req.query.empty()) inspect(req.query);
        if (!req.body.empty()) inspect(req.body);
    }

    // ---- 模块 3：HTTP 参数污染（HPP） ----
    static bool keyEqCi(const std::string& a, const std::string& b) {
        size_t la = a.size(), lb = b.size();
        while (la > 0 && (a[la - 1] == '[' || a[la - 1] == ']')) --la;   // 忽略 id[] 数组后缀
        while (lb > 0 && (b[lb - 1] == '[' || b[lb - 1] == ']')) --lb;
        if (la != lb) return false;
        for (size_t i = 0; i < la; ++i)
            if ((char)std::tolower((unsigned char)a[i]) !=
                (char)std::tolower((unsigned char)b[i]))
                return false;
        return true;
    }
    static bool isSensitiveParam(const std::string& k) {
        size_t len = k.size();
        while (len > 0 && (k[len - 1] == '[' || k[len - 1] == ']')) --len;  // 忽略 id[] 后缀
        static const char* kNames[] = {"id",     "uid",      "user",   "username", "account",
                                       "redirect", "url",    "next",   "return",   "callback",
                                       "file",   "filename", "path",   "dir",      "cmd",
                                       "exec",   "token",    "action", "role",     "admin",
                                       "price",  "amount",   "quantity"};
        for (const char* n : kNames) {
            size_t nl = std::strlen(n);
            if (len != nl) continue;
            bool eq = true;
            for (size_t i = 0; i < nl; ++i)
                if ((char)std::tolower((unsigned char)k[i]) != n[i]) {
                    eq = false;
                    break;
                }
            if (eq) return true;
        }
        return false;
    }
    static void checkHpp(const HttpRequest& req, Scoreboard& sb) {
        const auto& qp = req.queryParams;
        if (qp.size() < 2) return;
        const size_t n = std::min<size_t>(qp.size(), 64);  // 上限保护：防 O(n²) 被放大
        for (size_t i = 0; i < n; ++i) {
            if (!isSensitiveParam(qp[i].first)) continue;
            int same = 0;
            bool differ = false;
            for (size_t j = 0; j < n; ++j) {
                if (j == i || !keyEqCi(qp[i].first, qp[j].first)) continue;
                ++same;
                if (qp[j].second != qp[i].second) differ = true;
            }
            if (same > 0 && differ)
                sb.add("IPS-3001", "HTTP parameter pollution (conflicting duplicate values)", 35,
                       qp[i].first + "=" + qp[i].second);
            else if (same >= 4)
                sb.add("IPS-3002", "Excessive duplicate parameters", 15, qp[i].first);
        }
    }

    // ---- 模块 4：无文件执行 / C2 / 反弹 shell / WebShell ----
    static void checkToolC2(const HttpRequest& req, Scoreboard& sb) {
        const AcAutomaton& lolbin = acLolbin();
        const AcAutomaton& shell = acReverseShell();
        const AcAutomaton& dl = acDownloadExec();
        const AcAutomaton& ws = acWebshell();
        forEachPayload(req, [&](const std::string& raw) {
            if (raw.size() < 8 || !looksTextual(raw)) return;  // 二进制上传体不做签名扫描
            scanText(raw, [&](const std::string& piece) {
                std::string norm = Decoder::normalize(piece);
                if (lolbin.containsAny(norm))
                    sb.add("IPS-4001", "Fileless execution / LOLBin usage", 65, norm);
                if (shell.containsAny(norm))
                    sb.add("IPS-4004", "Reverse shell payload", 70, norm);
                if (dl.containsAny(norm))
                    sb.add("IPS-4003", "Remote download and execution", 60, norm);
                if (ws.containsAny(norm)) {
                    sb.add("IPS-4002", "WebShell / encoded payload execution", 60, norm);
                } else if (containsI(norm, "eval") || containsI(norm, "exec") ||
                           containsI(norm, "system") || containsI(norm, "assert")) {
                    // 长 Base64 串 + 执行语义共现：编码后的载荷投放
                    if (hasLongBase64(norm))
                        sb.add("IPS-4002", "Encoded payload execution", 55, norm);
                }
            });
        });
    }
    // 文本判定：仅对可读载荷做签名扫描，避免对上传的二进制/压缩数据误判与浪费 CPU
    static bool looksTextual(const std::string& s) {
        size_t n = std::min<size_t>(s.size(), 4096);
        size_t bad = 0;
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)s[i];
            if (c == 0) return false;
            if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') ++bad;
        }
        return bad * 20 <= n;  // 控制字符占比 <5%
    }
    static bool hasLongBase64(const std::string& s) {
        size_t run = 0;
        for (char c : s) {
            if (std::isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=') {
                if (++run >= 120) return true;
            } else {
                run = 0;
            }
        }
        return false;
    }

    // ---- 模块 5：敏感端点探测 ----
    static void checkSensitivePath(const HttpRequest& req, Scoreboard& sb) {
        if (req.path.size() < 4) return;
        // 归一化：对抗 /.%67it/config 之类编码探测
        std::string norm = Decoder::normalize(req.path);
        if (acPathHigh().containsAny(norm))
            sb.add("IPS-5001", "Sensitive endpoint probing", 60, norm);
        else if (acPathMed().containsAny(norm))
            sb.add("IPS-5002", "Suspicious endpoint probing", 45, norm);
    }

    // ---- 签名集（进程内单次构建，所有检测器实例共享，热路径只读） ----
    static AcAutomaton makeAc(std::initializer_list<const char*> pats) {
        AcAutomaton a;
        for (const char* p : pats) a.addPattern(p);
        a.build();
        return a;
    }
    static const AcAutomaton& acLolbin() {
        static const AcAutomaton ac = makeAc({
            "powershell -enc", "powershell.exe", "-encodedcommand", "powershell -e ",
            "certutil -urlcache", "certutil -decode", "bitsadmin /transfer",
            "mshta http", "mshta vbscript", "mshta javascript", "regsvr32 /s /u /i",
            "rundll32.exe javascript", "wmic process call create", "schtasks /create",
            "vssadmin delete shadows", "bcdedit /set", "net user /add",
            "net localgroup administrators", "whoami /priv", "mimikatz", "procdump",
            "comsvcs.dll", "ntds.dit",
        });
        return ac;
    }
    static const AcAutomaton& acReverseShell() {
        static const AcAutomaton ac = makeAc({
            "/dev/tcp/", "bash -i", "sh -i", "nc -e", "ncat -e", "socat exec",
            "mkfifo /tmp/", "python -c 'import socket'", "perl -e 'use socket'",
            "php -r '$sock", "bash -c 'bash -i", "0>&1",
        });
        return ac;
    }
    static const AcAutomaton& acDownloadExec() {
        static const AcAutomaton ac = makeAc({
            "wget http", "curl -o /tmp", "curl -o /var/tmp", "chmod +x /tmp",
            "chmod 777 /tmp", "certutil -f -urlcache",
        });
        return ac;
    }
    static const AcAutomaton& acWebshell() {
        static const AcAutomaton ac = makeAc({
            "eval($_post", "eval($_request", "assert($_post", "system($_get",
            "passthru($_get", "shell_exec($_get", "base64_decode($_post",
            "eval(base64_decode", "assert(base64_decode", "gzinflate(base64_decode",
        });
        return ac;
    }
    static const AcAutomaton& acPathHigh() {
        static const AcAutomaton ac = makeAc({
            "/.git/", "/.svn/", "/.hg/", "/.env", "/wp-config.php", "/actuator/env",
            "/actuator/heapdump", "/actuator/jolokia", "/druid/index.html",
            "/web-inf/web.xml", "/meta-inf/application", "/proc/self/environ",
            "/proc/self/cmdline", "/etc/shadow", "/etc/passwd", "/.aws/credentials",
            "/.ssh/id_rsa", "/h2-console", "/jmx-console", "/manager/html",
            "/console/login",
        });
        return ac;
    }
    static const AcAutomaton& acPathMed() {
        static const AcAutomaton ac = makeAc({
            "/phpinfo.php", "/server-status", "/server-info", "/.ds_store",
            "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/config.php.bak",
        });
        return ac;
    }
};

}  // namespace novawaf
