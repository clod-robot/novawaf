// NovaWAF - 响应侧 DLP（出站敏感数据检测 / 脱敏）
// 挂载点：UpstreamForwarder 回写客户端之前（与 rewriteUpstreamErrorBody 同区域）。
// 设计：
//   * 检测算法为 O(n) 单遍扫描 + 确定性校验，杜绝正则回溯与误报：
//       - 手机号：1[3-9]xxxxxxxxx 号段判定
//       - 身份证：GB 11643 加权校验码验证（17 位数字 + 校验位，含 X）
//       - 银行卡：13-19 位数字 + Luhn 算法验证（排除随机数字串误报）
//       - 密钥族：固定前缀锚点搜索（AWS AKIA / OpenAI sk- / Google AIza /
//                 GitHub ghp_ / Slack xox / PEM 私钥块）
//   * 脱敏为「等长星号替换」（保留前几位 + 后几位），Content-Length 不变，
//     keep-alive 分帧与 JSON/HTML 结构均不受破坏，无需重建响应头。
//   * 跳过条件（安全默认）：chunked 分块、Content-Encoding 压缩、非文本
//     Content-Type、body 超阈值（NOVA_RESP_DLP_MAX_BYTES，默认 1MB）。
//   * 动作 NOVA_RESP_DLP_ACTION：mask（默认，脱敏放行）/ log（只上报不改写）/
//     block（整响应替换为全站统一人格 500 页）。命中统一发 AttackEvent 到事件总线
//     （category=DLP），SIEM 出口与态势落库自动获得该事件。
//   * 默认关闭：NOVA_RESP_DLP=1 启用。
#pragma once

#include "novawaf/core/event_bus.h"
#include "novawaf/core/event_sink.h"   // AttackEvent
#include "novawaf/core/waf_mode.h"
#include "novawaf/protect/block_page.h"
#include "novawaf/protect/mimic.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace novawaf {

class ResponseDlp {
public:
    static ResponseDlp& instance() {
        static ResponseDlp inst;
        return inst;
    }

    enum Action : int { ACT_OFF = 0, ACT_MASK = 1, ACT_LOG = 2, ACT_BLOCK = 3 };

    // 主入口：就地处理响应（head+body 完整字节流）。命中按配置动作处理并上报事件。
    void process(std::string& resp, const std::string& ip,
                 const std::string& host, const std::string& path) {
        if (act_ == ACT_OFF) return;
        size_t he = resp.find("\r\n\r\n");
        if (he == std::string::npos) return;
        if (resp.size() - (he + 4) == 0) return;
        if (resp.size() - (he + 4) > maxBytes_) return;
        if (!textualAndPlain(resp, he)) return;  // 跳过 chunked/压缩/二进制

        std::string body = resp.substr(he + 4);
        HitStat stat;
        scanBody(body, stat);  // 就地脱敏（等长替换）
        int total = stat.mobile + stat.idcard + stat.bankcard + stat.secret + stat.privkey;
        if (total == 0) return;

        // 事件上报（态势落库 + SIEM 出口共用总线）
        AttackEvent e;
        e.ts = (int64_t)std::time(nullptr);
        e.ip = ip;
        e.category = "DLP";
        e.ruleId = "DLP-RESP";
        e.matched = "mobile=" + std::to_string(stat.mobile) +
                    " idcard=" + std::to_string(stat.idcard) +
                    " bankcard=" + std::to_string(stat.bankcard) +
                    " secret=" + std::to_string(stat.secret) +
                    " privkey=" + std::to_string(stat.privkey);
        e.severity = (stat.secret || stat.privkey) ? "high" : "medium";
        e.uri = path;
        e.host = host;

        if (act_ == ACT_BLOCK) {
            // 整响应替换为全站统一人格 500 页（含自身 Content-Length，
            // 后续 setResponseConnection 只归一化 Connection 头）
            e.action = "block";
            e.traceId = BlockPage::genTraceId();
            EventBus<AttackEvent>::instance().publish(e);
            if (WafMode::isPublic(WafMode::instance().current()))
                resp = BlockPage::render("500", "Internal Server Error", "内容已被保护",
                                         "响应包含敏感数据，已被数据防泄漏策略阻断",
                                         e.traceId, true);
            else
                resp = BlockPage::renderMimic(500, "Internal Server Error", 2,
                                              MimicDefense::siteBanner().c_str(), e.traceId);
            return;
        }
        e.action = (act_ == ACT_LOG) ? "log" : "mask";
        EventBus<AttackEvent>::instance().publish(e);
        if (act_ == ACT_MASK)
            resp = resp.substr(0, he + 4) + body;  // 等长替换：Content-Length 无需重建
    }

    // 当前配置摘要（启动日志/测试探针用）
    int action() const { return act_; }
    size_t maxBytes() const { return maxBytes_; }

private:
    ResponseDlp() {
        const char* en = std::getenv("NOVA_RESP_DLP");
        if (!(en && *en == '1')) { act_ = ACT_OFF; return; }
        const char* a = std::getenv("NOVA_RESP_DLP_ACTION");
        std::string act = a ? a : "mask";
        if (act == "log") act_ = ACT_LOG;
        else if (act == "block") act_ = ACT_BLOCK;
        else act_ = ACT_MASK;
        const char* mb = std::getenv("NOVA_RESP_DLP_MAX_BYTES");
        if (mb && *mb) {
            long v = std::atol(mb);
            if (v > 0) maxBytes_ = (size_t)v;
        }
    }

    struct HitStat { int mobile = 0, idcard = 0, bankcard = 0, secret = 0, privkey = 0; };

    // 仅处理「文本且未压缩且非 chunked」的响应：
    //   - Transfer-Encoding: chunked → 跳过分块帧（改写会破坏帧边界）
    //   - Content-Encoding（gzip/br/deflate）→ 压缩体不可扫描/脱敏
    //   - Content-Type 显式为二进制族（image/ video/ audio/ octet-stream pdf zip font）→ 跳过；
    //     其余（text/*、json、xml、javascript、缺失）按文本处理
    static bool textualAndPlain(const std::string& resp, size_t he) {
        std::string head = resp.substr(0, he);
        for (auto& c : head) c = (char)tolower((unsigned char)c);
        if (head.find("transfer-encoding:") != std::string::npos &&
            head.find("chunked") != std::string::npos) return false;
        if (head.find("content-encoding:") != std::string::npos) return false;
        auto ct = head.find("content-type:");
        if (ct == std::string::npos) return true;  // 缺失按文本处理（宽松检出）
        static const char* kBinary[] = {"image/", "video/", "audio/", "octet-stream",
                                        "application/pdf", "application/zip", "font/",
                                        "wasm", "x-protobuf"};
        for (auto* b : kBinary)
            if (head.find(b, ct) != std::string::npos) return false;
        return true;
    }

    // ---- 确定性校验算法 ----
    // GB 11643 身份证校验码：加权和 mod 11 映射 "10X98765432"
    static bool idcardChecksum(const char* d) {  // d 指向 18 字节（17 数字 + 校验位）
        static const int kW[17] = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
        int sum = 0;
        for (int i = 0; i < 17; ++i) {
            if (!std::isdigit((unsigned char)d[i])) return false;
            sum += (d[i] - '0') * kW[i];
        }
        static const char kCode[11] = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};
        char c = d[17];
        if (c == 'x') c = 'X';
        return c == kCode[sum % 11];
    }
    // Luhn 算法（银行卡/支付卡号）
    static bool luhnOk(const char* d, size_t n) {
        int sum = 0;
        bool dbl = false;
        for (size_t i = n; i-- > 0;) {
            int v = d[i] - '0';
            if (dbl) { v *= 2; if (v > 9) v -= 9; }
            sum += v;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    static void mask(std::string& s, size_t from, size_t to) {  // [from,to) 等长星号
        for (size_t i = from; i < to && i < s.size(); ++i) s[i] = '*';
    }

    // O(n) 单遍主体扫描：数字串归类 + 密钥前缀锚点，命中即就地脱敏
    void scanBody(std::string& body, HitStat& stat) {
        const size_t n = body.size();
        // 1) 数字串单遍扫描（手机号/身份证/银行卡共用一趟）
        for (size_t i = 0; i < n;) {
            if (!std::isdigit((unsigned char)body[i])) { ++i; continue; }
            size_t j = i + 1;
            while (j < n && std::isdigit((unsigned char)body[j])) ++j;
            size_t len = j - i;
            // 相邻字母（如 12345abc）不视为独立标识号，保守跳过银行卡/手机判定；
            // 但身份证 17 位 + 'X' 校验位是合法形态，单独处理
            bool letterNext = j < n && std::isalpha((unsigned char)body[j]);
            if (len == 17 && letterNext && (body[j] == 'X' || body[j] == 'x')) {
                if (idcardChecksum(body.data() + i)) {
                    ++stat.idcard;
                    if (act_ == ACT_MASK) mask(body, i + 6, i + 14);  // 留前6后4
                }
                i = j + 1;
                continue;
            }
            if (!letterNext) {
                if (len == 18 && idcardChecksum(body.data() + i)) {
                    ++stat.idcard;
                    if (act_ == ACT_MASK) mask(body, i + 6, i + 14);
                } else if (len == 11 && body[i] == '1' && body[i + 1] >= '3' && body[i + 1] <= '9') {
                    ++stat.mobile;
                    if (act_ == ACT_MASK) mask(body, i + 3, i + 7);  // 138****5678
                } else if (len >= 13 && len <= 19 && body[i] >= '3' && body[i] <= '6' &&
                           luhnOk(body.data() + i, len)) {
                    // BIN 前缀约束（Visa=4/MC=5/Amex=3/UnionPay=62 等真实卡 BIN 均落于 3-6），
                    // 排除时间戳/追踪号等长数字串的 Luhn 偶然通过（实测误报来源）
                    ++stat.bankcard;
                    if (act_ == ACT_MASK) mask(body, i + 4, j - 4);  // 留前4后4
                }
            }
            i = j;
        }
        // 2) 密钥前缀锚点（memchr 级 find，逐前缀扫描）
        scanSecret(body, "AKIA", 16, stat, true);   // AWS Access Key ID：AKIA+16 大写字母数字
        scanSecret(body, "AIza", 35, stat, false);  // Google API Key
        scanSecret(body, "ghp_", 36, stat, false);  // GitHub PAT
        scanSecret(body, "xox", 0, stat, false);    // Slack token：xox[baprs]-...
        scanSecret(body, "sk-", 20, stat, false);   // OpenAI API Key（宽松尾部，>=20 字母数字）
        scanPrivKey(body, stat);
    }

    // 前缀 + 定长/变长尾部的密钥族；命中保留前缀+3 尾部，其余星号
    void scanSecret(std::string& body, const char* prefix, int fixedTail,
                    HitStat& stat, bool upperOnly) {
        const size_t plen = std::strlen(prefix);
        size_t pos = 0;
        while ((pos = body.find(prefix, pos)) != std::string::npos) {
            size_t t0 = pos + plen;
            size_t tend = t0;
            if (fixedTail > 0) {
                size_t want = t0 + (size_t)fixedTail;
                if (want > body.size()) break;
                tend = t0;
                while (tend < want && std::isalnum((unsigned char)body[tend]) &&
                       (!upperOnly || !std::islower((unsigned char)body[tend]))) ++tend;
                if (tend != want) { pos = t0; continue; }  // 尾部不完整，非密钥
            } else {
                // 变长：吞掉字母数字与 '-_'，至少 16 字符才认定
                while (tend < body.size() &&
                       (std::isalnum((unsigned char)body[tend]) || body[tend] == '-' ||
                        body[tend] == '_')) ++tend;
                if (tend - t0 < 16) { pos = t0; continue; }
            }
            ++stat.secret;
            if (act_ == ACT_MASK) mask(body, t0 + 3, tend);
            pos = tend;
        }
    }

    // PEM 私钥块：BEGIN/END 行保留，中间 base64 字符等长星号（保留换行结构）
    void scanPrivKey(std::string& body, HitStat& stat) {
        size_t pos = 0;
        while ((pos = body.find("-----BEGIN ", pos)) != std::string::npos) {
            size_t beginEol = body.find("-----", pos + 11);
            if (beginEol == std::string::npos) break;
            beginEol = body.find('\n', beginEol);
            if (beginEol == std::string::npos) break;
            size_t endMark = body.find("-----END ", beginEol);
            if (endMark == std::string::npos) break;
            // 仅当 BEGIN 行含 PRIVATE KEY 才认定（排除证书块误伤）
            if (body.find("PRIVATE KEY", pos) == std::string::npos ||
                body.find("PRIVATE KEY", pos) > beginEol) { pos = endMark + 9; continue; }
            ++stat.privkey;
            if (act_ == ACT_MASK)
                for (size_t i = beginEol + 1; i < endMark; ++i) {
                    char c = body[i];
                    if (std::isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=')
                        body[i] = '*';
                }
            pos = endMark + 9;
        }
    }

    int act_ = ACT_OFF;
    size_t maxBytes_ = 1 << 20;  // 默认 1MB
};

}  // namespace novawaf
