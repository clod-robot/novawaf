// NovaWAF - 转发头清洗（代理族头反欺骗）
// 背景：客户端可自报 X-Forwarded-For / X-Real-IP / X-Client-IP / Forwarded(RFC7239)
// 等代理头。前门 nginx 已覆盖 XFF/X-Real-IP 为真实来源，但 X-Client-IP、Forwarded、
// X-Forwarded-Host 等其余家族成员会穿透整条链路到业务应用；若应用/框架采信其中
// 任意一个（常见 IP 白名单、风控、审计日志），即被欺骗。
// 策略（单一职责，仅操作转发字节，不影响检测模型 req.headers）：
//   - 可信代理来源：保留前门权威的 x-forwarded-for / x-real-ip / x-forwarded-proto，
//     剥离其余全部代理族头（含 client 经前门穿透注入的 X-Original-* 变体）。
//   - 非可信直连：剥离全部代理族头，以真实对端重建 X-Forwarded-For / X-Real-IP。
#pragma once

#include <cctype>
#include <string>

namespace novawaf {

class RequestSanitizer {
public:
    // raw: 完整请求字节（请求行+头+body），就地改写；peerIp: 直连对端 IP；
    // trusted: 对端是否为可信代理（NOVA_TRUSTED_PROXIES）
    static void sanitizeForwardHeaders(std::string& raw, const std::string& peerIp, bool trusted) {
        size_t he = raw.find("\r\n\r\n");
        if (he == std::string::npos) return;
        std::string out;
        out.reserve(raw.size() + 96);
        size_t pos = 0;
        bool firstLine = true;
        while (pos < he) {
            size_t nl = raw.find("\r\n", pos);
            if (nl == std::string::npos || nl > he) nl = he;
            const std::string& line = raw.substr(pos, nl - pos);
            pos = nl + 2;
            if (firstLine) { out += line; out += "\r\n"; firstLine = false; continue; }
            if (line.empty()) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) { out += line; out += "\r\n"; continue; }
            std::string name = line.substr(0, colon);
            for (auto& c : name) c = (char)tolower((unsigned char)c);
            if (spoofable(name, trusted)) continue;  // 剥离
            out += line; out += "\r\n";
        }
        if (!trusted) {
            // 直连客户端：重建权威链
            out += "X-Forwarded-For: " + peerIp + "\r\n";
            out += "X-Real-IP: " + peerIp + "\r\n";
        }
        out += "\r\n";
        out.append(raw, he + 4, std::string::npos);
        raw = std::move(out);
    }

private:
    // 代理族头判定。可信来源保留前门三件套（ff/real-ip/proto），其余全剥；
    // 非可信来源整族全剥（含三件套，由调用方重建）。
    static bool spoofable(const std::string& n, bool trusted) {
        if (n == "x-forwarded-for" || n == "x-real-ip" || n == "x-forwarded-proto")
            return !trusted;
        return n == "x-client-ip" || n == "client-ip" || n == "x-http-client-ip" ||
               n == "forwarded" || n == "x-original-forwarded-for" ||
               n == "x-original-real-ip" || n == "x-forwarded-host" ||
               n == "x-forwarded-server" || n == "x-forwarded-port";
    }
};

}  // namespace novawaf
