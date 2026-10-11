// NovaWAF - 生产用 LLM HTTP 传输层（Linux POSIX socket，带连接/读写超时）
// 仅 Linux 编译；向 LlmClient 注入即可。极简 HTTP/1.1 POST，零第三方依赖。
#pragma once

#include "novawaf/ai/llm_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <optional>
#include <string>

namespace novawaf {

inline LlmTransport makeHttpTransport(const LlmConfig& cfg) {
    return [cfg](const std::string& body) -> std::optional<std::string> {
        // 解析 endpoint: http://host:port/path
        std::string url = cfg.endpoint;
        const std::string prefix = "http://";
        if (url.rfind(prefix, 0) != 0) return std::nullopt;  // 暂仅支持 http
        std::string rest = url.substr(prefix.size());
        auto slash = rest.find('/');
        std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
        std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);
        auto colon = hostport.find(':');
        std::string host = (colon == std::string::npos) ? hostport : hostport.substr(0, colon);
        int port = (colon == std::string::npos) ? 80 : std::atoi(hostport.substr(colon + 1).c_str());

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
            return std::nullopt;

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { freeaddrinfo(res); return std::nullopt; }

        // 超时：秒+微秒
        timeval tv{};
        tv.tv_sec = cfg.timeoutMs / 1000;
        tv.tv_usec = (cfg.timeoutMs % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        bool ok = false;
        if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
            std::string req =
                "POST " + path + " HTTP/1.1\r\n"
                "Host: " + host + "\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n";
            if (!cfg.apiKey.empty())
                req += "Authorization: Bearer " + cfg.apiKey + "\r\n";
            req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

            size_t sent = 0;
            while (sent < req.size()) {
                ssize_t n = send(fd, req.data() + sent, req.size() - sent, 0);
                if (n <= 0) break;
                sent += n;
            }
            if (sent == req.size()) {
                std::string resp;
                char buf[4096];
                while (true) {
                    ssize_t n = recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    resp.append(buf, n);
                }
                // 截取 body（首个空行后）
                auto sep = resp.find("\r\n\r\n");
                if (sep != std::string::npos) {
                    ok = true;
                    return resp.substr(sep + 4);
                }
            }
        }
        close(fd);
        freeaddrinfo(res);
        return ok ? std::optional<std::string>{""} : std::nullopt;
    };
}

}  // namespace novawaf
