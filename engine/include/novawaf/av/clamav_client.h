// NovaWAF - ClamAV(clamd) 引擎侧接入
// 无第三方依赖：原生 TCP socket 走 clamd INSTREAM 协议对上传体做签名扫描。
// 命中 -> BLOCK 并记录签名名；clamd 不可达/超时 -> 默认 fail-open（可配 fail-close）。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace novawaf {

// ---- clamd INSTREAM 客户端 ----
class ClamavClient {
public:
    enum class State { Clean, Infected, Error };
    struct Result { State state; std::string signature; };

    ClamavClient(std::string host, int port, int timeoutMs)
        : host_(std::move(host)), port_(port), timeoutMs_(timeoutMs) {}

    Result scan(const std::string& data) const {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return {State::Error, "socket() failed"};
        // 超时（收发）
        timeval tv{timeoutMs_ / 1000, (timeoutMs_ % 1000) * 1000};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port_);
        if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
            ::close(fd);
            return {State::Error, "bad host: " + host_};
        }
        if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
            ::close(fd);
            return {State::Error, std::string("connect failed: ") + std::strerror(errno)};
        }

        // 命令：zINSTREAM\0 （z = 命令与回复均以 \0 定界）
        const char cmd[] = "zINSTREAM";
        if (!sendAll(fd, cmd, sizeof(cmd))) {  // sizeof 含末尾 \0
            ::close(fd); return {State::Error, "send cmd failed"};
        }
        // 分块发送：每块前缀 4 字节大端长度，末尾 0 长度块结束
        const size_t CHUNK = 65536;
        size_t off = 0;
        bool ok = true;
        while (ok && off < data.size()) {
            size_t n = data.size() - off; if (n > CHUNK) n = CHUNK;
            uint32_t len = htonl((uint32_t)n);
            ok = sendAll(fd, (const char*)&len, 4) && sendAll(fd, data.data() + off, n);
            off += n;
        }
        uint32_t endian0 = 0;
        ok = ok && sendAll(fd, (const char*)&endian0, 4);
        ::shutdown(fd, SHUT_WR);
        if (!ok) { ::close(fd); return {State::Error, "send stream failed"}; }

        // 读回复直到对端关闭
        std::string resp;
        char buf[4096];
        while (true) {
            ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
            if (r > 0) resp.append(buf, (size_t)r);
            else if (r == 0) break;
            else { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
        }
        ::close(fd);
        // 回复形如 "stream: OK\0" 或 "stream: Eicar-Test-Signature FOUND\0"
        size_t nul = resp.find('\0');
        if (nul != std::string::npos) resp.resize(nul);
        if (resp.rfind("stream: ", 0) == 0) {
            std::string body = resp.substr(8);
            if (body.size() >= 3 && body.compare(body.size() - 3, 3, "OK ") == 0) { body.pop_back(); }
            if (body == "OK") return {State::Clean, ""};
            size_t f = body.rfind(" FOUND");
            if (f != std::string::npos) return {State::Infected, body.substr(0, f)};
            if (!body.empty()) return {State::Infected, body};
        }
        return {State::Error, "unexpected resp: " + resp};
    }

private:
    static bool sendAll(int fd, const char* p, size_t n) {
        while (n) {
            ssize_t w = ::send(fd, p, n, 0);
            if (w <= 0) { if (errno == EINTR) continue; return false; }
            p += w; n -= (size_t)w;
        }
        return true;
    }
    std::string host_;
    int port_;
    int timeoutMs_;
};

// ---- 检测器：仅对上传请求做 clamd 深度扫描 ----
class ClamavDetector : public IDetector {
public:
    ClamavDetector() {
        disabled_ = std::getenv("NOVA_AV_DISABLE") != nullptr;
        const char* h = std::getenv("NOVA_CLAMD_HOST"); host_ = h ? h : "127.0.0.1";
        const char* p = std::getenv("NOVA_CLAMD_PORT"); port_ = p ? std::atoi(p) : 3310;
        const char* t = std::getenv("NOVA_CLAMD_TIMEOUT_MS"); timeoutMs_ = t ? std::atoi(t) : 5000;
        const char* f = std::getenv("NOVA_AV_FAIL"); failClose_ = f && std::string(f) == "close";
    }
    const char* name() const override { return "ClamAV"; }
    std::unique_ptr<IDetector> clone() const override {
        auto c = std::make_unique<ClamavDetector>();
        c->disabled_ = disabled_; c->host_ = host_; c->port_ = port_;
        c->timeoutMs_ = timeoutMs_; c->failClose_ = failClose_;
        return c;
    }
    DetectionResult detect(const HttpRequest& req) override {
        if (disabled_) return {};
        std::string ct = getHeaderCi(req, "content-type");
        bool isUpload = ct.find("multipart") != std::string::npos ||
                        ct.find("octet-stream") != std::string::npos ||
                        req.body.find("filename=") != std::string::npos;
        if (!isUpload || req.body.empty()) return {};

        // 提取待扫描内容：multipart 需拆出每个 part 的真实文件体（clamd 对整段原始
        // multipart 体检测率差，必须喂纯净文件内容）；octet-stream 则取整个 body。
        auto payloads = extractUploadPayloads(req, ct);
        if (payloads.empty()) return {};
        ClamavClient client(host_, port_, timeoutMs_);
        for (auto& p : payloads) {
            if (p.empty()) continue;
            ClamavClient::Result r = client.scan(p);
            if (r.state == ClamavClient::State::Infected)
                return {Action::BLOCK, "AV-001", "Virus", "ClamAV detected: " + r.signature, r.signature};
            if (r.state == ClamavClient::State::Error) {
                if (failClose_)
                    return {Action::BLOCK, "AV-002", "Virus", "clamd unavailable (fail-close)", "error"};
                // fail-open：clamd 不可用时放行
            }
        }
        return {};  // clean / fail-open
    }
private:
    // 从 multipart 体中拆出各 part 的文件内容；非 multipart 退回整个 body
    static std::vector<std::string> extractUploadPayloads(const HttpRequest& req, const std::string& ct) {
        std::vector<std::string> out;
        size_t bp = ct.find("boundary=");
        if (ct.find("multipart") != std::string::npos && bp != std::string::npos) {
            std::string boundary = ct.substr(bp + 9);
            size_t sc = boundary.find(';'); if (sc != std::string::npos) boundary.resize(sc);
            while (!boundary.empty() && (boundary.front()==' '||boundary.front()=='"')) boundary.erase(boundary.begin());
            while (!boundary.empty() && (boundary.back()==' '||boundary.back()=='"')) boundary.pop_back();
            if (boundary.empty()) { out.push_back(req.body); return out; }
            std::string delim = "--" + boundary;
            size_t pos = 0;
            while (true) {
                size_t s = req.body.find(delim, pos);
                if (s == std::string::npos) break;
                size_t start = s + delim.size();
                if (start + 2 <= req.body.size() && req.body.compare(start, 2, "--") == 0) break; // 结束标记
                if (start + 2 <= req.body.size() && req.body.compare(start, 2, "\r\n") == 0) start += 2;
                size_t e = req.body.find("\r\n" + delim, start);
                if (e == std::string::npos) break;
                std::string part = req.body.substr(start, e - start);
                size_t hb = part.find("\r\n\r\n");
                if (hb != std::string::npos) out.push_back(part.substr(hb + 4));
                pos = e + 2;
            }
            return out;
        }
        out.push_back(req.body);
        return out;
    }
    static std::string getHeaderCi(const HttpRequest& req, const std::string& key) {
        for (auto& kv : req.headers)
            if (kv.first.size() == key.size()) {
                bool eq = true;
                for (size_t i = 0; i < key.size(); ++i)
                    if (std::tolower((unsigned char)kv.first[i]) != std::tolower((unsigned char)key[i])) { eq = false; break; }
                if (eq) return kv.second;
            }
        return {};
    }
    bool disabled_ = false;
    std::string host_ = "127.0.0.1";
    int port_ = 3310;
    int timeoutMs_ = 5000;
    bool failClose_ = false;
};

}  // namespace novawaf
