#pragma once

// TLS 上下文管理：TLS-TCP（ALPN: h2 / http/1.1）与 QUIC（ALPN: h3）两套 SSL_CTX。
// 证书加载失败时降级为仅告警，h1 明文管线不受影响。

#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace novawaf {

class TlsContext {
public:
    static TlsContext& instance() {
        static TlsContext ctx;
        return ctx;
    }

    // TCP TLS（h2 / http/1.1）
    bool initTcp(const std::string& certFile, const std::string& keyFile) {
        tcpCtx_ = buildCtx(certFile, keyFile, &TlsContext::alpnSelectTcp);
        return tcpCtx_ != nullptr;
    }

    // QUIC TLS（h3）。ngtcp2 crypto ossl 后端初始化失败不影响 TCP TLS。
    bool initQuic(const std::string& certFile, const std::string& keyFile) {
        if (ngtcp2_crypto_ossl_init() != 0) {
            std::fprintf(stderr, "[tls] ngtcp2_crypto_ossl_init failed\n");
            return false;
        }
        quicCtx_ = buildCtx(certFile, keyFile, &TlsContext::alpnSelectQuic);
        if (quicCtx_) {
            SSL_CTX_set_options(quicCtx_, SSL_OP_NO_TICKET);
            SSL_CTX_set_max_early_data(quicCtx_, 0);  // 不做 0-RTT
        }
        return quicCtx_ != nullptr;
    }

    SSL_CTX* tcp() const { return tcpCtx_; }
    SSL_CTX* quic() const { return quicCtx_; }

private:
    TlsContext() = default;
    ~TlsContext() {
        if (tcpCtx_) SSL_CTX_free(tcpCtx_);
        if (quicCtx_) SSL_CTX_free(quicCtx_);
    }
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    using AlpnCb = int (*)(SSL*, const unsigned char**, unsigned char*, const unsigned char*,
                           unsigned int, void*);

    static SSL_CTX* buildCtx(const std::string& certFile, const std::string& keyFile, AlpnCb alpnCb) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            logErr("SSL_CTX_new");
            return nullptr;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
        if (SSL_CTX_use_certificate_chain_file(ctx, certFile.c_str()) != 1) {
            logErr("load cert " + certFile);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            logErr("load key " + keyFile);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        SSL_CTX_set_alpn_select_cb(ctx, alpnCb, nullptr);
        return ctx;
    }

    static bool pickProto(const unsigned char* in, unsigned int inlen, const char* proto,
                          unsigned int protolen, const unsigned char** out, unsigned char* outlen) {
        unsigned int i = 0;
        while (i + 1 <= inlen) {
            unsigned int l = in[i];
            if (i + 1 + l > inlen) break;
            if (l == protolen && std::memcmp(in + i + 1, proto, protolen) == 0) {
                *out = in + i + 1;
                *outlen = static_cast<unsigned char>(l);
                return true;
            }
            i += 1 + l;
        }
        return false;
    }

    static int alpnSelectTcp(SSL*, const unsigned char** out, unsigned char* outlen,
                             const unsigned char* in, unsigned int inlen, void*) {
        if (pickProto(in, inlen, "h2", 2, out, outlen)) return SSL_TLSEXT_ERR_OK;
        static const unsigned char kH1[] = "http/1.1";
        if (!pickProto(in, inlen, "http/1.1", 8, out, outlen)) {
            *out = kH1;
            *outlen = 8;  // 未协商按 h1 处理，不打断握手
        }
        return SSL_TLSEXT_ERR_OK;
    }

    static int alpnSelectQuic(SSL*, const unsigned char** out, unsigned char* outlen,
                              const unsigned char* in, unsigned int inlen, void*) {
        if (pickProto(in, inlen, "h3", 2, out, outlen)) return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_ALERT_FATAL;  // QUIC 只接受 h3
    }

    static void logErr(const std::string& what) {
        char buf[256];
        unsigned long e = ERR_get_error();
        ERR_error_string_n(e, buf, sizeof(buf));
        std::fprintf(stderr, "[tls] %s failed: %s\n", what.c_str(), buf);
    }

    SSL_CTX* tcpCtx_ = nullptr;
    SSL_CTX* quicCtx_ = nullptr;
};

}  // namespace novawaf
