#pragma once

// HTTP/3 (QUIC) 服务端：ngtcp2(传输) + nghttp3(HTTP 层)。
// 每 reactor 一个实例，绑定本 reactor 的 UDP SO_REUSEPORT 套接字，
// 请求聚合为 BridgeRequest 经 H1Bridge 入 h1 检测管线，响应经 nghttp3 回帧。
// 简化策略：不做连接迁移 / 0-RTT / Retry / GSO。全部方法仅限所属 reactor 线程调用。

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bridge.h"

namespace novawaf {

class H3Server {
public:
    H3Server(int udpFd, SSL_CTX* quicCtx, H1Bridge& bridge, size_t maxBody)
        : udpFd_(udpFd), sslCtx_(quicCtx), bridge_(bridge), maxBody_(maxBody) {
        RAND_bytes(staticSecret_, sizeof(staticSecret_));
        sockaddr_storage la{};
        socklen_t ll = sizeof(la);
        getsockname(udpFd_, reinterpret_cast<sockaddr*>(&la), &ll);
        localAddr_ = la;
        localLen_ = ll;
    }

    ~H3Server() { closeAll(); }

    size_t connCount() const { return conns_.size(); }

    // reactor：UDP 可读（ET，循环读空）
    void onReadable() {
        for (;;) {
            sockaddr_storage from{};
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(udpFd_, rxBuf_, sizeof(rxBuf_), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fromlen);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;  // EAGAIN
            }
            if (n == 0) continue;
            handleDatagram(rxBuf_, static_cast<size_t>(n), from, fromlen);
        }
    }

    // reactor：每次 epoll 返回后调用（到期处理 + 刷写 + 回收）
    void sweep() {
        ngtcp2_tstamp now = nowNs();
        for (auto& up : conns_) {
            Conn& c = *up;
            if (c.dead) continue;
            if (ngtcp2_conn_in_draining_period(c.conn)) {
                c.dead = true;
                continue;
            }
            ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c.conn);
            if (expiry != UINT64_MAX && expiry <= now) {
                int rv = ngtcp2_conn_handle_expiry(c.conn, now);
                if (rv != 0) {  // IDLE_CLOSE / HANDSHAKE_TIMEOUT 等
                    c.dead = true;
                    continue;
                }
            }
            if (writePending(c) < 0) {
                c.dead = true;
                continue;
            }
            if (ngtcp2_conn_in_closing_period(c.conn) || ngtcp2_conn_in_draining_period(c.conn)) {
                c.dead = true;
            }
        }
        reapDead();
    }

    // 距最近到期时间的毫秒数（epoll 超时收敛用）；无连接返回 -1
    int msToNextExpiry() {
        if (conns_.empty()) return -1;
        ngtcp2_tstamp now = nowNs();
        ngtcp2_tstamp best = UINT64_MAX;
        for (auto& up : conns_) {
            if (up->dead) continue;
            ngtcp2_tstamp e = ngtcp2_conn_get_expiry(up->conn);
            if (e < best) best = e;
        }
        if (best == UINT64_MAX) return -1;
        if (best <= now) return 0;
        uint64_t ms = (best - now) / 1000000;
        return static_cast<int>(ms > 200 ? 200 : ms);
    }

    void closeAll() {
        cidMap_.clear();
        conns_.clear();
    }

private:
    static constexpr size_t kScidLen = 18;  // ≤ NGTCP2_MAX_CIDLEN

    struct Stream {
        std::string method, path, authority;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        bool bodyTooLarge = false;
        std::string respBody;
        size_t respOff = 0;
    };

    struct Conn {
        H3Server* srv = nullptr;
        uint64_t id = 0;  // 单调连接 id：桥异步回调以此重查，避免 sweep reap 后悬空引用
        ngtcp2_conn* conn = nullptr;
        SSL* ssl = nullptr;
        ngtcp2_crypto_ossl_ctx* osslCtx = nullptr;
        ngtcp2_crypto_conn_ref connRef{};
        nghttp3_conn* http3 = nullptr;
        sockaddr_storage peer{};
        socklen_t peerLen = 0;
        std::string initialDcid;
        std::vector<std::string> scids;
        std::unordered_map<int64_t, Stream> streams;
        bool http3Ready = false;
        bool dead = false;

        ~Conn() {
            if (http3) nghttp3_conn_del(http3);
            if (conn) ngtcp2_conn_del(conn);
            if (osslCtx) ngtcp2_crypto_ossl_ctx_del(osslCtx);
            if (ssl) SSL_free(ssl);
        }
    };

    static ngtcp2_tstamp nowNs() {
        return static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    }

    static ngtcp2_conn* getConnCb(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<Conn*>(ref->user_data)->conn;
    }

    // ---------------- datagram 入口 ----------------

    void handleDatagram(const uint8_t* data, size_t len, const sockaddr_storage& from,
                        socklen_t fromlen) {
        ngtcp2_version_cid vc{};
        if (ngtcp2_pkt_decode_version_cid(&vc, data, len, kScidLen) != 0) return;

        std::string dcidKey(reinterpret_cast<const char*>(vc.dcid), vc.dcidlen);
        auto it = cidMap_.find(dcidKey);
        Conn* c = nullptr;
        if (it == cidMap_.end()) {
            if (!ngtcp2_is_supported_version(vc.version)) return;  // v1：不发 VN，直接丢
            c = createConn(vc, from, fromlen);
            if (!c) return;
        } else {
            c = it->second;
            if (c->dead) return;
        }

        ngtcp2_path path{};
        path.local = {reinterpret_cast<ngtcp2_sockaddr*>(&localAddr_), localLen_};
        path.remote = {reinterpret_cast<ngtcp2_sockaddr*>(const_cast<sockaddr_storage*>(&from)),
                       fromlen};
        ngtcp2_pkt_info pi{};
        int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, data, len, nowNs());
        if (rv == NGTCP2_ERR_DRAINING || ngtcp2_conn_in_draining_period(c->conn)) {
            c->dead = true;
            reapDead();
            return;
        }
        if (rv < 0 && rv != NGTCP2_ERR_CLOSING) {
            c->dead = true;  // crypto 错误等：静默回收（客户端按超时重试）
            reapDead();
            return;
        }
        if (writePending(*c) < 0 || ngtcp2_conn_in_closing_period(c->conn)) {
            c->dead = true;
            reapDead();
        }
    }

    Conn* createConn(const ngtcp2_version_cid& vc, const sockaddr_storage& from, socklen_t fromlen) {
        if (conns_.size() >= maxConns_) return nullptr;
        auto holder = std::make_unique<Conn>();
        Conn* c = holder.get();
        c->srv = this;
        c->id = nextConnId_++;
        c->peer = from;
        c->peerLen = fromlen;
        c->initialDcid.assign(reinterpret_cast<const char*>(vc.dcid), vc.dcidlen);

        c->ssl = SSL_new(sslCtx_);
        if (!c->ssl) return nullptr;
        if (ngtcp2_crypto_ossl_ctx_new(&c->osslCtx, c->ssl) != 0) return nullptr;
        c->connRef.get_conn = &H3Server::getConnCb;
        c->connRef.user_data = c;
        SSL_set_app_data(c->ssl, &c->connRef);
        ngtcp2_crypto_ossl_configure_server_session(c->ssl);
        SSL_set_accept_state(c->ssl);

        uint8_t scidBytes[kScidLen];
        RAND_bytes(scidBytes, kScidLen);
        ngtcp2_cid scid;
        ngtcp2_cid_init(&scid, scidBytes, kScidLen);
        c->scids.emplace_back(reinterpret_cast<char*>(scidBytes), kScidLen);

        // ngtcp2_conn_server_new 的 dcid 语义 = 客户端 Initial 包的 SCID
        // （服务器视角发往对端的 destination cid）；vc.dcid 是客户端随机选的
        // 初始 DCID，只能用于 original_dcid 传输参数，二者不可混用。
        ngtcp2_cid dcid;
        ngtcp2_cid_init(&dcid, vc.scid, vc.scidlen);
        ngtcp2_cid odcid;
        ngtcp2_cid_init(&odcid, vc.dcid, vc.dcidlen);

        ngtcp2_callbacks cb{};
        cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        cb.handshake_completed = &H3Server::onHandshakeCompleted;
        cb.recv_tx_key = &H3Server::onRecvTxKey;
        cb.recv_stream_data = &H3Server::onRecvStreamData;
        cb.acked_stream_data_offset = &H3Server::onAckedStreamData;
        cb.stream_open = &H3Server::onStreamOpen;
        cb.stream_close = &H3Server::onStreamClose;
        cb.stream_reset = &H3Server::onStreamReset;
        cb.stream_stop_sending = &H3Server::onStreamStopSending;
        cb.extend_max_stream_data = &H3Server::onExtendMaxStreamData;
        cb.rand = &H3Server::onRand;
        cb.get_new_connection_id = &H3Server::onGetNewCid;
        cb.remove_connection_id = &H3Server::onRemoveCid;
        cb.encrypt = ngtcp2_crypto_encrypt_cb;
        cb.decrypt = ngtcp2_crypto_decrypt_cb;
        cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
        cb.update_key = ngtcp2_crypto_update_key_cb;
        cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = nowNs();
        settings.log_printf = nullptr;

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        // ngtcp2 >=1.15 强制：server 必须提供 original_dcid（客户端 Initial 包的 DCID，
        // 本实现不做 Retry，直接用 vc.dcid）；缺失触发 conn_new 断言 abort
        params.original_dcid = odcid;
        params.original_dcid_present = 1;
        params.initial_max_stream_data_bidi_local = 1u << 20;
        params.initial_max_stream_data_bidi_remote = 1u << 20;
        params.initial_max_stream_data_uni = 1u << 16;
        params.initial_max_data = 8u << 20;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 3;
        params.max_idle_timeout = 30 * NGTCP2_SECONDS;
        params.active_connection_id_limit = 8;

        ngtcp2_path path{};
        path.local = {reinterpret_cast<ngtcp2_sockaddr*>(&localAddr_), localLen_};
        path.remote = {reinterpret_cast<ngtcp2_sockaddr*>(const_cast<sockaddr_storage*>(&from)),
                       fromlen};

        if (ngtcp2_conn_server_new(&c->conn, &dcid, &scid, &path, vc.version, &cb, &settings,
                                   &params, nullptr, c) != 0) {
            return nullptr;
        }
        ngtcp2_conn_set_tls_native_handle(c->conn, c->osslCtx);

        conns_.push_back(std::move(holder));
        cidMap_[c->scids[0]] = c;
        cidMap_[c->initialDcid] = c;
        return c;
    }

    // 桥异步回调用：按单调 id 重查连接（连接数 <=256，线性扫描足够）
    Conn* findConnById(uint64_t id) {
        for (auto& up : conns_)
            if (up->id == id) return up.get();
        return nullptr;
    }

    // ---------------- ngtcp2 回调 ----------------

    static int onHandshakeCompleted(ngtcp2_conn* conn, void* user_data) {
        auto* c = static_cast<Conn*>(user_data);
        setupHttp3(*c);
        return 0;
    }

    static int onRecvTxKey(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data) {
        auto* c = static_cast<Conn*>(user_data);
        if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) setupHttp3(*c);
        return 0;
    }

    static void setupHttp3(Conn& c) {
        if (c.http3Ready) return;
        c.http3Ready = true;

        nghttp3_callbacks hcb{};
        hcb.acked_stream_data = &H3Server::onH3AckedStreamData;
        hcb.stream_close = &H3Server::onH3StreamClose;
        hcb.recv_data = &H3Server::onH3RecvData;
        hcb.deferred_consume = &H3Server::onH3DeferredConsume;
        hcb.begin_headers = &H3Server::onH3BeginHeaders;
        hcb.recv_header = &H3Server::onH3RecvHeader;
        hcb.end_headers = &H3Server::onH3EndHeaders;
        hcb.end_stream = &H3Server::onH3EndStream;
        hcb.stop_sending = &H3Server::onH3StopSending;
        hcb.reset_stream = &H3Server::onH3ResetStream;

        nghttp3_settings hst;
        nghttp3_settings_default(&hst);
        hst.max_field_section_size = 64 * 1024;

        if (nghttp3_conn_server_new(&c.http3, &hcb, &hst, nullptr, &c) != 0) {
            c.dead = true;
            return;
        }
        nghttp3_conn_set_max_client_streams_bidi(c.http3, 100);

        int64_t stCtrl = -1, stQEnc = -1, stQDec = -1;
        if (ngtcp2_conn_open_uni_stream(c.conn, &stCtrl, nullptr) != 0 ||
            ngtcp2_conn_open_uni_stream(c.conn, &stQEnc, nullptr) != 0 ||
            ngtcp2_conn_open_uni_stream(c.conn, &stQDec, nullptr) != 0) {
            c.dead = true;
            return;
        }
        nghttp3_conn_bind_control_stream(c.http3, stCtrl);
        nghttp3_conn_bind_qpack_streams(c.http3, stQEnc, stQDec);
    }

    static int onRecvStreamData(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id, uint64_t,
                                const uint8_t* data, size_t datalen, void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        if (c->dead || !c->http3) return 0;
        int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
        nghttp3_ssize nconsumed = nghttp3_conn_read_stream2(c->http3, stream_id, data, datalen, fin,
                                                            ngtcp2_conn_get_timestamp(conn));
        if (nconsumed < 0) {
            c->dead = true;
            return 0;
        }
        if (nconsumed > 0) {
            ngtcp2_conn_extend_max_stream_offset(conn, stream_id, nconsumed);
            ngtcp2_conn_extend_max_offset(conn, nconsumed);
        }
        return 0;
    }

    static int onAckedStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t, uint64_t datalen,
                                 void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        if (c->http3) nghttp3_conn_add_ack_offset(c->http3, stream_id, datalen);
        return 0;
    }

    static int onStreamOpen(ngtcp2_conn*, int64_t stream_id, void* user_data) {
        auto* c = static_cast<Conn*>(user_data);
        if ((stream_id & 0x3) == 0) {  // 客户端双向流 = 请求流
            c->streams.emplace(stream_id, Stream{});
        }
        return 0;
    }

    static int onStreamClose(ngtcp2_conn* conn, uint32_t, int64_t stream_id, uint64_t,
                             void* user_data, void* stream_user_data) {
        auto* c = static_cast<Conn*>(user_data);
        if (c->http3) {
            int rv = nghttp3_conn_close_stream(c->http3, stream_id, NGHTTP3_H3_NO_ERROR);
            if (rv == NGHTTP3_ERR_STREAM_NOT_FOUND) {
                // http3 未接管过此流 → 自行清理（rv==0 时 onH3StreamClose 已同步完成）
                c->streams.erase(stream_id);
                if ((stream_id & 0x3) == 0) ngtcp2_conn_extend_max_streams_bidi(conn, 1);
            }
        } else {
            c->streams.erase(stream_id);
            if ((stream_id & 0x3) == 0) ngtcp2_conn_extend_max_streams_bidi(conn, 1);
        }
        return 0;
    }

    static int onStreamReset(ngtcp2_conn*, int64_t stream_id, uint64_t, uint64_t, void* user_data,
                             void*) {
        auto* c = static_cast<Conn*>(user_data);
        if (c->http3) nghttp3_conn_shutdown_stream_read(c->http3, stream_id);
        return 0;
    }

    static int onStreamStopSending(ngtcp2_conn*, int64_t stream_id, uint64_t, void* user_data,
                                   void*) {
        auto* c = static_cast<Conn*>(user_data);
        // 对端 STOP_SENDING → http3 层关读侧（官方示例同：nghttp3_conn_shutdown_stream_read）
        if (c->http3) nghttp3_conn_shutdown_stream_read(c->http3, stream_id);
        return 0;
    }

    static int onExtendMaxStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t, void* user_data,
                                     void*) {
        auto* c = static_cast<Conn*>(user_data);
        if (c->http3) nghttp3_conn_unblock_stream(c->http3, stream_id);
        return 0;
    }

    static void onRand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
        RAND_bytes(dest, static_cast<int>(destlen));
    }

    static int onGetNewCid(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                           void* user_data) {
        auto* c = static_cast<Conn*>(user_data);
        auto* srv = c->srv;
        std::vector<uint8_t> bytes(cidlen);
        RAND_bytes(bytes.data(), static_cast<int>(cidlen));
        ngtcp2_cid_init(cid, bytes.data(), cidlen);
        RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
        std::string key(reinterpret_cast<char*>(bytes.data()), cidlen);
        c->scids.push_back(key);
        srv->cidMap_[key] = c;
        return 0;
    }

    static int onRemoveCid(ngtcp2_conn*, const ngtcp2_cid* cid, void* user_data) {
        auto* c = static_cast<Conn*>(user_data);
        std::string key(reinterpret_cast<const char*>(cid->data), cid->datalen);
        c->srv->cidMap_.erase(key);
        return 0;
    }

    // ---------------- nghttp3 回调 ----------------

    static int onH3BeginHeaders(nghttp3_conn* conn3, int64_t stream_id, void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        auto it = c->streams.find(stream_id);
        if (it == c->streams.end()) {
            auto [nit, ok] = c->streams.emplace(stream_id, Stream{});
            it = nit;
        }
        nghttp3_conn_set_stream_user_data(conn3, stream_id, &it->second);
        return 0;
    }

    static int onH3RecvHeader(nghttp3_conn*, int64_t stream_id, int32_t token, nghttp3_rcbuf* name,
                              nghttp3_rcbuf* value, uint8_t, void*, void* stream_user_data) {
        auto* s = static_cast<Stream*>(stream_user_data);
        if (!s) return 0;
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        std::string val(reinterpret_cast<const char*>(v.base), v.len);
        switch (token) {
            case NGHTTP3_QPACK_TOKEN__METHOD:
                s->method = std::move(val);
                break;
            case NGHTTP3_QPACK_TOKEN__PATH:
                s->path = std::move(val);
                break;
            case NGHTTP3_QPACK_TOKEN__AUTHORITY:
                s->authority = std::move(val);
                break;
            default: {
                nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
                std::string ns(reinterpret_cast<const char*>(n.base), n.len);
                if (!ns.empty() && ns[0] != ':') s->headers.emplace_back(std::move(ns), std::move(val));
                break;
            }
        }
        return 0;
    }

    static int onH3EndHeaders(nghttp3_conn*, int64_t, int, void*, void*) { return 0; }

    static int onH3RecvData(nghttp3_conn*, int64_t stream_id, const uint8_t* data, size_t datalen,
                            void* user_data, void* stream_user_data) {
        auto* c = static_cast<Conn*>(user_data);
        auto* s = static_cast<Stream*>(stream_user_data);
        if (!s) return 0;
        if (!s->bodyTooLarge) {
            if (s->body.size() + datalen > c->srv->maxBody_) {
                s->bodyTooLarge = true;
                s->body.clear();
            } else {
                s->body.append(reinterpret_cast<const char*>(data), datalen);
            }
        }
        ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, datalen);
        ngtcp2_conn_extend_max_offset(c->conn, datalen);
        return 0;
    }

    static int onH3DeferredConsume(nghttp3_conn*, int64_t stream_id, size_t consumed,
                                   void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, consumed);
        ngtcp2_conn_extend_max_offset(c->conn, consumed);
        return 0;
    }

    static int onH3EndStream(nghttp3_conn*, int64_t stream_id, void* user_data,
                             void* stream_user_data) {
        auto* c = static_cast<Conn*>(user_data);
        auto* s = static_cast<Stream*>(stream_user_data);
        if (!s || c->dead) return 0;
        c->srv->dispatch(*c, stream_id, *s);
        return 0;
    }

    static int onH3StopSending(nghttp3_conn*, int64_t stream_id, uint64_t app_code,
                               void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        ngtcp2_conn_shutdown_stream_read(c->conn, 0, stream_id, app_code);
        return 0;
    }

    static int onH3ResetStream(nghttp3_conn*, int64_t stream_id, uint64_t app_code,
                               void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        ngtcp2_conn_shutdown_stream_write(c->conn, 0, stream_id, app_code);
        return 0;
    }

    static int onH3StreamClose(nghttp3_conn*, int64_t stream_id, uint64_t, void* user_data, void*) {
        auto* c = static_cast<Conn*>(user_data);
        c->streams.erase(stream_id);
        if ((stream_id & 0x3) == 0) ngtcp2_conn_extend_max_streams_bidi(c->conn, 1);
        return 0;
    }

    static int onH3AckedStreamData(nghttp3_conn*, int64_t, uint64_t, void*, void*) { return 0; }

    static nghttp3_ssize readDataCb(nghttp3_conn*, int64_t, nghttp3_vec* vec, size_t veccnt,
                                    uint32_t* pflags, void*, void* stream_user_data) {
        auto* s = static_cast<Stream*>(stream_user_data);
        if (!s || veccnt == 0) {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (s->respOff >= s->respBody.size()) {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        size_t remain = s->respBody.size() - s->respOff;
        vec[0].base = reinterpret_cast<uint8_t*>(s->respBody.data()) + s->respOff;
        vec[0].len = remain;
        s->respOff += remain;
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    // ---------------- 请求分发 / 响应 ----------------

    void dispatch(Conn& c, int64_t streamId, Stream& s) {
        if (s.method.empty() || s.path.empty()) {
            nghttp3_conn_close_stream(c.http3, streamId, NGHTTP3_H3_GENERAL_PROTOCOL_ERROR);
            return;
        }
        if (s.bodyTooLarge) {
            BridgeResponse r;
            r.status = 413;
            r.body = "request body too large";
            submitResponse(c, streamId, s, r);
            return;
        }

        BridgeRequest req;
        req.method = s.method;
        req.target = s.path;
        req.host = s.authority;
        req.headOnly = (s.method == "HEAD");
        req.headers = s.headers;
        req.body = s.body;

        req.clientIp = peerIpOf(c);
        if (novaTrustedProxy(req.clientIp)) {
            for (const auto& [k, v] : s.headers) {
                if (lowerStr(k) == "x-forwarded-for") {
                    std::string lm = xffLeftmost(v);
                    if (!lm.empty()) req.clientIp = lm;
                    break;
                }
            }
        }

        const uint64_t connId = c.id;
        // 桥异步回调可能晚于本对象析构触发（reactor 退出收尾）：weak 存活令牌防悬空
        std::weak_ptr<char> wp = alive_;
        bridge_.submit(std::move(req), [this, connId, streamId, wp](const BridgeResponse& resp) {
            if (wp.expired()) return;
            Conn* cc = findConnById(connId);
            if (!cc || cc->dead || !cc->http3) return;
            auto it = cc->streams.find(streamId);
            if (it == cc->streams.end()) return;
            submitResponse(*cc, streamId, it->second, resp);
        });
    }

    void submitResponse(Conn& c, int64_t streamId, Stream& s, const BridgeResponse& resp) {
        int status = resp.status > 0 ? resp.status : 502;
        std::string statusStr = std::to_string(status);
        std::string body = resp.status > 0 ? resp.body : std::string("bad gateway\n");
        bool headOnly = (s.method == "HEAD");

        std::vector<std::string> lowered;
        lowered.reserve(resp.headers.size());
        std::vector<nghttp3_nv> nva;
        nva.reserve(resp.headers.size() + 2);
        nva.push_back({reinterpret_cast<const uint8_t*>(":status"),
                       reinterpret_cast<const uint8_t*>(statusStr.data()), 7, statusStr.size(),
                       NGHTTP3_NV_FLAG_NONE});
        for (const auto& [k, v] : resp.headers) {
            std::string lk = lowerStr(k);
            if (isHopByHop(lk)) continue;
            lowered.push_back(std::move(lk));
            nva.push_back({reinterpret_cast<const uint8_t*>(lowered.back().data()),
                           reinterpret_cast<const uint8_t*>(v.data()), lowered.back().size(),
                           v.size(), NGHTTP3_NV_FLAG_NONE});
        }

        nghttp3_data_reader dr{};
        nghttp3_data_reader* drp = nullptr;
        if (!body.empty() && !headOnly) {
            s.respBody = std::move(body);
            s.respOff = 0;
            dr.read_data = &H3Server::readDataCb;
            drp = &dr;
        }

        int rv = nghttp3_conn_submit_response(c.http3, streamId, nva.data(), nva.size(), drp);
        if (rv != 0) {
            nghttp3_conn_close_stream(c.http3, streamId, NGHTTP3_H3_INTERNAL_ERROR);
            return;
        }
        writePending(c);
    }

    // ---------------- 写循环 ----------------

    int writePending(Conn& c) {
        if (c.dead) return 0;
        ngtcp2_tstamp ts = nowNs();
        for (;;) {
            int64_t stream_id = -1;
            int fin = 0;
            nghttp3_vec v8[8];
            nghttp3_ssize vcnt = 0;
            if (c.http3 && ngtcp2_conn_get_max_data_left(c.conn)) {
                vcnt = nghttp3_conn_writev_stream(c.http3, &stream_id, &fin, v8, 8);
                if (vcnt < 0) return -1;
            }
            ngtcp2_vec v[8];
            for (nghttp3_ssize i = 0; i < vcnt; ++i) v[i] = {v8[i].base, v8[i].len};

            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | NGTCP2_WRITE_STREAM_FLAG_PADDING;
            if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            ngtcp2_ssize pdatalen = 0;
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_init(&ps, reinterpret_cast<ngtcp2_sockaddr*>(&localAddr_), localLen_,
                                     reinterpret_cast<ngtcp2_sockaddr*>(&c.peer), c.peerLen,
                                     nullptr);
            ngtcp2_pkt_info pi{};
            auto nwrite = ngtcp2_conn_writev_stream(
                c.conn, &ps.path, &pi, txBuf_, sizeof(txBuf_), &pdatalen, flags,
                (vcnt > 0 || stream_id >= 0) ? stream_id : -1, v, static_cast<size_t>(vcnt), ts);

            if (nwrite == 0) return 0;
            if (nwrite < 0) {
                if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                    if (stream_id >= 0 && pdatalen > 0)
                        nghttp3_conn_add_write_offset(c.http3, stream_id, pdatalen);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                    if (stream_id >= 0) nghttp3_conn_block_stream(c.http3, stream_id);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
                    if (stream_id >= 0) nghttp3_conn_shutdown_stream_write(c.http3, stream_id);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) continue;
                return -1;
            }
            ssize_t sent = sendto(udpFd_, txBuf_, static_cast<size_t>(nwrite), 0,
                                  reinterpret_cast<sockaddr*>(&c.peer), c.peerLen);
            (void)sent;
            if (stream_id >= 0 && pdatalen > 0)
                nghttp3_conn_add_write_offset(c.http3, stream_id, pdatalen);
        }
    }

    void reapDead() {
        for (auto it = conns_.begin(); it != conns_.end();) {
            Conn* c = it->get();
            if (!c->dead) {
                ++it;
                continue;
            }
            for (const auto& scid : c->scids) cidMap_.erase(scid);
            cidMap_.erase(c->initialDcid);
            it = conns_.erase(it);
        }
    }

    std::string peerIpOf(const Conn& c) const {
        char buf[INET_ADDRSTRLEN] = {0};
        if (c.peer.ss_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&c.peer);
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        }
        return buf;
    }

    int udpFd_ = -1;
    SSL_CTX* sslCtx_ = nullptr;
    H1Bridge& bridge_;
    size_t maxBody_;
    size_t maxConns_ = 256;
    uint8_t staticSecret_[32];
    sockaddr_storage localAddr_{};
    socklen_t localLen_ = 0;
    uint8_t rxBuf_[65536];
    uint8_t txBuf_[65536];
    std::vector<std::unique_ptr<Conn>> conns_;
    std::unordered_map<std::string, Conn*> cidMap_;
    uint64_t nextConnId_ = 1;
    std::shared_ptr<char> alive_ = std::make_shared<char>(0);  // 析构即失效的存活令牌

    friend struct Conn;
};

}  // namespace novawaf
