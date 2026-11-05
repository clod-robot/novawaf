#pragma once

// HTTP/2 (nghttp2) 服务端会话：由 TlsConn 驱动 SSL 读写字节。
// 请求聚合为 BridgeRequest 经 H1Bridge 入 h1 管线，响应经 nghttp2 回帧。

#include <nghttp2/nghttp2.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bridge.h"

namespace novawaf {

class H2Session {
public:
    // 由 TlsConn 实现的字节出口
    struct Io {
        virtual ~Io() = default;
        virtual void h2QueueOut(const uint8_t* data, size_t len) = 0;
    };

    H2Session(Io& io, H1Bridge& bridge, std::string peerIp, size_t maxBody)
        : io_(io), bridge_(bridge), peerIp_(std::move(peerIp)), maxBody_(maxBody) {}

    ~H2Session() {
        if (sess_) nghttp2_session_del(sess_);
        for (auto& [id, s] : streams_) delete s.pendingBody;
    }

    bool init() {
        nghttp2_session_callbacks* cb = nullptr;
        if (nghttp2_session_callbacks_new(&cb) != 0) return false;
        nghttp2_session_callbacks_set_send_callback(cb, &H2Session::onSend);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cb, &H2Session::onFrameRecv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, &H2Session::onDataChunk);
        nghttp2_session_callbacks_set_on_stream_close_callback(cb, &H2Session::onStreamClose);
        nghttp2_session_callbacks_set_on_header_callback(cb, &H2Session::onHeader);
        nghttp2_session_callbacks_set_on_begin_headers_callback(cb, &H2Session::onBeginHeaders);
        int rv = nghttp2_session_server_new(&sess_, cb, this);
        nghttp2_session_callbacks_del(cb);
        if (rv != 0) return false;

        nghttp2_settings_entry iv[2] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 128},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20},
        };
        nghttp2_submit_settings(sess_, NGHTTP2_FLAG_NONE, iv, 2);
        return flush() == 0;
    }

    // <0 = 致命错误，连接应关闭
    int onRecv(const uint8_t* data, size_t len) {
        if (nghttp2_session_mem_recv(sess_, data, len) < 0) return -1;
        return flush();
    }

    int flush() { return nghttp2_session_send(sess_) == 0 ? 0 : -1; }

    // 无在途流（drain 期间空闲判定用）
    bool idle() const { return streams_.empty(); }

private:
    struct BodySrc {
        std::string data;
        size_t pos = 0;
    };

    struct Stream {
        std::string method, path, authority;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        bool bodyTooLarge = false;
        BodySrc* pendingBody = nullptr;
    };

    static nghttp2_ssize onSend(nghttp2_session*, const uint8_t* data, size_t length, int,
                                void* user_data) {
        auto* self = static_cast<H2Session*>(user_data);
        self->io_.h2QueueOut(data, length);
        return static_cast<nghttp2_ssize>(length);
    }

    static int onBeginHeaders(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
        if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
        auto* self = static_cast<H2Session*>(user_data);
        self->streams_[frame->hd.stream_id] = Stream{};
        return 0;
    }

    static int onHeader(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name,
                        size_t namelen, const uint8_t* value, size_t valuelen, uint8_t,
                        void* user_data) {
        auto* self = static_cast<H2Session*>(user_data);
        auto it = self->streams_.find(frame->hd.stream_id);
        if (it == self->streams_.end()) return 0;
        Stream& s = it->second;
        std::string n(reinterpret_cast<const char*>(name), namelen);
        std::string v(reinterpret_cast<const char*>(value), valuelen);
        if (n == ":method") s.method = std::move(v);
        else if (n == ":path") s.path = std::move(v);
        else if (n == ":authority") s.authority = std::move(v);
        else if (!n.empty() && n[0] != ':') s.headers.emplace_back(std::move(n), std::move(v));
        return 0;
    }

    static int onDataChunk(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data,
                           size_t len, void* user_data) {
        auto* self = static_cast<H2Session*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it == self->streams_.end()) return 0;
        Stream& s = it->second;
        if (s.bodyTooLarge) return 0;
        if (s.body.size() + len > self->maxBody_) {
            s.bodyTooLarge = true;
            s.body.clear();
            return 0;
        }
        s.body.append(reinterpret_cast<const char*>(data), len);
        return 0;
    }

    static int onFrameRecv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<H2Session*>(user_data);
        if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            self->dispatch(frame->hd.stream_id);
        }
        return 0;
    }

    static int onStreamClose(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data) {
        auto* self = static_cast<H2Session*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            delete it->second.pendingBody;
            self->streams_.erase(it);
        }
        return 0;
    }

    static nghttp2_ssize bodyRead(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                                  uint32_t* flags, nghttp2_data_source* source, void*) {
        auto* b = static_cast<BodySrc*>(source->ptr);
        size_t remain = b->data.size() - b->pos;
        size_t n = remain < length ? remain : length;
        if (n) {
            std::memcpy(buf, b->data.data() + b->pos, n);
            b->pos += n;
        }
        if (b->pos == b->data.size()) *flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<nghttp2_ssize>(n);
    }

    void dispatch(int32_t streamId) {
        auto it = streams_.find(streamId);
        if (it == streams_.end()) return;
        Stream& s = it->second;
        if (s.method.empty() || s.path.empty()) return;  // 伪头缺失，交给 nghttp2 协议层处理

        if (s.bodyTooLarge) {
            BridgeResponse r;
            r.status = 413;
            r.body = "request body too large";
            respond(streamId, it, r);
            return;
        }

        BridgeRequest req;
        req.method = s.method;
        req.target = s.path;
        req.host = s.authority;
        req.headOnly = (s.method == "HEAD");
        req.headers = s.headers;
        req.body = std::move(s.body);
        s.body.clear();

        // 有效客户端 IP：peer 是受信代理时采信其 XFF
        req.clientIp = peerIp_;
        if (novaTrustedProxy(peerIp_)) {
            for (const auto& [k, v] : s.headers) {
                if (lowerStr(k) == "x-forwarded-for") {
                    std::string lm = xffLeftmost(v);
                    if (!lm.empty()) req.clientIp = lm;
                    break;
                }
            }
        }

        // 桥异步回调可能晚于本对象析构触发（连接中途断开）：weak 存活令牌防悬空
        std::weak_ptr<char> wp = alive_;
        bridge_.submit(std::move(req), [this, streamId, wp](const BridgeResponse& resp) {
            if (wp.expired()) return;
            auto it2 = streams_.find(streamId);
            if (it2 == streams_.end()) return;  // 流已被对方 rst
            respond(streamId, it2, resp);
        });
    }

    void respond(int32_t streamId, std::unordered_map<int32_t, Stream>::iterator it,
                 const BridgeResponse& resp) {
        Stream& s = it->second;
        int status = resp.status > 0 ? resp.status : 502;
        std::string statusStr = std::to_string(status);
        std::string body = resp.status > 0 ? resp.body : std::string("bad gateway\n");

        std::vector<std::string> lowered;  // 头名小写副本，保证生命周期到 submit 返回
        lowered.reserve(resp.headers.size());
        std::vector<nghttp2_nv> nva;
        nva.reserve(resp.headers.size() + 2);
        nva.push_back({reinterpret_cast<uint8_t*>(const_cast<char*>(":status")),
                       reinterpret_cast<uint8_t*>(statusStr.data()), 7, statusStr.size(),
                       NGHTTP2_NV_FLAG_NONE});
        for (const auto& [k, v] : resp.headers) {
            std::string lk = lowerStr(k);
            if (isHopByHop(lk)) continue;
            lowered.push_back(std::move(lk));
            const std::string& nameRef = lowered.back();
            nva.push_back({reinterpret_cast<uint8_t*>(const_cast<char*>(nameRef.data())),
                           reinterpret_cast<uint8_t*>(const_cast<char*>(v.data())), nameRef.size(),
                           v.size(), NGHTTP2_NV_FLAG_NONE});
        }
        std::string clStr = std::to_string(body.size());
        nva.push_back({reinterpret_cast<uint8_t*>(const_cast<char*>("content-length")),
                       reinterpret_cast<uint8_t*>(clStr.data()), 14, clStr.size(),
                       NGHTTP2_NV_FLAG_NONE});

        nghttp2_data_provider prd{};
        nghttp2_data_provider* prdPtr = nullptr;
        bool headOnly = (s.method == "HEAD");
        if (!body.empty() && !headOnly) {
            delete s.pendingBody;
            s.pendingBody = new BodySrc{std::move(body), 0};
            prd.source.ptr = s.pendingBody;
            prd.read_callback = &H2Session::bodyRead;
            prdPtr = &prd;
        }

        int rv = nghttp2_submit_response(sess_, streamId, nva.data(), nva.size(), prdPtr);
        if (rv != 0) {
            nghttp2_submit_rst_stream(sess_, NGHTTP2_FLAG_NONE, streamId, NGHTTP2_INTERNAL_ERROR);
        }
        flush();
    }

    Io& io_;
    H1Bridge& bridge_;
    std::string peerIp_;
    size_t maxBody_;
    nghttp2_session* sess_ = nullptr;
    std::unordered_map<int32_t, Stream> streams_;
    std::shared_ptr<char> alive_ = std::make_shared<char>(0);  // 析构即失效的存活令牌
};

}  // namespace novawaf
