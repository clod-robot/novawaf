// NovaWAF - 外部情报信誉检测（Phase 2）
// 设计：引擎不直接调用外部 HTTPS API（VT/OTX 均为 HTTPS，且限速），而是：
//   1) 热路径：对上传文件算 SHA-256，查内存已知恶意集（命中即拦）；普通请求零开销直接放行。
//   2) 未知哈希投递到 Redis 队列 novawaf:intel:queue，由外部 enricher（Python）异步查询
//      VirusTotal / OTX / AbuseIPDB，结果写回 novawaf:intel:hash:<sha>（1=恶意 0=干净，带 TTL）。
//   3) 后台线程轮询 pending 哈希，把判定结果回灌内存集，实现"首次放行、再次命中即拦"。
// 全程 fail-open：Redis 不可用 / 无结果均放行，绝不阻塞检测热路径。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"
#include "novawaf/core/redis_client.h"
#include "novawaf/util/sha256.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace novawaf {

// 后台投递 + 回灌器（跨 detector clone 共享的单例式实例）
class IntelPoster {
public:
    static std::shared_ptr<IntelPoster> instance() {
        static std::shared_ptr<IntelPoster> inst = std::make_shared<IntelPoster>();
        return inst;
    }

    IntelPoster() {
        const char* dis = std::getenv("NOVA_INTEL_DISABLE");
        disabled_ = dis && *dis == '1';
        if (disabled_) return;
        thread_ = std::thread([this] { run(); });
    }
    ~IntelPoster() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

    bool disabled() const { return disabled_; }

    // 热路径查询：是否已知恶意（只读，shared_lock）
    bool isMalicious(const std::string& sha) {
        std::shared_lock lk(mtx_);
        return malicious_.count(sha) != 0;
    }
    bool isClean(const std::string& sha) {
        std::shared_lock lk(mtx_);
        return clean_.count(sha) != 0;
    }
    // 若哈希未决（不在恶意/干净/pending），加入待查队列；返回是否为新增
    bool enqueueIfNew(const std::string& sha) {
        std::unique_lock lk(mtx_);
        if (malicious_.count(sha) || clean_.count(sha) || pending_.count(sha)) return false;
        if (pending_.size() >= kMaxPending) return false;  // 背压：上限保护
        pending_.insert(sha);
        incoming_.push_back(sha);
        return true;
    }

private:
    static constexpr size_t kMaxPending = 20000;

    void run() {
        RedisClient r;
        bool connected = false;
        auto ensureConn = [&]() -> bool {
            if (connected && r.connected()) return true;
            const char* rh = std::getenv("NOVA_REDIS_HOST");
            if (!rh || !*rh) return false;
            int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
            const char* pass = std::getenv("NOVA_REDIS_PASS");
            int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
            connected = r.connect(rh, port, pass ? pass : "", db, 1000);
            return connected;
        };
        int pollTick = 0;
        while (running_) {
            // 1) 把 incoming 批量 LPUSH 到队列
            {
                std::unique_lock lk(mtx_);
                if (!incoming_.empty() && ensureConn()) {
                    r.rpushMulti("novawaf:intel:queue", incoming_);
                    incoming_.clear();
                }
            }
            // 2) 每 ~5s 轮询 pending 回灌结果
            if (++pollTick >= 5) {
                pollTick = 0;
                std::vector<std::string> pend;
                {
                    std::shared_lock lk(mtx_);
                    pend.assign(pending_.begin(), pending_.end());
                }
                if (!pend.empty() && ensureConn()) {
                    std::vector<std::string> gotMalicious, gotClean;
                    for (auto& sha : pend) {
                        auto v = r.get("novawaf:intel:hash:" + sha);
                        if (!v) continue;
                        if (*v == "1") gotMalicious.push_back(sha);
                        else if (*v == "0") gotClean.push_back(sha);
                    }
                    if (!gotMalicious.empty() || !gotClean.empty()) {
                        std::unique_lock lk(mtx_);
                        for (auto& s : gotMalicious) { malicious_.insert(s); pending_.erase(s); }
                        for (auto& s : gotClean)     { clean_.insert(s);     pending_.erase(s); }
                    }
                }
            }
            for (int i = 0; i < 10 && running_; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::atomic<bool> running_{true};
    bool disabled_ = false;
    std::thread thread_;
    std::shared_mutex mtx_;
    std::unordered_set<std::string> malicious_;
    std::unordered_set<std::string> clean_;
    std::unordered_set<std::string> pending_;
    std::vector<std::string> incoming_;
};

class ExternalIntelDetector : public IDetector {
public:
    ExternalIntelDetector() : poster_(IntelPoster::instance()) {}
    ExternalIntelDetector(const ExternalIntelDetector&) = default;  // 共享 poster_
    const char* name() const override { return "ExternalIntel"; }
    std::unique_ptr<IDetector> clone() const override {
        return std::make_unique<ExternalIntelDetector>(*this);
    }

    DetectionResult detect(const HttpRequest& req) override {
        if (!poster_ || poster_->disabled()) return {};
        std::string ct = getHeaderCi(req, "content-type");
        auto payloads = extractUploadPayloads(req, ct);
        if (payloads.empty()) return {};  // 非上传请求：零开销放行

        for (auto& p : payloads) {
            if (p.empty()) continue;
            std::string sha = sha256::hashHex(p.data(), p.size());
            if (poster_->isMalicious(sha)) {
                return {Action::BLOCK, "TI-EXT-001", "MalwareHash",
                        "外部情报命中恶意文件哈希 " + sha.substr(0, 16) + "…", sha};
            }
            if (!poster_->isClean(sha)) poster_->enqueueIfNew(sha);  // 未决则投递异步查询
        }
        return {};  // fail-open
    }

private:
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
    static std::vector<std::string> extractUploadPayloads(const HttpRequest& req, const std::string& ct) {
        std::vector<std::string> out;
        // 仅处理上传：multipart 拆出每个 part 的纯净内容；非 multipart 且有 body 则整段算
        const std::string marker = "boundary=";
        auto bp = ct.find(marker);
        if (bp != std::string::npos) {
            std::string boundary = ct.substr(bp + marker.size());
            if (!boundary.empty() && boundary[0] == '"') {
                boundary.erase(0, 1);
                if (!boundary.empty() && boundary.back() == '"') boundary.pop_back();
            }
            std::string delim = "--" + boundary;
            size_t pos = 0;
            while (true) {
                auto s = req.body.find(delim, pos);
                if (s == std::string::npos) break;
                auto start = s + delim.size();
                auto e = req.body.find(delim, start);
                if (e == std::string::npos) break;
                std::string part = req.body.substr(start, e - start);
                auto sep = part.find("\r\n\r\n");
                if (sep != std::string::npos) {
                    std::string content = part.substr(sep + 4);
                    // 去掉 part 末尾可能的 \r\n
                    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) content.pop_back();
                    if (!content.empty()) out.push_back(std::move(content));
                }
                pos = e;
            }
        } else if (!req.body.empty()) {
            out.push_back(req.body);
        }
        return out;
    }

    std::shared_ptr<IntelPoster> poster_;
};

}  // namespace novawaf
