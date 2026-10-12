// NovaWAF - YARA 自建规则库检测器
// 链接 libyara，对上传文件体做 YARA 规则匹配；规则目录下 *.yar 按 mtime 热加载。
// 命中 -> BLOCK，记录命中规则名。可 NOVA_YARA_DISABLE 关闭。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <yara.h>

#include <sys/stat.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace novawaf {

class YaraDetector : public IDetector {
public:
    YaraDetector() {
        disabled_ = std::getenv("NOVA_YARA_DISABLE") != nullptr;
        const char* d = std::getenv("NOVA_YARA_RULES");
        rulesDir_ = d ? d : "yara-rules";
        static std::once_flag initFlag;
        std::call_once(initFlag, []() { yr_initialize(); });
        compileRules();
    }
    ~YaraDetector() override = default;

    const char* name() const override { return "YARA"; }
    std::unique_ptr<IDetector> clone() const override {
        // 共享已编译规则与热加载状态（检测器被克隆进新流水线时复用即可）
        return std::unique_ptr<YaraDetector>(new YaraDetector(*this));
    }

    DetectionResult detect(const HttpRequest& req) override {
        if (disabled_) return {};
        std::string ct = getHeaderCi(req, "content-type");
        bool isUpload = ct.find("multipart") != std::string::npos ||
                        ct.find("octet-stream") != std::string::npos ||
                        req.body.find("filename=") != std::string::npos;
        if (!isUpload || req.body.empty()) return {};

        reloadIfChanged();  // 规则文件变更则热重载
        std::shared_lock lk(mtx_);
        if (!rules_) return {};
        // 对 multipart 取各 part 纯净内容扫描；否则整个 body
        for (auto& p : extractUploadPayloads(req, ct)) {
            if (p.empty()) continue;
            std::string hit;
            int rc = yr_rules_scan_mem(rules_.get(), (const uint8_t*)p.data(), p.size(),
                                       0, &YaraDetector::cb, &hit, 1000);
            if (rc == ERROR_SUCCESS && !hit.empty())
                return {Action::BLOCK, "YARA-001", "Virus", "YARA matched: " + hit, hit};
        }
        return {};
    }

private:
    YaraDetector(const YaraDetector& o)
        : disabled_(o.disabled_), rulesDir_(o.rulesDir_),
          rules_(o.rules_), fingerprint_(o.fingerprint_.load()) {}
    // mtx_ 各自新建（不拷贝），rules_ 经 shared_ptr 共享

    static int cb(YR_SCAN_CONTEXT*, int message, void* msg_data, void* user_data) {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            auto* rule = (YR_RULE*)msg_data;
            auto* hit = (std::string*)user_data;
            *hit = rule->identifier;
            return CALLBACK_ABORT;  // 命中即停
        }
        return CALLBACK_CONTINUE;
    }

    // 计算规则目录指纹：文件数 + 最大 mtime
    static uint64_t dirFingerprint(const std::string& dir, std::vector<std::string>& files) {
        files.clear();
        uint64_t fp = 0; int64_t maxM = 0;
        if (FILE* pipe = popen(("ls -1 -- '" + dir + "' 2>/dev/null").c_str(), "r")) {
            char buf[512];
            while (fgets(buf, sizeof(buf), pipe)) {
                std::string f(buf); while (!f.empty() && (f.back()=='\n'||f.back()=='\r')) f.pop_back();
                if (f.size() > 4 && f.substr(f.size()-4) == ".yar") {
                    files.push_back(dir + "/" + f);
                    struct stat st{};
                    if (stat((dir + "/" + f).c_str(), &st) == 0 && st.st_mtime > maxM) maxM = st.st_mtime;
                }
            }
            pclose(pipe);
        }
        fp = (uint64_t)files.size() * 1000003ULL + (uint64_t)maxM;
        return fp;
    }

    void reloadIfChanged() {
        std::vector<std::string> files;
        uint64_t fp = dirFingerprint(rulesDir_, files);
        if (fp == fingerprint_.load()) return;
        std::unique_lock lk(mtx_);
        if (fp == fingerprint_.load()) return;  // double-check
        compileRulesLocked(files);
        fingerprint_.store(fp);
    }

    void compileRules() {
        std::vector<std::string> files;
        uint64_t fp = dirFingerprint(rulesDir_, files);
        compileRulesLocked(files);
        fingerprint_.store(fp);
    }

    void compileRulesLocked(const std::vector<std::string>& files) {
        YR_COMPILER* compiler = nullptr;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return;
        int errs = 0;
        for (auto& f : files) {
            std::FILE* fp = std::fopen(f.c_str(), "r");
            if (!fp) { std::fprintf(stderr, "[yara] cannot open %s\n", f.c_str()); continue; }
            int rc = yr_compiler_add_file(compiler, fp, nullptr, f.c_str());
            std::fclose(fp);
            if (rc != ERROR_SUCCESS) {
                // 规则编译失败则标记，避免对带错误的 compiler 调用 get_rules（YARA 会 assert 崩溃）
                std::fprintf(stderr, "[yara] rule compile error in %s (skipped)\n", f.c_str());
                ++errs;
            }
        }
        YR_RULES* r = nullptr;
        if (errs == 0 && yr_compiler_get_rules(compiler, &r) == ERROR_SUCCESS) {
            rules_.reset(r, [](YR_RULES* p) { if (p) yr_rules_destroy(p); });
        } else if (errs) {
            std::fprintf(stderr, "[yara] %d rule file(s) failed; keeping previous ruleset\n", errs);
        }
        yr_compiler_destroy(compiler);
    }

    // 复用 multipart 拆包逻辑（与 ClamavDetector 一致）
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
                if (start + 2 <= req.body.size() && req.body.compare(start, 2, "--") == 0) break;
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
    std::string rulesDir_ = "yara-rules";
    mutable std::shared_mutex mtx_;
    std::shared_ptr<YR_RULES> rules_;
    std::atomic<uint64_t> fingerprint_{0};
};

}  // namespace novawaf
