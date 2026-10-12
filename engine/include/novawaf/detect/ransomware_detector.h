// NovaWAF - 勒索软件 / Rootkit 上传检测器
// 不依赖外部引擎：对上传请求做扩展名/文件名/rootkit 特征 + 高熵值（疑似已加密）启发式。
// 命中返回 BLOCK，由现有拦截+记录路径接管（事件/日志）。阈值与开关可经环境变量调整。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <cctype>
#include <cmath>
#include <cstdlib>
#include <string>
#include <unordered_set>

namespace novawaf {

class RansomwareDetector : public IDetector {
public:
    RansomwareDetector() {
        disabled_ = std::getenv("NOVA_RANSOMWARE_DISABLE") != nullptr;
        const char* et = std::getenv("NOVA_ENTROPY_THRESHOLD");
        entropyThreshold_ = et ? std::atof(et) : 7.9;
        const char* mb = std::getenv("NOVA_ENTROPY_MIN_BYTES");
        entropyMinBytes_ = mb ? (size_t)std::atoll(mb) : 1024;
    }

    const char* name() const override { return "Ransomware"; }
    std::unique_ptr<IDetector> clone() const override {
        auto c = std::make_unique<RansomwareDetector>();
        c->disabled_ = disabled_;
        c->entropyThreshold_ = entropyThreshold_;
        c->entropyMinBytes_ = entropyMinBytes_;
        return c;
    }

    DetectionResult detect(const HttpRequest& req) override {
        if (disabled_) return {};
        std::string ct = getHeaderCi(req, "content-type");
        bool isUpload = ct.find("multipart") != std::string::npos ||
                        ct.find("octet-stream") != std::string::npos ||
                        req.body.find("filename=") != std::string::npos;
        if (!isUpload) return {};

        // 1) 收集上传文件名（multipart 的 filename="..."）+ 请求路径末段
        std::vector<std::string> names;
        extractFilenames(req.body, names);
        names.push_back(lastPathSegment(req.path));

        for (auto& fn : names) {
            if (fn.empty()) continue;
            std::string lfn = toLower(fn);
            // 勒索提示文件名
            if (isRansomNote(lfn))
                return block("Ransomware", "ransom note filename: " + fn, fn);
            std::string ext = extensionOf(lfn);
            if (ext.empty()) continue;
            if (ransomExts.count(ext))
                return block("Ransomware", "ransomware extension: ." + ext, fn);
            if (ext == "ko")
                return block("Rootkit", "kernel module upload (.ko) blocked", fn);
            if (dropperNames.count(lfn))
                return block("Rootkit", "known rootkit/dropper filename: " + fn, fn);
        }

        // 2) 高熵启发式：疑似已加密/随机内容（勒索加密文件）
        if (req.body.size() >= entropyMinBytes_) {
            double e = shannonEntropy(req.body);
            if (e >= entropyThreshold_)
                return block("Ransomware",
                             "high-entropy content (likely encrypted), entropy=" + fmt(e),
                             "entropy");
        }
        return {};
    }

private:
    static std::string getHeaderCi(const HttpRequest& req, const std::string& key) {
        for (auto& kv : req.headers) {
            if (iequals(kv.first, key)) return kv.second;
        }
        return {};
    }
    static bool iequals(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i)
            if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
        return true;
    }
    static std::string toLower(std::string s) {
        for (auto& c : s) c = (char)std::tolower((unsigned char)c);
        return s;
    }
    static void extractFilenames(const std::string& body, std::vector<std::string>& out) {
        size_t p = 0;
        while ((p = body.find("filename=\"", p)) != std::string::npos) {
            p += 10;
            size_t e = body.find('"', p);
            if (e == std::string::npos) break;
            out.push_back(body.substr(p, e - p));
            p = e + 1;
        }
    }
    static std::string lastPathSegment(const std::string& path) {
        size_t q = path.find('?');
        std::string p = (q == std::string::npos) ? path : path.substr(0, q);
        size_t s = p.find_last_of('/');
        return (s == std::string::npos) ? p : p.substr(s + 1);
    }
    static std::string extensionOf(const std::string& lfn) {
        size_t d = lfn.find_last_of('.');
        if (d == std::string::npos || d + 1 >= lfn.size()) return {};
        return lfn.substr(d + 1);
    }
    static bool isRansomNote(const std::string& lfn) {
        return lfn.find("decrypt") != std::string::npos ||
               lfn.find("restore") != std::string::npos ||
               lfn.find("recover") != std::string::npos ||
               lfn.find("ransom") != std::string::npos ||
               lfn.find("your_files") != std::string::npos ||
               lfn.find("readme_decrypt") != std::string::npos;
    }
    static double shannonEntropy(const std::string& data) {
        size_t n = data.size() > (1 << 18) ? (1 << 18) : data.size();  // 采样前 256KB
        size_t freq[256] = {0};
        for (size_t i = 0; i < n; ++i) freq[(unsigned char)data[i]]++;
        double ent = 0.0;
        for (int c = 0; c < 256; ++c) {
            if (freq[c]) {
                double p = (double)freq[c] / (double)n;
                ent -= p * std::log2(p);
            }
        }
        return ent;
    }
    static std::string fmt(double v) {
        char b[32]; std::snprintf(b, sizeof(b), "%.2f", v); return b;
    }
    static DetectionResult block(const std::string& cat, const std::string& desc,
                                 const std::string& matched) {
        return {Action::BLOCK, "RANSOM-001", cat, desc, matched};
    }

    bool disabled_ = false;
    double entropyThreshold_ = 7.9;
    size_t entropyMinBytes_ = 1024;

    static inline const std::unordered_set<std::string> ransomExts = {
        "locked","crypt","encrypted","wncry","wcry","zepto","odin","locky","cerber",
        "teslacrypt","xtbl","rnsmwr","aaa","abc","xyz","vvv","ccc","rdm","rtf","derns",
        "mole","locky","micro","delta","globe","pyk","crab","domino","contagio","gamma",
        "blackbit","clus","fun","harma","khropitsi","onion","porno","ecc","exx","ezz"
    };
    static inline const std::unordered_set<std::string> dropperNames = {
        "rootkit.exe","rootkit.sys","ntkrnlmp.exe","svch0st.exe","lsass.exe.bak"
    };
};

}  // namespace novawaf
