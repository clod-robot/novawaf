// NovaWAF - 静态文件魔数启发式检测器（D）
// 对上传内容按文件头魔数识别危险类型：PE/ELF 可执行文件（默认拦截）、
// OLE2 Office 文档（宏载体，可配拦截）。命中 -> BLOCK。NOVA_MAGIC_DISABLE 关闭。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace novawaf {

class MagicDetector : public IDetector {
public:
    MagicDetector() {
        disabled_ = std::getenv("NOVA_MAGIC_DISABLE") != nullptr;
        blockOffice_ = std::getenv("NOVA_MAGIC_BLOCK_OFFICE") != nullptr;
    }
    const char* name() const override { return "Magic"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<MagicDetector>(*this); }

    DetectionResult detect(const HttpRequest& req) override {
        if (disabled_) return {};
        std::string ct = getHeaderCi(req, "content-type");
        bool isUpload = ct.find("multipart") != std::string::npos ||
                        ct.find("octet-stream") != std::string::npos ||
                        req.body.find("filename=") != std::string::npos;
        if (!isUpload || req.body.empty()) return {};
        for (auto& p : extractUploadPayloads(req, ct)) {
            if (p.size() < 4) continue;
            const uint8_t* b = (const uint8_t*)p.data();
            if (b[0] == 0x4D && b[1] == 0x5A)  // MZ
                return block("Executable_PE", "PE executable upload (MZ magic)");
            if (b[0] == 0x7F && b[1] == 0x45 && b[2] == 0x4C && b[3] == 0x46)  // .ELF
                return block("Executable_ELF", "ELF executable upload");
            if (blockOffice_ && b[0] == 0xD0 && b[1] == 0xCF && b[2] == 0x11 && b[3] == 0xE0)  // OLE2
                return block("Office_Macro", "OLE2 Office document upload (macro carrier)");
        }
        return {};
    }
private:
    static DetectionResult block(const std::string& cat, const std::string& desc) {
        return {Action::BLOCK, "MAGIC-001", cat, desc, "magic"};
    }
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
    bool blockOffice_ = false;
};

}  // namespace novawaf
