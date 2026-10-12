// NovaWAF - 检测器策略接口 + 具体检测器（SQLi/XSS/RCE/路径遍历等）
// 采用策略模式，每个检测器可独立插拔。检测基于：归一化 + AC 预筛 + 语义特征打分。
#pragma once

#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/http_model.h"
#include "novawaf/detect/threat_intel.h"

#include <cctype>
#include <memory>
#include <string>
#include <vector>

namespace novawaf {

class IDetector {
public:
    virtual ~IDetector() = default;
    virtual const char* name() const = 0;
    virtual DetectionResult detect(const HttpRequest& req) = 0;
    // 用于 copy-on-write 热更新：克隆一个独立检测器（含独立 AC 自动机）
    virtual std::unique_ptr<IDetector> clone() const = 0;
};

// ---- SQL 注入检测器 ----
class SqlInjectionDetector : public IDetector {
public:
    SqlInjectionDetector() {
        // SQL 关键词特征（AC 预筛）
        for (auto& p : {"union select", "select ", "insert ", "update ", "delete ",
                         "drop table", "--", "/*", "*/", "or 1=1", "or '1'='1",
                         "information_schema", "sleep(", "benchmark(", "xp_cmdshell",
                         "exec(", "execute(", "char(", "concat(", "0x"})
            ac_.addPattern(p);
        ac_.build();
    }

    const char* name() const override { return "SQLi"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<SqlInjectionDetector>(); }

    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                // 二次确认：检测 SQL 语义结构
                if (looksLikeSql(norm)) {
                    return {Action::BLOCK, "SQLI-001", "SQLi", "SQL injection detected", norm};
                }
            }
        }
        return {};
    }

private:
    bool looksLikeSql(const std::string& s) {
        bool hasKw = s.find("select") != std::string::npos ||
                     s.find("union") != std::string::npos ||
                     s.find("insert") != std::string::npos ||
                     s.find("drop") != std::string::npos ||
                     s.find("delete") != std::string::npos ||
                     s.find("update") != std::string::npos;
        bool hasComment = s.find("--") != std::string::npos ||
                          s.find("/*") != std::string::npos ||
                          s.find("#") != std::string::npos;
        // 永真注入：' or '1'='1  /  " or "1"="1  /  or 1=1
        bool tautology = (s.find("' or ") != std::string::npos ||
                          s.find("\" or ") != std::string::npos ||
                          s.find(" or 1=1") != std::string::npos ||
                          s.find("or '1'='1") != std::string::npos);
        bool timeBased = s.find("sleep(") != std::string::npos ||
                         s.find("benchmark(") != std::string::npos ||
                         s.find("waitfor delay") != std::string::npos;
        if (timeBased) return true;
        if (tautology) return true;
        return hasKw && (hasComment || s.find("=") != std::string::npos);
    }

    AcAutomaton ac_;
};

// ---- XSS 检测器 ----
class XssDetector : public IDetector {
public:
    XssDetector() {
        for (auto& p : {"<script", "</script>", "javascript:", "onerror=", "onload=",
                         "onclick=", "onmouseover=", "eval(", "alert(", "document.cookie",
                         "<iframe", "<img", "vbscript:", "data:text/html"})
            ac_.addPattern(p);
        ac_.build();
    }

    const char* name() const override { return "XSS"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<XssDetector>(); }

    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "XSS-001", "XSS", "Cross-site scripting detected", norm};
            }
        }
        return {};
    }

private:
    AcAutomaton ac_;
};

// ---- 命令注入/RCE 检测器 ----
class CommandInjectionDetector : public IDetector {
public:
    CommandInjectionDetector() {
        for (auto& p : {";ls", "|ls", "`ls`", "$(", "&&", "||", ">", "<",
                         "/bin/", "/etc/passwd", "wget ", "curl ", "nc ",
                         "bash -i", "python -c", "perl -e", "system(", "exec(",
                         "passthru(", "shell_exec(", "proc_open("})
            ac_.addPattern(p);
        ac_.build();
    }

    const char* name() const override { return "RCE"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<CommandInjectionDetector>(); }

    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "RCE-001", "RCE", "Command injection / RCE detected", norm};
            }
        }
        return {};
    }

private:
    AcAutomaton ac_;
};

// ---- 路径遍历检测器 ----
class PathTraversalDetector : public IDetector {
public:
    PathTraversalDetector() {
        for (auto& p : {"../", "..\\", "%2e%2e", "....//", "..%2f", "/etc/", "c:\\", "c:/",
                         "boot.ini", "win.ini", "php://", "file://"})
            ac_.addPattern(p);
        ac_.build();
    }

    const char* name() const override { return "Traversal"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<PathTraversalDetector>(); }

    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "TRAV-001", "Traversal", "Path traversal detected", norm};
            }
        }
        return {};
    }

private:
    AcAutomaton ac_;
};

// ---- 服务端模板注入 SSTI 检测器 ----
class SstiDetector : public IDetector {
public:
    SstiDetector() {
        for (auto& p : {"{{", "}}", "${", "<%=", "%{", "{%", "%}",
                         "7*7", "config.items", "self.__init__", "__globals__",
                         "request|attr", "lipsum.__globals__", "get_flashed_messages"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "SSTI"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<SstiDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "SSTI-001", "SSTI", "Server-side template injection", norm};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- XXE / XML 外部实体检测器 ----
class XxeDetector : public IDetector {
public:
    XxeDetector() {
        // 仅匹配 XML 上下文特征，避免裸词 system/public 误伤正常路径/字段(如 /api/auth/system/info)
        // 真实 XXE 必带 <!ENTITY>/<!DOCTYPE，由下方精确特征兜底
        for (auto& p : {"<!entity", "<!doctype", "externalentity",
                         "%remote;", "file:///etc", "expect://"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "XXE"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<XxeDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "XXE-001", "XXE", "XML external entity injection", norm};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- SSRF 服务器端请求伪造检测器 ----
class SsrfDetector : public IDetector {
public:
    SsrfDetector() {
        for (auto& p : {"gopher://", "dict://", "ftp://", "tftp://", "ldap://",
                         "127.0.0.1", "localhost", "169.254.", "10.0.0.", "192.168.",
                         "100.100.100.200", "metadata.google", "0.0.0.0", "[::1]"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "SSRF"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<SsrfDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        // 仅检测用户可控输入（path/query/body/参数），不扫 Host 等头，避免误报正常回环地址
        std::vector<std::string> payloads{req.path, req.query, req.body};
        for (auto& [k, v] : req.queryParams) { payloads.push_back(k); payloads.push_back(v); }
        for (auto& payload : payloads) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "SSRF-001", "SSRF", "Server-side request forgery", norm};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- CRLF 注入 / HTTP 响应拆分 / 请求走私 检测器 ----
class CrlfDetector : public IDetector {
public:
    CrlfDetector() {
        for (auto& p : {"%0d%0a", "%0a", "set-cookie", "content-length", "transfer-encoding",
                         "\r\n\r\n", "0\r\n\r\n"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "CRLF"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<CrlfDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        // CRLF 注入/响应拆分的注入面是 URL 与请求头，请求体含 CRLF 属正常
        // （如 multipart 边界），故不扫描 body，避免上传误报。
        std::vector<std::string> payloads;
        payloads.push_back(req.path);
        payloads.push_back(req.query);
        for (auto& [k, v] : req.headers) payloads.push_back(v);
        for (auto& [k, v] : req.queryParams) {
            payloads.push_back(k);
            payloads.push_back(v);
        }
        for (auto& payload : payloads) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "CRLF-001", "CRLF", "CRLF injection / response splitting", norm};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- 敏感信息泄露 / 探针 检测器 ----
class InfoLeakDetector : public IDetector {
public:
    InfoLeakDetector() {
        for (auto& p : {".env", ".git/", ".svn/", "web.config", ".htaccess",
                         "/wp-admin", "phpinfo", ".bak", ".sql", "/.aws/",
                         "id_rsa", ".pem", "debug=true", "actuator"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "InfoLeak"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<InfoLeakDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            if (ac_.containsAny(norm)) {
                return {Action::BLOCK, "LEAK-001", "InfoLeak", "Sensitive path / info probing", norm};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- 扫描器/恶意爬虫 User-Agent 检测器 ----
class ScannerDetector : public IDetector {
public:
    ScannerDetector() {
        for (auto& p : {"sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus",
                         "dirbuster", "gobuster", "wfuzz", "burpsuite", "burp",
                         "zgrab", "havij", "wpscan", "metasploit", "skipfish", "hydra"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "Scanner"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<ScannerDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        auto it = req.headers.find("User-Agent");
        if (it != req.headers.end()) {
            std::string ua = it->second;
            for (auto& c : ua) c = (char)std::tolower((unsigned char)c);
            if (ac_.containsAny(ua)) {
                return {Action::BLOCK, "SCAN-001", "Scanner", "Security scanner / malicious UA", ua};
            }
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- 威胁情报 IOC 适配检测器：把 ThreatIntel 接入流水线 ----
class TiDetector : public IDetector {
public:
    explicit TiDetector(std::shared_ptr<ThreatIntel> ti) : ti_(std::move(ti)) {}
    const char* name() const override { return "ThreatIntel"; }
    std::unique_ptr<IDetector> clone() const override {
        return std::make_unique<TiDetector>(ti_);
    }
    DetectionResult detect(const HttpRequest& req) override {
        if (!ti_) return {};
        auto r = ti_->match(req);
        return r ? *r : DetectionResult{};
    }
private:
    std::shared_ptr<ThreatIntel> ti_;
};

}  // namespace novawaf
