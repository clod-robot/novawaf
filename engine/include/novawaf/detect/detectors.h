// NovaWAF - 检测器策略接口 + 具体检测器（SQLi/XSS/RCE/路径遍历等）
// 采用策略模式，每个检测器可独立插拔。检测基于：归一化 + AC 预筛 + 语义特征打分。
#pragma once

#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/http_model.h"

#include <memory>
#include <string>
#include <vector>

namespace novawaf {

class IDetector {
public:
    virtual ~IDetector() = default;
    virtual const char* name() const = 0;
    virtual DetectionResult detect(const HttpRequest& req) = 0;
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

}  // namespace novawaf
