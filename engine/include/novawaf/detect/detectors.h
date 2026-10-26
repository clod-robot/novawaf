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

// ---- 文件上传检测器：危险扩展名 / multipart 内嵌可执行内容 ----
class FileUploadDetector : public IDetector {
public:
    FileUploadDetector() {
        // 危险可执行/脚本扩展名（出现在 filename= 或路径中即高危）
        for (auto& p : {".php", ".phtml", ".php3", ".php5", ".jsp", ".jspx",
                         ".asp", ".aspx", ".asa", ".cer", ".ashx", ".asmx",
                         ".exe", ".dll", ".so", ".sh", ".py", ".pl", ".cgi",
                         ".war", ".jar", ".htaccess", ".user.ini"})
            ac_.addPattern(p);
        // multipart 内嵌的可执行内容特征
        for (auto& p : {"<?php", "<%", "eval(", "#!/bin", "pk\x03\x04"})
            ac2_.addPattern(p);
        ac_.build(); ac2_.build();
    }
    const char* name() const override { return "FileUpload"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<FileUploadDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        // 仅 multipart/form-data 或含 filename= 才视为上传面，避免普通请求误报
        std::string ct;
        auto it = req.headers.find("Content-Type");
        if (it != req.headers.end()) { ct = it->second; for (auto& c : ct) c = (char)std::tolower((unsigned char)c); }
        bool isUpload = ct.find("multipart/form-data") != std::string::npos ||
                        req.body.find("filename=") != std::string::npos;
        if (!isUpload) return {};
        // PHP2Shell 类畸形 multipart 防护（CVE-2026-109618/109619）：
        // 特制 multipart POST 触发 PHP 核心内存破坏。正常表单 part 数量远低于 500，
        // 超限即视为畸形 multipart 洪泛/内存破坏尝试，直接拦截。
        {
            std::string low = req.body;
            for (auto& c : low) c = (char)std::tolower((unsigned char)c);
            size_t parts = 0, pos = 0;
            while ((pos = low.find("content-disposition", pos)) != std::string::npos) {
                if (++parts > 500)
                    return {Action::BLOCK, "UPLOAD-003", "FileUpload", "Malformed multipart flood (PHP2Shell)", ""};
                pos += 19;
            }
        }
        std::string norm = Decoder::normalize(req.body);
        std::string normPath = Decoder::normalize(req.path);
        std::string normQ = Decoder::normalize(req.query);
        if (ac_.containsAny(norm) || ac_.containsAny(normPath) || ac_.containsAny(normQ))
            return {Action::BLOCK, "UPLOAD-001", "FileUpload", "Dangerous upload file extension", norm};
        if (ac2_.containsAny(norm))
            return {Action::BLOCK, "UPLOAD-002", "FileUpload", "Executable content in upload body", norm};
        return {};
    }
private:
    AcAutomaton ac_, ac2_;
};

// ---- Java 代码注入检测器：OGNL / SpEL / EL 表达式 / Runtime.exec ----
class JavaCodeInjectionDetector : public IDetector {
public:
    JavaCodeInjectionDetector() {
        for (auto& p : {"runtime.getruntime", ".exec(", "processbuilder",
                         "ognl.ognlcontext", "@ognl", "getclass().forname",
                         "t(java.lang.runtime)", "new java.lang.processbuilder",
                         "class.forname", "method.invoke", "spel", "${t(", "#runtime",
                         "getmethod(", "scriptengine", "javax.script"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "JavaCode"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<JavaCodeInjectionDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            for (auto& c : norm) c = (char)std::tolower((unsigned char)c);
            if (ac_.containsAny(norm))
                return {Action::BLOCK, "JCODE-001", "JavaCode", "Java code injection (OGNL/SpEL/EL)", norm};
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- Java 反序列化检测器：序列化魔数 / 危险 gadget 类名 ----
class JavaDeserializationDetector : public IDetector {
public:
    JavaDeserializationDetector() {
        // 危险 gadget 类/包名（ysoserial 常见链）
        for (auto& p : {"org.apache.commons.collections", "commons.beanutils",
                         "invokertransformer", "chainedtransformer", "annotationinvocationhandler",
                         "jrmpclient", "lookupsecuresystray", "badattributevalueexp",
                         "templatesimpl", "javassist", "groovy.lang.metaclass",
                         "readobject", "defaultreadobject", "priorityqueue"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "JavaDeser"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<JavaDeserializationDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            // Java 序列化魔数 AC ED 00 05（原始字节）
            if (payload.size() >= 4 && (unsigned char)payload[0] == 0xAC &&
                (unsigned char)payload[1] == 0xED && payload[2] == 0x00 && payload[3] == 0x05)
                return {Action::BLOCK, "JDESER-001", "JavaDeser", "Java serialized object magic bytes", payload.substr(0, 8)};
            // Base64 编码的魔数 rO0AB
            if (payload.find("rO0AB") != std::string::npos)
                return {Action::BLOCK, "JDESER-002", "JavaDeser", "Base64 Java serialized object", "rO0AB"};
            std::string norm = Decoder::normalize(payload);
            for (auto& c : norm) c = (char)std::tolower((unsigned char)c);
            if (ac_.containsAny(norm))
                return {Action::BLOCK, "JDESER-003", "JavaDeser", "Java deserialization gadget", norm};
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- PHP 反序列化检测器：serialize 对象字面量 / __wakeup / __destruct ----
class PhpDeserializationDetector : public IDetector {
public:
    PhpDeserializationDetector() {
        for (auto& p : {"__wakeup", "__destruct", "__construct", "__tostring",
                         "__call", "__get", "__set", "phar://"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "PhpDeser"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<PhpDeserializationDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            // PHP 序列化对象字面量：O:<len>:"<class>":<n>:{...}
            if (hasPhpSerializedObject(norm))
                return {Action::BLOCK, "PDESER-001", "PhpDeser", "PHP serialized object literal", norm};
            std::string low = norm; for (auto& c : low) c = (char)std::tolower((unsigned char)c);
            if (ac_.containsAny(low))
                return {Action::BLOCK, "PDESER-002", "PhpDeser", "PHP magic method / phar deserialization", norm};
        }
        return {};
    }
private:
    // 匹配 O:数字:" 或 C:数字:"（PHP 对象/可序列化类开头，normalize 后已统一小写），并含 ":{" / "s:"
    static bool hasPhpSerializedObject(const std::string& s) {
        for (size_t i = 0; i + 4 < s.size(); ++i) {
            char c0 = (char)std::tolower((unsigned char)s[i]);
            if ((c0 == 'o' || c0 == 'c') && s[i+1] == ':') {
                size_t j = i + 2;
                if (j < s.size() && s[j] == '+') ++j;
                size_t d = j;
                while (d < s.size() && std::isdigit((unsigned char)s[d])) ++d;
                if (d > j && d + 1 < s.size() && s[d] == ':' && s[d+1] == '"') {
                    if (s.find(":{", d) != std::string::npos || s.find("s:", d) != std::string::npos)
                        return true;
                }
            }
        }
        return false;
    }
    AcAutomaton ac_;
};

// ---- ASP/ASPX 代码注入检测器：vbscript/jscript/eval request ----
class AspCodeInjectionDetector : public IDetector {
public:
    AspCodeInjectionDetector() {
        for (auto& p : {"eval request", "execute request", "execute(request",
                         "eval(request", "response.write", "createobject(\"wscript",
                         "createobject(\"shell", "wscript.shell", "shell.application",
                         "server.createobject", "<%eval", "<%execute", "vbscript:",
                         "request.form", "request.querystring" ,"eval vbs", "executeglobal"})
            ac_.addPattern(p);
        ac_.build();
    }
    const char* name() const override { return "ASPCode"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<AspCodeInjectionDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        for (auto& payload : req.collectPayloads()) {
            std::string norm = Decoder::normalize(payload);
            for (auto& c : norm) c = (char)std::tolower((unsigned char)c);
            if (ac_.containsAny(norm))
                return {Action::BLOCK, "ASP-001", "ASPCode", "ASP/ASPX code injection", norm};
        }
        return {};
    }
private:
    AcAutomaton ac_;
};

// ---- CSRF 检测器：跨站状态变更请求缺少同源凭证/Token ----
// 对"改变状态"的方法(POST/PUT/DELETE/PATCH)做同源校验：存在 Referer/Origin 时必须是同源，
// 且带自定义防 CSRF 头(X-CSRF-Token/X-XSRF-TOKEN)的视为已防护直接放行；跨域且无 Token → 拦截。
class CsrfDetector : public IDetector {
public:
    CsrfDetector() = default;
    const char* name() const override { return "CSRF"; }
    std::unique_ptr<IDetector> clone() const override { return std::make_unique<CsrfDetector>(); }
    DetectionResult detect(const HttpRequest& req) override {
        // 只对状态变更方法校验；GET/HEAD/OPTIONS 不做（幂等/预检）
        std::string m = req.method; for (auto& c : m) c = (char)std::toupper((unsigned char)c);
        if (!(m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH")) return {};
        // 已带防 CSRF Token 头 → 视为业务已防护
        if (req.headers.count("X-CSRF-Token") || req.headers.count("X-XSRF-TOKEN") ||
            req.headers.count("X-Csrf-Token") || req.headers.count("X-Xsrf-Token"))
            return {};
        std::string host = headerCi(req, "Host");
        std::string origin = headerCi(req, "Origin");
        std::string referer = headerCi(req, "Referer");
        std::string src = !origin.empty() ? origin : referer;
        if (src.empty() || host.empty()) return {};  // 无来源头：交由浏览器 SameSite/业务处理，不拦
        std::string srcHost = hostOf(src);
        for (auto& c : srcHost) c = (char)std::tolower((unsigned char)c);
        std::string h = host; for (auto& c : h) c = (char)std::tolower((unsigned char)c);
        stripPort(h); stripPort(srcHost);
        if (!srcHost.empty() && !h.empty() && srcHost != h)
            return {Action::BLOCK, "CSRF-001", "CSRF", "Cross-site state-changing request without token", src};
        return {};
    }
private:
    static std::string headerCi(const HttpRequest& req, const std::string& name) {
        for (auto& [k, v] : req.headers) {
            std::string lk = k; for (auto& c : lk) c = (char)std::tolower((unsigned char)c);
            std::string ln = name; for (auto& c : ln) c = (char)std::tolower((unsigned char)c);
            if (lk == ln) return v;
        }
        return {};
    }
    static std::string hostOf(const std::string& url) {
        size_t p = url.find("://");
        std::string s = (p == std::string::npos) ? url : url.substr(p + 3);
        size_t slash = s.find('/');
        return slash == std::string::npos ? s : s.substr(0, slash);
    }
    static void stripPort(std::string& h) {
        size_t c = h.rfind(':');
        if (c != std::string::npos && h.find(']') == std::string::npos) h = h.substr(0, c);
    }
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
