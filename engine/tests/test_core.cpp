// NovaWAF - 核心逻辑单元测试（平台无关，Windows/Linux 均可编译运行）
// 自带极简测试框架，无第三方依赖。
#include "novawaf/core/buffer.h"
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/detect/http_model.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; std::printf("  [FAIL] %s (line %d)\n", msg, __LINE__); } \
} while(0)

#define TEST(name) std::printf("== %s ==\n", name)

static void test_ac_automaton() {
    TEST("AcAutomaton");
    novawaf::AcAutomaton ac;
    ac.addPattern("select");
    ac.addPattern("union");
    ac.addPattern("<script");
    ac.build();
    CHECK(ac.patternCount() == 3, "pattern count");
    auto hits = ac.scan("hello select world union");
    CHECK(hits.size() == 2, "two hits");
    CHECK(ac.containsAny("foo <script>bar") == true, "contains script");
    CHECK(ac.containsAny("hello world") == false, "no hit clean");
}

static void test_decoder() {
    TEST("Decoder");
    // URL decode
    CHECK(novawaf::Decoder::urlDecode("%3cscript%3e") == "<script>", "url decode");
    // HTML entity
    CHECK(novawaf::Decoder::htmlEntityDecode("&lt;script&gt;") == "<script>", "html entity");
    // 大小写归一
    std::string s = "UNION SELECT";
    novawaf::Decoder::toLowerInPlace(s);
    CHECK(s == "union select", "tolower");
    // 归一化：编码嵌套绕过
    std::string norm = novawaf::Decoder::normalize("%253cscript%253e");
    CHECK(norm.find("script") != std::string::npos, "nested url decode");
    // base64: "PHNjcmlwdD4=" 是 "<script>" 的 base64
    std::string b64 = novawaf::Decoder::tryBase64Decode("PHNjcmlwdD4=");
    CHECK(b64.find("script") != std::string::npos, "base64 decode");
}

static void test_detectors() {
    TEST("Detectors");
    novawaf::SqlInjectionDetector sqli;
    novawaf::HttpRequest req;
    req.query = "id=1 union select password from users";
    auto r = sqli.detect(req);
    CHECK(r.isBlocked(), "sqli blocked");
    CHECK(r.category == "SQLi", "sqli category");

    novawaf::HttpRequest clean;
    clean.query = "q=hello+world";
    auto r2 = sqli.detect(clean);
    CHECK(!r2.isBlocked(), "clean not blocked");

    // XSS
    novawaf::XssDetector xss;
    novawaf::HttpRequest xreq;
    xreq.query = "q=<script>alert(1)</script>";
    CHECK(xss.detect(xreq).isBlocked(), "xss blocked");

    // RCE
    novawaf::CommandInjectionDetector rce;
    novawaf::HttpRequest rreq;
    rreq.query = "cmd=;ls /etc/passwd";
    CHECK(rce.detect(rreq).isBlocked(), "rce blocked");

    // Traversal
    novawaf::PathTraversalDetector trav;
    novawaf::HttpRequest treq;
    treq.path = "/download?file=../../etc/passwd";
    CHECK(trav.detect(treq).isBlocked(), "traversal blocked");
}

static void test_pipeline() {
    TEST("Pipeline");
    novawaf::DetectionPipeline pipe;
    CHECK(pipe.detectorCount() == 4, "four detectors loaded");
    novawaf::HttpRequest req;
    req.query = "id=1' or '1'='1";
    auto r = pipe.detect(req);
    CHECK(r.isBlocked(), "pipeline blocks sqli");

    novawaf::HttpRequest clean;
    clean.path = "/index.html";
    clean.query = "name=tom";
    CHECK(!pipe.detect(clean).isBlocked(), "pipeline passes clean");
}

static void test_rate_limiter() {
    TEST("RateLimiter");
    novawaf::RateLimiter rl(5, 100);  // 桶容量5，每秒补100
    int allowed = 0;
    for (int i = 0; i < 10; ++i) {
        if (rl.allow("1.2.3.4")) allowed++;
    }
    CHECK(allowed == 5, "burst of 5 allowed");
    // 不同 key 独立
    CHECK(rl.allow("5.6.7.8") == true, "other ip allowed");
}

static void test_http_parser() {
    TEST("HttpParser");
    novawaf::HttpParser parser;
    std::string raw =
        "GET /search?q=%3cscript%3e&x=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: curl/7.0\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    auto st = parser.feed(raw);
    CHECK(st == novawaf::HttpParser::State::DONE, "parse done");
    auto req = parser.request();
    CHECK(req.method == "GET", "method");
    CHECK(req.path == "/search", "path");
    CHECK(req.query == "q=%3cscript%3e&x=1", "query");
    CHECK(req.body == "hello", "body");
    CHECK(req.headers["Host"] == "example.com", "host header");
    CHECK(req.queryParams.size() == 2, "two query params");
}

static void test_mpmc_queue() {
    TEST("MpmcQueue");
    novawaf::MpmcQueue<int> q(8);
    CHECK(q.enqueue(1), "enqueue 1");
    CHECK(q.enqueue(2), "enqueue 2");
    int v;
    CHECK(q.dequeue(v) && v == 1, "dequeue 1");
    CHECK(q.dequeue(v) && v == 2, "dequeue 2");
    CHECK(!q.dequeue(v), "empty now");
}

static void test_buffer() {
    TEST("Buffer");
    novawaf::Buffer buf;
    buf.append("hello", 5);
    CHECK(buf.readableBytes() == 5, "readable 5");
    CHECK(buf.toStringView() == "hello", "content");
    buf.retrieve(5);
    CHECK(buf.readableBytes() == 0, "empty after retrieve");
}

int main() {
    std::printf("NovaWAF Core Unit Tests\n");
    std::printf("=======================\n\n");
    test_ac_automaton();
    test_decoder();
    test_detectors();
    test_pipeline();
    test_rate_limiter();
    test_http_parser();
    test_mpmc_queue();
    test_buffer();

    std::printf("\n=======================\n");
    std::printf("PASS: %d  FAIL: %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
