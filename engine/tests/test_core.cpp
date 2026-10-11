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
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/ai_cache.h"
#include "novawaf/core/thread_pool.h"

#include <atomic>
#include <chrono>
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
    CHECK(pipe.detectorCount() == 10, "ten detectors loaded");
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

static void test_ddos_guard() {
    TEST("DdosGuard");
    using novawaf::DdosGuard;
    DdosGuard::Config cfg;
    cfg.maxConcurrentPerIp = 3;
    cfg.newConnPerSec = 5;
    cfg.reqPerSec = 10;
    cfg.banThreshold = 2;
    cfg.banSeconds = 60;
    cfg.slowTimeoutMs = 5000;
    DdosGuard g(cfg);

    // 1) 并发连接上限
    CHECK(g.onConnect("10.0.0.1"), "conn1 ok");
    CHECK(g.onConnect("10.0.0.1"), "conn2 ok");
    CHECK(g.onConnect("10.0.0.1"), "conn3 ok");
    CHECK(!g.onConnect("10.0.0.1"), "conn4 blocked (max concurrent)");
    g.onDisconnect("10.0.0.1");
    CHECK(g.onConnect("10.0.0.1"), "after disconnect, conn ok again");

    // 2) 新建连接速率（并发上限调高，单独测速率）
    DdosGuard::Config cfgRate = cfg;
    cfgRate.maxConcurrentPerIp = 100000;
    DdosGuard g2(cfgRate);
    int ok = 0;
    for (int i = 0; i < 10; ++i) if (g2.onConnect("10.0.0.2")) ok++;
    CHECK(ok == 5, "only 5 new conns/sec allowed");

    // 3) 请求速率
    DdosGuard g3(cfgRate);
    int rok = 0;
    for (int i = 0; i < 20; ++i) if (g3.onRequest("10.0.0.3")) rok++;
    CHECK(rok == 10, "only 10 req/sec allowed");

    // 4) 违规累计触发自动封禁，封禁后全部拒绝
    DdosGuard g4(cfg);
    for (int i = 0; i < 5; ++i) g4.onConnect("10.0.0.4");  // 触发多次违规
    CHECK(g4.bannedCount() >= 1, "auto-banned after threshold");
    CHECK(!g4.onRequest("10.0.0.4"), "banned ip rejected");
    CHECK(!g4.onConnect("10.0.0.4"), "banned ip connect rejected");

    // 5) 手动封禁/解封
    DdosGuard g5(cfg);
    CHECK(g5.onConnect("10.0.0.5"), "connect ok before ban");
    g5.ban("10.0.0.5", 60);
    CHECK(!g5.onConnect("10.0.0.5"), "rejected after manual ban");
    g5.unban("10.0.0.5");
    CHECK(g5.onConnect("10.0.0.5"), "allowed after unban");

    // 6) 不同 IP 互不影响
    DdosGuard g6(cfg);
    CHECK(g6.onConnect("10.0.0.6") && g6.onConnect("10.0.0.7"),
          "different ips independent");
}

static void test_llm_client() {
    TEST("LlmClient");
    using namespace novawaf;

    // 1) 未启用 → 直接降级返回空，不调用传输层
    {
        LlmConfig c; c.enabled = false;
        int calls = 0;
        LlmTransport t = [&](const std::string&){ calls++; return std::optional<std::string>("x"); };
        LlmClient cli(c, t);
        auto r = cli.chat("sys", "user");
        CHECK(!r.has_value(), "disabled client returns nullopt");
        CHECK(calls == 0, "disabled client never calls transport");
    }

    // 2) 正常调用 → 从响应 JSON 提取 content
    {
        LlmConfig c; c.enabled = true;
        std::string sentBody;
        LlmTransport t = [&](const std::string& body){
            sentBody = body;
            return std::optional<std::string>(
                "{\"choices\":[{\"message\":{\"content\":\"{\\\"block\\\":true}\"}}]}");
        };
        LlmClient cli(c, t);
        auto r = cli.chat("SYS", "hello \"world\"");
        CHECK(r.has_value(), "got response");
        CHECK(*r == "{\"block\":true}", "content extracted");
        // 确认请求体里用户输入被 JSON 转义
        CHECK(sentBody.find("hello \\\"world\\\"") != std::string::npos, "user input escaped in body");
    }

    // 3) 传输层失败 → 重试后返回空（降级）
    {
        LlmConfig c; c.enabled = true; c.maxRetries = 2;
        int calls = 0;
        LlmTransport t = [&](const std::string&){ calls++; return std::nullopt; };
        LlmClient cli(c, t);
        auto r = cli.chat("s", "u");
        CHECK(!r.has_value(), "transport failure degrades to nullopt");
        CHECK(calls == 3, "retried maxRetries+1 times");
    }

    // 4) jsonEscape 防注入
    CHECK(jsonEscape("a\"b\\c\n") == "a\\\"b\\\\c\\n", "json escape");
}

static void test_ai_detector() {
    TEST("AiDetector");
    using namespace novawaf;

    HttpRequest req;
    req.method = "GET";
    req.path = "/search";
    req.query = "q=' OR 1=1--";

    // AI 判定攻击 → 拦截
    {
        LlmConfig c; c.enabled = true;
        LlmTransport t = [&](const std::string&){
            return std::optional<std::string>(
                "{\"choices\":[{\"message\":{\"content\":"
                "\"{\\\"block\\\":true,\\\"category\\\":\\\"SQLi\\\",\\\"reason\\\":\\\"tautology\\\"}\"}}]}");
        };
        auto llm = std::make_shared<LlmClient>(c, t);
        AiDetector ai(llm);
        auto r = ai.detect(req);
        CHECK(r.action == Action::BLOCK, "ai blocks attack");
        CHECK(r.category == "SQLi", "ai category");
        CHECK(std::string(ai.name()) == "AI", "detector name");
    }

    // AI 判定非攻击 + 规则误报 → 二阶复核应放行
    {
        DetectionPipeline pipe;
        HttpRequest blocked;
        blocked.method = "GET"; blocked.path = "/x"; blocked.query = "id=1' or '1'='1";
        auto base = pipe.detect(blocked);
        CHECK(base.action == Action::BLOCK, "rule blocks it first");

        LlmConfig c; c.enabled = true;
        LlmTransport t = [&](const std::string&){
            return std::optional<std::string>(
                "{\"choices\":[{\"message\":{\"content\":"
                "\"{\\\"block\\\":false,\\\"category\\\":\\\"Benign\\\",\\\"reason\\\":\\\"fp\\\"}\"}}]}");
        };
        auto llm = std::make_shared<LlmClient>(c, t);
        auto ai = std::make_shared<AiDetector>(llm);
        auto reviewed = detectWithAiReview(pipe, ai, blocked);
        CHECK(reviewed.action == Action::PASS, "ai review overrules false positive");
    }

    // AI 不可用 → 复核维持规则结果（fail-closed）
    {
        DetectionPipeline pipe;
        HttpRequest blocked;
        blocked.method = "GET"; blocked.path = "/x"; blocked.query = "id=1' or '1'='1";
        LlmConfig c; c.enabled = false;  // AI 关闭
        auto llm = std::make_shared<LlmClient>(c, LlmTransport{});
        auto ai = std::make_shared<AiDetector>(llm);
        auto reviewed = detectWithAiReview(pipe, ai, blocked);
        CHECK(reviewed.action == Action::BLOCK, "degraded keeps rule block (fail-closed)");
    }
}

static void test_ai_cache() {
    TEST("AiCache");
    using namespace novawaf;
    AiCache cache(300, 2);  // ttl 300s, 容量2

    HttpRequest a; a.method = "GET"; a.path = "/p"; a.query = "q=1";
    HttpRequest b; b.method = "GET"; b.path = "/p"; b.query = "q=2";
    HttpRequest c; c.method = "GET"; c.path = "/p"; c.query = "q=3";

    std::string ka = AiCache::makeKey(a);
    std::string kb = AiCache::makeKey(b);
    CHECK(ka != kb, "different payload -> different key");
    CHECK(AiCache::makeKey(a) == ka, "same payload -> stable key");

    CHECK(!cache.get(ka).has_value(), "miss before put");
    DetectionResult block{Action::BLOCK, "AI-001", "SQLi", "x", "y"};
    cache.put(ka, block);
    auto hit = cache.get(ka);
    CHECK(hit.has_value() && hit->action == Action::BLOCK, "hit returns cached block");

    // 容量上限 2：放入 b、c 后应淘汰
    cache.put(kb, block);
    cache.put(AiCache::makeKey(c), block);
    CHECK(cache.size() <= 2, "cache respects max entries");
}

static void test_ai_async() {
    TEST("AiDetector async (non-blocking)");
    using namespace novawaf;

    // 传输层：第一次调用会阻塞 200ms 模拟慢 AI，计数调用次数
    auto calls = std::make_shared<std::atomic<int>>(0);
    LlmConfig cfg; cfg.enabled = true; cfg.maxRetries = 0;
    LlmTransport t = [calls](const std::string&) -> std::optional<std::string> {
        (*calls)++;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return std::string(
            "{\"choices\":[{\"message\":{\"content\":"
            "\"{\\\"block\\\":true,\\\"category\\\":\\\"SQLi\\\",\\\"reason\\\":\\\"r\\\"}\"}}]}");
    };
    auto llm = std::make_shared<LlmClient>(cfg, t);
    auto ai = std::make_shared<AiDetector>(llm);
    auto cache = std::make_shared<AiCache>(300, 1000);
    auto pool = std::make_shared<ThreadPool>(2, 1024);
    pool->start();
    ai->setCache(cache);
    ai->setExecutor(pool);
    CHECK(ai->asyncReady(), "async ready when cache+executor set");

    HttpRequest req; req.method = "GET"; req.path = "/x"; req.query = "q=' OR 1=1";

    // 第 1 次：未命中 → 立即返回 nullopt（不阻塞 200ms），并异步提交任务
    auto t0 = std::chrono::steady_clock::now();
    auto r1 = ai->analyzeNonBlocking(req);
    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    CHECK(!r1.has_value(), "first call is non-blocking miss");
    CHECK(dt < 100, "non-blocking returns fast (<100ms)");

    // 等待后台 AI 完成并填充缓存
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK(calls->load() >= 1, "async task called the LLM");

    // 第 2 次相同 payload：缓存命中 → 秒回拦截，且不再调用 LLM
    int before = calls->load();
    auto r2 = ai->analyzeNonBlocking(req);
    CHECK(r2.has_value() && r2->action == Action::BLOCK, "second call hits cache -> block");
    CHECK(calls->load() == before, "cache hit does NOT call LLM again");
    CHECK(ai->cacheHits() >= 1, "cache hit counter incremented");

    pool->stop();
}

static void test_new_detectors() {
    TEST("NewDetectors");
    using namespace novawaf;

    auto mkReq = [](const std::string& q) {
        HttpRequest r; r.method = "GET"; r.path = "/x"; r.query = q;
        r.headers["User-Agent"] = "curl/7.0";
        return r;
    };

    { SstiDetector d; auto r = d.detect(mkReq("name={{7*7}}"));
      CHECK(r.action == Action::BLOCK && r.category == "SSTI", "SSTI {{7*7}}"); }
    { SstiDetector d; auto r = d.detect(mkReq("name=hello"));
      CHECK(r.action == Action::PASS, "SSTI benign pass"); }

    { XxeDetector d; HttpRequest r; r.method="POST"; r.path="/x"; r.body="<!ENTITY xxe SYSTEM>";
      CHECK(d.detect(r).action == Action::BLOCK, "XXE entity"); }

    { SsrfDetector d; auto r = d.detect(mkReq("url=http://169.254.169.254/"));
      CHECK(r.action == Action::BLOCK && r.category == "SSRF", "SSRF metadata"); }
    { SsrfDetector d; auto r = d.detect(mkReq("url=gopher://x"));
      CHECK(r.action == Action::BLOCK, "SSRF gopher scheme"); }

    { CrlfDetector d; auto r = d.detect(mkReq("next=http://a/%0d%0aSet-Cookie:x=1"));
      CHECK(r.action == Action::BLOCK, "CRLF header injection"); }

    { InfoLeakDetector d; HttpRequest r; r.method="GET"; r.path="/.env"; r.headers["User-Agent"]="x";
      CHECK(d.detect(r).action == Action::BLOCK, "InfoLeak .env"); }

    { ScannerDetector d; HttpRequest r; r.method="GET"; r.path="/"; r.headers["User-Agent"]="sqlmap/1.5";
      CHECK(d.detect(r).action == Action::BLOCK, "Scanner sqlmap UA"); }
    { ScannerDetector d; HttpRequest r; r.method="GET"; r.path="/"; r.headers["User-Agent"]="Mozilla/5.0";
      CHECK(d.detect(r).action == Action::PASS, "Scanner benign UA pass"); }
}

static void test_threat_intel() {
    TEST("ThreatIntel");
    using namespace novawaf;

    ThreatIntel ti(TiSeverity::HIGH);  // >=HIGH 拦截，MEDIUM 挑战，LOW 记录
    size_t n = ti.loadFromLines({
        "# comment",
        "ip,203.0.113.66,critical,botnet,c2",
        "cidr,198.51.100.0/24,high,scanner,scan range",
        "path,/wp-admin,critical,webshell,wp admin",
        "domain,evil.com,high,c2,bad domain",
        "ua,nikto,high,scanner,nikto",
        "signature,exec xp_cmdshell,critical,sqli,mssql exec",
        "garbage line",
    });
    CHECK(n == 6, "parsed 6 valid IOCs");
    CHECK(ti.count() == 6, "count matches");

    // 1) 恶意 IP 精确命中 → critical → BLOCK
    { HttpRequest r; r.clientIp = "203.0.113.66";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "malicious ip blocked"); }

    // 2) CIDR 命中（段内任意 IP）→ high → BLOCK
    { HttpRequest r; r.clientIp = "198.51.100.42";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "cidr match blocked"); }
    // 段外不应命中
    { HttpRequest r; r.clientIp = "198.51.101.5";
      CHECK(!ti.match(r).has_value(), "cidr out-of-range not matched"); }

    // 3) 路径命中
    { HttpRequest r; r.path = "/wp-admin/login.php";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "path ioc blocked"); }

    // 4) 域名命中（Host 头）
    { HttpRequest r; r.path="/"; r.headers["Host"]="evil.com";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "domain ioc blocked"); }

    // 5) UA 命中
    { HttpRequest r; r.path="/"; r.headers["User-Agent"]="Nikto/2.1.6";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "ua ioc blocked"); }

    // 6) 攻击签名命中（出现在 query）
    { HttpRequest r; r.path="/x"; r.query="q=exec xp_cmdshell";
      auto m = ti.match(r); CHECK(m && m->action == Action::BLOCK, "signature ioc blocked"); }

    // 7) 正常流量不命中
    { HttpRequest r; r.clientIp="8.8.8.8"; r.path="/index.html";
      CHECK(!ti.match(r).has_value(), "clean traffic no match"); }

    // 8) 热更新：reload 后旧数据被替换
    ti.loadFromLines({"ip,1.2.3.4,high,x,x"});
    CHECK(ti.count() == 1, "reload replaces dataset");
    { HttpRequest r; r.clientIp="203.0.113.66";
      CHECK(!ti.match(r).has_value(), "old ioc gone after reload"); }
    { HttpRequest r; r.clientIp="1.2.3.4";
      CHECK(ti.match(r)->action == Action::BLOCK, "new ioc active after reload"); }

    // 9) 分级：MEDIUM → CHALLENGE
    ThreatIntel ti2(TiSeverity::HIGH);
    ti2.loadFromLines({"ua,slowika,medium,bot,slow bot"});
    { HttpRequest r; r.path="/"; r.headers["User-Agent"]="slowika";
      auto m = ti2.match(r); CHECK(m && m->action == Action::CHALLENGE, "medium -> challenge"); }
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
    test_ddos_guard();
    test_llm_client();
    test_ai_detector();
    test_ai_cache();
    test_ai_async();
    test_new_detectors();
    test_threat_intel();

    std::printf("\n=======================\n");
    std::printf("PASS: %d  FAIL: %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
