// NovaWAF - 核心逻辑单元测试（平台无关，Windows/Linux 均可编译运行）
// 自带极简测试框架，无第三方依赖。
#include "novawaf/core/buffer.h"
#include "novawaf/core/json.h"
#include "novawaf/core/mpmc_queue.h"
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/detect/decoder.h"
#include "novawaf/detect/detectors.h"
#include "novawaf/detect/custom_rules.h"
#include "novawaf/detect/pipeline.h"
#include "novawaf/detect/http_model.h"
#include "novawaf/detect/threat_intel.h"
#include "novawaf/protect/cc_guard.h"
#include "novawaf/protect/bot_guard.h"
#include "novawaf/protect/dynamic_shield.h"
#include "novawaf/protect/fingerprint.h"
#include "novawaf/protect/geo_filter.h"
#include "novawaf/protect/tamper_cache.h"
#include "novawaf/limit/rate_limiter.h"
#include "novawaf/net/http_parser.h"
#include "novawaf/ddos/ddos_guard.h"
#include "novawaf/ai/llm_client.h"
#include "novawaf/ai/ai_detector.h"
#include "novawaf/ai/ai_cache.h"
#include "novawaf/core/thread_pool.h"
#include "novawaf/accel/teddy.h"
#include "novawaf/accel/accel_runtime.h"

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
    CHECK(pipe.detectorCount() == 16, "sixteen detectors loaded");
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

static void test_fingerprint() {
    TEST("Fingerprint");
    using namespace novawaf;

    // HTTP 指纹稳定性：相同头部集合 → 相同指纹
    std::unordered_map<std::string,std::string> h1{{"User-Agent","x"},{"Accept","*/*"}};
    std::unordered_map<std::string,std::string> h2{{"accept","*/*"},{"user-agent","x"}};
    std::string f1 = httpFingerprint("GET", h1);
    std::string f2 = httpFingerprint("GET", h2);
    CHECK(f1 == f2, "http fingerprint stable regardless of header order/case");
    CHECK(!f1.empty() && f1[0] == 'h', "http fingerprint format");

    // JA4：构造一个最小 ClientHello（TLS 1.2，含 SNI + ALPN 扩展）
    std::vector<uint8_t> ch;
    auto u16 = [&](uint16_t v){ ch.push_back(v>>8); ch.push_back(v&0xFF); };
    // handshake header (type 0x01, len filled later)
    size_t hsStart = ch.size();
    ch.push_back(0x01); ch.push_back(0); ch.push_back(0); ch.push_back(0);
    u16(0x0303);                       // legacy version TLS1.2
    for (int i=0;i<32;i++) ch.push_back((uint8_t)i);  // random
    ch.push_back(0);                    // session id len 0
    u16(4); u16(0x1301); u16(0x1302);   // 2 cipher suites
    ch.push_back(1); ch.push_back(0);   // compression
    // extensions block
    size_t extStart = ch.size();
    u16(0); // placeholder ext total len
    u16(0);   u16(0);  // SNI ext (type0, len0)
    u16(16);  u16(0);  // ALPN ext (type16, len0)
    size_t extEnd = ch.size();
    // fill ext total len
    ch[extStart]   = (uint8_t)((extEnd-extStart-2)>>8);
    ch[extStart+1] = (uint8_t)((extEnd-extStart-2)&0xFF);
    // fill handshake len
    uint32_t hsLen = extEnd - hsStart - 4;
    ch[hsStart+1] = (uint8_t)(hsLen>>16);
    ch[hsStart+2] = (uint8_t)(hsLen>>8);
    ch[hsStart+3] = (uint8_t)(hsLen&0xFF);

    std::string ja4 = ja4FromClientHello(ch.data(), ch.size());
    CHECK(!ja4.empty(), "ja4 parsed from clienthello");
    CHECK(ja4.rfind("t12", 0) == 0, "ja4 version token t12");  // TLS1.2 → d? actually map
    // 同一字节流重复计算 → 稳定
    CHECK(ja4 == ja4FromClientHello(ch.data(), ch.size()), "ja4 deterministic");
    // 解析失败（空/垃圾）返回空
    std::vector<uint8_t> junk{0x16,0x03};
    CHECK(ja4FromClientHello(junk.data(), junk.size()).empty(), "ja4 garbage -> empty");
}

static void test_cc_guard() {
    TEST("CcGuard");
    using namespace novawaf;

    CcGuard::Config cfg;
    cfg.windowMs = 1000; cfg.maxReqPerWindow = 10; cfg.burstPerUrl = 6;
    cfg.hotUrlGlobal = 1000; cfg.scoreToChallenge = 40; cfg.scoreToBlock = 100;
    CcGuard cc(cfg);

    // 正常低频 → PASS
    for (int i = 0; i < 5; ++i)
        CHECK(cc.assess("1.1.1.1", "/a").action == Action::PASS, "low rate pass");

    // 单 IP 速率超限 → 至少 CHALLENGE
    Action worst = Action::PASS;
    for (int i = 0; i < 25; ++i) {
        auto r = cc.assess("9.9.9.9", "/b");
        if ((int)r.action > (int)worst) worst = r.action;
    }
    CHECK((int)worst >= (int)Action::CHALLENGE, "high rate triggers challenge/block");

    // 单 IP 狂刷同一 URL → 触发
    CcGuard cc2(cfg);
    Action w2 = Action::PASS;
    for (int i = 0; i < 20; ++i) {
        auto r = cc2.assess("8.8.8.8", "/hot");
        if ((int)r.action > (int)w2) w2 = r.action;
    }
    CHECK((int)w2 >= (int)Action::CHALLENGE, "url burst triggers action");

    // 动态收紧：applyThreatLevel 后阈值下降，更容易触发
    CcGuard cc3(cfg);
    cc3.applyThreatLevel((int)ThreatLevel::SEVERE);  // factor≈0.216
    Action w3 = Action::PASS;
    for (int i = 0; i < 6; ++i) {
        auto r = cc3.assess("7.7.7.7", "/x");
        if ((int)r.action > (int)w3) w3 = r.action;
    }
    CHECK((int)w3 >= (int)Action::CHALLENGE, "tightened threshold triggers earlier");
}

static void test_bot_guard() {
    TEST("BotGuard");
    using namespace novawaf;

    BotGuard bot(BotGuard::Config{});

    // 裸请求（无 UA/无 Accept）→ 应被判定
    HttpRequest r1; r1.method="GET"; r1.path="/";
    auto a1 = bot.assess(r1);
    CHECK((int)a1.action >= (int)Action::CHALLENGE, "bare request flagged as bot");

    // 完整浏览器请求（含 UA/Accept/sec-ch-ua）→ PASS
    HttpRequest r2; r2.method="GET"; r2.path="/";
    r2.headers["User-Agent"] = "Mozilla/5.0 Chrome/120";
    r2.headers["Accept"] = "text/html";
    r2.headers["Accept-Language"] = "en-US";
    r2.headers["Accept-Encoding"] = "gzip";
    r2.headers["sec-ch-ua"] = "\"Chromium\"";
    auto a2 = bot.assess(r2);
    CHECK(a2.action == Action::PASS, "browser-like request passes");

    // 声明现代 UA 但无客户端提示头 → 触发
    HttpRequest r3; r3.method="GET"; r3.path="/";
    r3.headers["User-Agent"] = "Mozilla/5.0 Chrome/120";
    r3.headers["Accept"] = "text/html";
    auto a3 = bot.assess(r3);
    CHECK((int)a3.action >= (int)Action::CHALLENGE, "modern ua without hints flagged");
}

static void test_dynamic_shield() {
    TEST("DynamicShield");
    using namespace novawaf;

    DynamicShield::Config cfg;
    cfg.sampleMs = 100; cfg.elevatedQps = 50; cfg.highQps = 200; cfg.severeQps = 1000;
    DynamicShield shield(cfg);
    std::atomic<int> calls{0};
    ThreatLevel seen = ThreatLevel::NORMAL;
    shield.observe([&](ThreatLevel l){ if ((int)l > (int)seen) seen = l; calls++; });
    shield.start();
    // 持续注入请求 + 拦截（覆盖整个采样窗口），应触发升级
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
    while (std::chrono::steady_clock::now() < deadline) {
        for (int i = 0; i < 2000; ++i) { shield.recordRequest(); shield.recordBlock(); }
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    shield.stop();
    CHECK((int)seen >= (int)ThreatLevel::ELEVATED, "shield escalates under load");
    CHECK(calls.load() >= 1, "observer callback fired");
}

static void test_ti_fingerprint() {
    TEST("TiFingerprint");
    using namespace novawaf;

    ThreatIntel ti(TiSeverity::HIGH);
    ti.loadFromLines({
        "ja4,t12di_8daaf6152771_e5627efa2ab1,critical,bot,known bot JA4",
        "fingerprint,h0123456789ab,high,bot,bad http fp",
    });
    HttpRequest req; req.clientIp = "8.8.8.8"; req.path = "/";
    // JA4 命中
    auto m = ti.match(req, "t12di_8daaf6152771_e5627efa2ab1", "");
    CHECK(m && m->action == Action::BLOCK, "ja4 blacklist blocks");
    // HTTP 指纹命中
    auto m2 = ti.match(req, "", "h0123456789ab");
    CHECK(m2 && m2->action == Action::BLOCK, "http fp blacklist blocks");
    // 干净指纹不命中
    CHECK(!ti.match(req, "t13d_aaaaaaaaaaaa_bbbbbbbbbbbb", "hfedcba").has_value(), "clean fp passes");
}

static void test_geo_filter() {
    TEST("GeoFilter");
    using namespace novawaf;

    GeoFilter geo;
    size_t n = geo.loadFromLines({
        "# comment",
        "8.8.8.0/24,US,Google",
        "114.114.114.0/24,CN,dns",
        "1.1.1.0/24,AU,cf",
        "203.0.113.0/24,us,TEST",  // 小写 cc 应被归一为大写
        "garbage",
    });
    CHECK(n == 4, "parsed 4 valid cidr ranges");
    CHECK(geo.rangeCount() == 4, "range count matches");

    // 未启用 → 一律放行
    CHECK(!geo.assess("8.8.8.8").has_value(), "disabled -> pass");

    // 黑名单模式
    geo.setEnabled(true);
    geo.setBlockedCountries({"CN", "RU"});
    auto m = geo.assess("114.114.114.114");
    CHECK(m && m->action == Action::BLOCK && m->matched.find("CN") != std::string::npos,
          "blacklist blocks CN");
    CHECK(m && m->category == "GeoBlock", "category GeoBlock");
    // 小写 cc 归一：203.0.113.5 → US，不在黑名单 → 放行
    CHECK(!geo.assess("203.0.113.5").has_value(), "US not in blacklist -> pass");
    // 未知国家 → 默认放行
    CHECK(!geo.assess("9.9.9.9").has_value(), "unknown country -> pass");

    // 私有/保留地址永远放行（即使在配置了封锁的模式下）
    CHECK(!geo.assess("192.168.1.1").has_value(), "private 192.168 pass");
    CHECK(!geo.assess("10.0.0.5").has_value(), "private 10/8 pass");
    CHECK(!geo.assess("127.0.0.1").has_value(), "loopback pass");
    CHECK(!geo.assess("172.16.0.1").has_value(), "private 172.16 pass");
    CHECK(!geo.assess("169.254.1.1").has_value(), "link-local pass");

    // 白名单模式：仅放行 CN
    geo.setMode(GeoMode::WHITELIST);
    geo.setAllowedCountries({"CN"});
    CHECK(!geo.assess("114.114.114.114").has_value(), "whitelist CN -> pass");
    auto w = geo.assess("8.8.8.8");
    CHECK(w && w->action == Action::BLOCK, "whitelist blocks non-CN US");
    // 白名单对未知国家放行（保守）
    CHECK(!geo.assess("9.9.9.9").has_value(), "whitelist unknown -> pass");

    // 热更新：reload 替换数据集
    geo.setMode(GeoMode::BLACKLIST);
    geo.setBlockedCountries({"AU"});
    geo.loadFromLines({"8.8.8.0/24,US,x"});  // 只剩 US 段
    CHECK(geo.rangeCount() == 1, "reload replaces dataset");
    CHECK(!geo.assess("1.1.1.1").has_value(), "old AU range gone after reload");
}

static void test_json() {
    TEST("Json");
    using namespace novawaf;
    // 控制台写出的真实规则 JSON 格式
    std::string j = R"([{"id":1,"name":"block-sqli","pattern":"union select","action":"block","category":"sqli","enabled":true},{"id":2,"name":"noop","pattern":"","action":"log","category":"x","enabled":false}])";
    auto root = parseJson(j);
    CHECK(root.isArray(), "root is array");
    CHECK(root.arr.size() == 2, "two rules");
    CHECK(root.arr[0].at("name").str == "block-sqli", "name field");
    CHECK(root.arr[0].at("id").num == 1, "id field");
    CHECK(root.arr[0].at("enabled").b == true, "enabled bool");
    CHECK(root.arr[1].at("enabled").b == false, "disabled bool");
    // 转义
    auto s = parseJson(R"({"a":"he said \"hi\"\nline2"})");
    CHECK(s.at("a").str == "he said \"hi\"\nline2", "string escapes");
    // 空值
    auto e = parseJson("[]");
    CHECK(e.isArray() && e.arr.empty(), "empty array");
}

static void test_custom_rules() {
    TEST("CustomRule");
    using namespace novawaf;
    CustomRuleDetector det;
    // 空集不命中
    HttpRequest clean; clean.path = "/index"; clean.query = ""; clean.body = "";
    CHECK(det.detect(clean).action == Action::PASS, "empty set passes");

    // 加载控制台格式 JSON
    std::string j = R"([{"id":1,"name":"block-sqli","pattern":"union select","action":"block","category":"sqli","enabled":true},{"id":2,"name":"log-only","pattern":"foobar","action":"log","category":"probe","enabled":true},{"id":3,"name":"off","pattern":"zzz","action":"block","category":"x","enabled":false}])";
    size_t n = det.reload(j);
    CHECK(n == 2, "two enabled rules loaded (disabled skipped)");
    CHECK(det.enabledCount() == 2, "enabled count");

    // 命中 block
    HttpRequest evil; evil.path = "/"; evil.query = "id=1 union select password"; evil.body = "";
    auto r = det.detect(evil);
    CHECK(r.action == Action::BLOCK, "union select blocked");
    CHECK(r.category == "sqli", "category sqli");
    CHECK(r.ruleId == "CUSTOM-1", "rule id CUSTOM-1");

    // 命中 log
    HttpRequest logreq; logreq.path = "/"; logreq.query = "x=foobar"; logreq.body = "";
    auto r2 = det.detect(logreq);
    CHECK(r2.action == Action::LOG, "foobar logs");

    // 禁用规则不命中
    HttpRequest off; off.path = "/"; off.query = "x=zzz"; off.body = "";
    CHECK(det.detect(off).action == Action::PASS, "disabled rule ignored");

    // 热更新：移除规则后 clone 副本应同步看到（共享原子）
    auto clone = det.clone();
    det.reload("[]");
    CHECK(det.enabledCount() == 0, "reload clears");
    HttpRequest evil2; evil2.path = "/"; evil2.query = "union select"; evil2.body = "";
    CHECK(clone->detect(evil2).action == Action::PASS, "clone sees live reload");

    // 损坏 JSON 不崩溃，保留空集
    det.reload("not json at all");
    CHECK(det.enabledCount() == 0, "bad json -> empty, no crash");
    CHECK(det.detect(evil2).action == Action::PASS, "bad json keeps passing");
}

// ===================== 硬件加速（Teddy / 熔断 / AC 接入） =====================
namespace {
struct AclRng {
    uint64_t s = 0x9e3779b97f4a7c15ULL;
    uint32_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return (uint32_t)(s >> 32); }
};
std::string randText(AclRng& r, int maxLen, int alpha) {
    int n = (int)(r.next() % (uint32_t)(maxLen + 1));
    std::string t;
    t.reserve(n);
    for (int i = 0; i < n; ++i) t.push_back((char)('a' + r.next() % (uint32_t)alpha));
    return t;
}
// 定长随机串（用于模式，保证长度>=2，避免空串这种现实中不会出现的输入）
std::string fixedStr(AclRng& r, int n, int alpha) {
    std::string t;
    t.reserve(n);
    for (int i = 0; i < n; ++i) t.push_back((char)('a' + r.next() % (uint32_t)alpha));
    return t;
}
}  // namespace

// 随机 fuzz：标量 Teddy / 运行时分发(AVX2,SSE,标量) / 暴力子串，三者必须完全一致（零漏报零误报）
static void test_accel_teddy_fuzz() {
    TEST("Accel-Teddy-Fuzz(zero-miss)");
    using namespace novawaf::accel;
    AclRng r;
    long cases = 0;
    // 主 fuzz：模式长度>=2、字母表 5（最多 25 个不同首字节对），锚点必然可用
    for (int it = 0; it < 20000; ++it) {
        std::vector<std::string> pats;
        int np = 1 + r.next() % 10;
        for (int i = 0; i < np; ++i) {
            int L = 2 + r.next() % 4;  // 2..5
            pats.push_back(fixedStr(r, L, 5));
        }
        AnchorSet A;
        bool usable = A.build(pats);
        if (!usable) continue;  // 理论上不会（<=25 对），保险
        for (int q = 0; q < 4; ++q) {
            std::string t = randText(r, 96, 5);
            bool gold = bruteForceAny(pats, t);
            bool sc = scalarContains(t, A);
            bool disp = anchorContainsAny(t, A);  // x86 上为 AVX2/SSE
            CHECK(sc == gold, "scalar teddy == brute");
            CHECK(disp == gold, "dispatch(simd) teddy == brute");
            ++cases;
        }
    }
    // 边界长度扫描：覆盖 16/32 字节块边界与跨 lane 拼接，命中放在每个可能偏移
    for (int L = 0; L <= 80; ++L) {
        std::vector<std::string> pats = {"ab", "cde", "eebb"};
        AnchorSet A; A.build(pats);
        std::string t(L, 'c');
        for (size_t pos = 0; pos + 2 <= t.size(); ++pos) {
            std::string x = t;
            x[pos] = 'a'; x[pos + 1] = 'b';
            bool gold = bruteForceAny(pats, x);
            CHECK(scalarContains(x, A) == gold, "boundary scalar");
            CHECK(anchorContainsAny(x, A) == gold, "boundary dispatch");
        }
    }
    // 含单字节模式时锚点必须判定不可用（回退 AC，语义不变）
    {
        AnchorSet A;
        CHECK(A.build({"a", "bc"}) == false, "single-char pattern -> unusable");
    }
    // 超过 64 个不同首字节对 -> 不可用
    {
        std::vector<std::string> many;
        for (int i = 0; i < 70; ++i) many.push_back(std::string(1, (char)('A' + i / 10)) +
                                                  std::string(1, (char)('a' + i % 10)) + "z");
        AnchorSet A;
        CHECK(A.build(many) == false, ">64 anchors -> unusable");
    }
    std::printf("   (fuzz cases: %ld)\n", cases);
}

// AC 自动机在“加速关(AC) / 加速开(Teddy)”下结果必须一致且与暴力匹配一致
static void test_accel_ac_integration() {
    TEST("Accel-AcIntegration(on/off identical)");
    using namespace novawaf::accel;
    setEnabled(false);
    setActiveBackend(BackendKind::Scalar);
    AclRng r;
    for (int it = 0; it < 6000; ++it) {
        novawaf::AcAutomaton ac;
        std::vector<std::string> pats;
        int np = 1 + r.next() % 8;
        for (int i = 0; i < np; ++i) pats.push_back(fixedStr(r, 2 + r.next() % 4, 5));
        for (auto& p : pats) ac.addPattern(p);
        ac.build();
        std::string t = randText(r, 96, 5);
        bool gold = bruteForceAny(pats, t);

        setEnabled(false); setActiveBackend(BackendKind::Scalar);
        bool off = ac.containsAny(t);

        setEnabled(true); setActiveBackend(BackendKind::SimdAVX2);  // 非 SIMD 机器内部仍标量
        bool on = ac.containsAny(t);

        setEnabled(false); setActiveBackend(BackendKind::Scalar);

        CHECK(off == gold, "AC baseline == brute");
        CHECK(on == gold, "Teddy accel == brute");
        CHECK(off == on, "accel on/off identical");
    }
    // 真实攻击/干净样本端到端
    {
        novawaf::SqlInjectionDetector sqli;
        novawaf::HttpRequest req;
        req.query = "id=1 union select password from users";
        setEnabled(false);
        CHECK(sqli.detect(req).isBlocked(), "sqli blocked (accel off)");
        setEnabled(true); setActiveBackend(BackendKind::SimdAVX2);
        CHECK(sqli.detect(req).isBlocked(), "sqli blocked (accel on)");
        setEnabled(false); setActiveBackend(BackendKind::Scalar);
    }
}

// 批量接口与逐文本一致
static void test_accel_batch() {
    TEST("Accel-Batch");
    using namespace novawaf::accel;
    std::vector<std::string> pats = {"abc", "xy"};
    AnchorSet A; A.build(pats);
    std::vector<std::string> store = {"---abc---", "no hit", "xy!!", "ab", "zxy"};
    std::vector<std::string_view> views;
    for (auto& s : store) views.push_back(s);
    uint8_t out[8] = {0};
    batchAnchorContainsAny(views, A, out);
    bool expect[5] = {true, false, true, false, true};
    for (int i = 0; i < 5; ++i) CHECK((out[i] == 1) == expect[i], "batch hit per text");
}

// 熔断器状态转换
static void test_accel_circuit() {
    TEST("Accel-CircuitBreaker");
    using namespace novawaf::accel;
    CircuitBreaker cb;
    CHECK(cb.state() == BackendState::Closed, "initial closed");
    CHECK(cb.allow(), "closed allows");
    cb.failure(); cb.failure();
    CHECK(cb.state() == BackendState::Closed, "under threshold closed");
    cb.failure();
    CHECK(cb.state() == BackendState::Open, "threshold trips open");
    CHECK(!cb.allow(), "open blocks");
    cb.success();
    CHECK(cb.state() == BackendState::Closed, "success closes");
    cb.setUnavailable();
    CHECK(cb.state() == BackendState::Unavailable, "unavailable");
}

// 运行时自检（黄金样本）必须通过
static void test_accel_runtime_selftest() {
    TEST("Accel-Runtime-SelfTest");
    using namespace novawaf::accel;
    CHECK(AccelRuntime::instance().runSelfTest(), "golden selftest passes");
}

static void test_tamper_cache() {
    TEST("TamperCache");
    using novawaf::TamperCache;
    auto& tc = TamperCache::instance();
    tc.clear();
    TamperCache::Config c;
    c.enabled = true;
    c.ttlSec = 3600;
    c.maxBody = 64 * 1024;
    c.maxPages = 2;
    tc.configure(c);
    int events = 0;
    std::string evPath;
    tc.setEventHook([&](const std::string&, const std::string&, const std::string& p) {
        events++;
        evPath = p;
    });

    auto mkResp = [](const std::string& body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
               std::to_string(body.size()) + "\r\n\r\n" + body;
    };
    const std::string page1 = "<html><body>hello</body></html>";

    // 1. 首次观测 → 学习并放行
    CHECK(!tc.process("GET", "a.com", "/", mkResp(page1), "1.1.1.1").has_value(),
          "learn pass-through");
    CHECK(tc.size() == 1, "learned one page");
    // 2. 与基线一致 → 放行
    CHECK(!tc.process("GET", "a.com", "/", mkResp(page1), "1.1.1.2").has_value(),
          "identical pass");
    // 3. body 被篡改 → 返回基线 + 事件
    auto r3 = tc.process("GET", "a.com", "/", mkResp("<html><body>HACKED</body></html>"),
                         "2.2.2.2");
    CHECK(r3.has_value(), "tamper restored");
    CHECK(r3 && r3->find("hello") != std::string::npos, "restored baseline body");
    CHECK(events == 1 && evPath == "/", "tamper event emitted");
    // 4. 基线不被篡改页面投毒
    auto r4 = tc.process("GET", "a.com", "/", mkResp("<html><body>HACKED-2</body></html>"),
                         "2.2.2.3");
    CHECK(r4 && r4->find("hello") != std::string::npos, "baseline not poisoned");
    CHECK(events == 2, "second tamper event");
    // 5. 非 GET 不参与
    CHECK(!tc.process("POST", "a.com", "/p", mkResp("x"), "1.1.1.1").has_value(), "POST skip");
    CHECK(tc.size() == 1, "POST not learned");
    // 6. 非 200 不参与
    std::string r404 = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
                       "Content-Length: 3\r\n\r\nabc";
    CHECK(!tc.process("GET", "a.com", "/404", r404, "1.1.1.1").has_value(), "404 skip");
    CHECK(tc.size() == 1, "404 not learned");
    // 7. 非 html 不参与
    std::string js = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "Content-Length: 2\r\n\r\n{}";
    CHECK(!tc.process("GET", "a.com", "/api", js, "1.1.1.1").has_value(), "json skip");
    CHECK(tc.size() == 1, "json not learned");
    // 8. chunked 不参与（字节比较有歧义）
    std::string ch = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    CHECK(!tc.process("GET", "a.com", "/ch", ch, "1.1.1.1").has_value(), "chunked skip");
    CHECK(tc.size() == 1, "chunked not learned");
    // 9. 压缩响应不参与
    std::string gz = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n"
                     "Content-Length: 3\r\n\r\nabc";
    CHECK(!tc.process("GET", "a.com", "/gz", gz, "1.1.1.1").has_value(), "gzip skip");
    CHECK(tc.size() == 1, "gzip not learned");
    // 10. 超大 body 不参与
    std::string big = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 70000\r\n\r\n" +
                      std::string(70000, 'x');
    CHECK(!tc.process("GET", "a.com", "/big", big, "1.1.1.1").has_value(), "oversize skip");
    CHECK(tc.size() == 1, "oversize not learned");
    // 11. LRU 容量：maxPages=2，再学两页 → 最早的 / 被淘汰
    tc.process("GET", "a.com", "/b", mkResp("b"), "1.1.1.1");
    tc.process("GET", "a.com", "/c", mkResp("c"), "1.1.1.1");
    CHECK(tc.size() == 2, "lru cap holds");
    // / 已被淘汰 → 重新学习（放行而非恢复）
    CHECK(!tc.process("GET", "a.com", "/", mkResp(page1 + "v2"), "1.1.1.1").has_value(),
          "evicted page relearns");
    // 12. 前缀限制
    tc.clear();
    c.prefixes = {"/static"};
    tc.configure(c);
    CHECK(!tc.process("GET", "a.com", "/other", mkResp("o"), "1.1.1.1").has_value(),
          "prefix skip");
    CHECK(tc.size() == 0, "prefix mismatch not learned");
    tc.process("GET", "a.com", "/static/a", mkResp("s"), "1.1.1.1");
    CHECK(tc.size() == 1, "prefix match learned");
    // 13. TTL=0 → 每次过期重学，不触发恢复
    c.prefixes.clear();
    c.ttlSec = 0;
    tc.configure(c);
    CHECK(!tc.process("GET", "a.com", "/static/a", mkResp("s-changed"), "1.1.1.1").has_value(),
          "ttl expired relearn");
    // 14. 开关关闭 → 全量放行
    c.enabled = false;
    c.ttlSec = 3600;
    tc.configure(c);
    CHECK(!tc.process("GET", "a.com", "/static/a", mkResp("s-changed-2"), "1.1.1.1").has_value(),
          "disabled skip");
    // 15. base64 精确往返（含全字节域）
    std::string bin;
    for (int i = 0; i < 256; ++i) bin.push_back((char)i);
    CHECK(TamperCache::b64Decode(TamperCache::b64Encode(bin)) == bin, "b64 binary roundtrip");
    CHECK(TamperCache::b64Decode(TamperCache::b64Encode("")) == "", "b64 empty roundtrip");
    CHECK(TamperCache::b64Decode(TamperCache::b64Encode("a")) == "a", "b64 1-byte roundtrip");
    CHECK(TamperCache::b64Decode(TamperCache::b64Encode("ab")) == "ab", "b64 2-byte roundtrip");
    // 16. pageId 稳定且区分路径
    CHECK(TamperCache::pageId("a.com", "/") == TamperCache::pageId("a.com", "/"), "id stable");
    CHECK(TamperCache::pageId("a.com", "/") != TamperCache::pageId("a.com", "/x"),
          "id distinct");

    tc.clear();
    tc.setEventHook(nullptr);
}

int main() {
    std::printf("NovaWAF Core Unit Tests\n");
    std::printf("=======================\n\n");
    test_ac_automaton();
    test_decoder();
    test_json();
    test_custom_rules();
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
    test_fingerprint();
    test_cc_guard();
    test_bot_guard();
    test_dynamic_shield();
    test_ti_fingerprint();
    test_geo_filter();
    test_tamper_cache();

    test_accel_teddy_fuzz();
    test_accel_ac_integration();
    test_accel_batch();
    test_accel_circuit();
    test_accel_runtime_selftest();

    std::printf("\n=======================\n");
    std::printf("PASS: %d  FAIL: %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
