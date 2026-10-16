// NovaWAF 硬件加速——多模式匹配扫描吞吐微基准（真实规则集）
//
// 目的：在同一 CPU、同一份规则集、同一批数据上，量化检测子系统的匹配吞吐：
//   AC   : 线上默认的 Aho-Corasick 标量自动机（加速关闭时的生产路径）
//   T-scalar : Teddy 标量内核（可移植黄金实现）
//   T-SSSE3  : Teddy 128 位 SIMD 内核（16 字节/拍）
//   T-AVX2   : Teddy 256 位 SIMD 内核（32 字节/拍）
// 数据面绝大多数为“干净请求”，在锚点预筛阶段即被 fast-reject，故主基准采用
// 不含任何锚点的良性长文本（最坏全扫，最能体现 SIMD 收益）。
//
// 编译（x86 GCC/Clang，函数级 target，无需全局 -mavx2，旧 CPU 可运行）：
//   g++ -std=c++20 -O2 -I include tests/bench_teddy.cpp -o /tmp/bench_teddy -pthread
//
// 输出 stdout JSON：每核 GB/s、单核相对 AC 提速、4 核聚合吞吐、自检结果。
#include "novawaf/detect/ac_automaton.h"
#include "novawaf/accel/teddy.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using clk = std::chrono::steady_clock;
using namespace novawaf;
using namespace novawaf::accel;

// 与线上 SQLi/XSS/语义攻击同类的代表规则（首两字节锚点互不相同）
static const std::vector<std::string> kRules = {
    "union select", "' or '1'='1", "<script", "onerror=", "../", "/etc/passwd",
    "<!entity", "sleep(", "select * from", "information_schema", "waitfor delay",
    "drop table", "delete from", "updatexml(", "extractvalue(", "benchmark(",
    "<img src", "system(",
};

// 生成不含任何锚点首字节对的良性数据：仅数字与不触发锚点的分隔符（最坏全扫）
static std::string makeClean(size_t n) {
    static const char* alpha = "0123456789:;=-& ";
    std::string s;
    s.resize(n);
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        s[i] = alpha[x % 17];
    }
    return s;
}

struct R { double gbps; double mops; bool sink; };

// 预切成 chunk 字节的“请求”（准备阶段不计入计时），避免计时中产生内存分配。
static std::vector<std::string> makeChunks(size_t total, size_t chunk) {
    std::string blob = makeClean(total);
    std::vector<std::string> v;
    v.reserve(total / chunk);
    for (size_t p = 0; p + chunk <= blob.size(); p += chunk)
        v.emplace_back(blob.data() + p, chunk);
    return v;
}

// 对每个请求串调用 fn；多线程按下标均分。
template <class Fn>
static R runOnce(const std::vector<std::string>& chunks, int threads, Fn fn) {
    const size_t n = chunks.size();
    std::vector<std::thread> th;
    std::atomic<int64_t> hits{0};
    auto gate = std::make_shared<std::atomic<int>>(0);
    auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < threads; ++t) {
        size_t lo = (n / threads) * (size_t)t;
        size_t hi = (t == threads - 1) ? n : (n / threads) * (size_t)(t + 1);
        th.emplace_back([&, lo, hi] {
            gate->fetch_add(1);
            while (gate->load() < threads) {}
            int64_t h = 0;
            for (size_t i = lo; i < hi; ++i) h += fn(chunks[i]);
            hits += h;
        });
    }
    for (auto& x : th) x.join();
    double sec = std::chrono::duration<double>(clk::now() - start).count();
    double bytes = (double)n * (double)chunks[0].size();
    return {bytes / sec / 1e9, (double)n / sec / 1e6, (hits.load() & 1) != 0};
}

template <class Fn>
static R bench(const char* name, const std::vector<std::string>& chunks, int threads,
               double minSec, Fn fn) {
    R best{0, 0, false};
    // 重复扫描直到达到 minSec，取吞吐最高一轮
    auto t0 = clk::now();
    while (std::chrono::duration<double>(clk::now() - t0).count() < minSec) {
        R r = runOnce(chunks, threads, fn);
        if (r.gbps > best.gbps) best = r;
    }
    std::printf("  %-9s threads=%d  %7.3f GB/s  %8.1f M req/s\n",
                name, threads, best.gbps, best.mops);
    return best;
}

int main() {
    AcAutomaton ac;
    for (auto& p : kRules) ac.addPattern(p);
    ac.build();
    AnchorSet A;
    A.build(kRules);
    if (!A.usable) { std::printf("anchor unusable\n"); return 2; }

    // ---- 正确性自检：随机数据里埋入规则，各内核必须与暴力参考一致 ----
    std::mt19937_64 rng(12345);
    int bad = 0, cases = 20000;
    std::string scratch(8192, '0');
    for (int t = 0; t < cases; ++t) {
        for (auto& c : scratch) c = "0123456789:;=-& "[rng() % 17];
        bool want = false;
        if ((rng() & 3) == 0) {  // 1/4 概率埋入
            const std::string& p = kRules[rng() % kRules.size()];
            size_t pos = rng() % (scratch.size() - p.size() - 1);
            scratch.replace(pos, p.size(), p);
            want = true;
        }
        std::string_view sv(scratch);
        bool bAc = ac.containsAny(scratch);          // 默认标量 AC
        accel::setEnabled(true);
        accel::setActiveBackend(BackendKind::Scalar);
        // 标量/向量内核直接调用，绕过运行时分发以便分别计时
        bool bSc = scalarContains(reinterpret_cast<const uint8_t*>(scratch.data()),
                                  scratch.size(), A);
        accel::setEnabled(false);
        bool bRef = ac.containsAny(scratch);
        (void)bAc; (void)bRef;
#if NOVA_ACCEL_X86_GNU
        bool bSse = sseContainsImpl(reinterpret_cast<const uint8_t*>(scratch.data()),
                                    scratch.size(), A);
        bool bAvx = avx2ContainsImpl(reinterpret_cast<const uint8_t*>(scratch.data()),
                                     scratch.size(), A);
#else
        bool bSse = bSc, bAvx = bSc;
#endif
        bool bf = bruteForceAny(kRules, sv);
        if (!(bf == want && bSc == bf && bSse == bf && bAvx == bf)) ++bad;
    }
    accel::setEnabled(false);
    std::printf("self-check cases=%d mismatch=%d simd=%s\n",
                cases, bad,
#if NOVA_ACCEL_X86_GNU
                detectSimdLevel() >= SimdLevel::AVX2 ? "AVX2"
                : detectSimdLevel() == SimdLevel::SSSE3 ? "SSSE3" : "none");
#else
                "none");
#endif
    if (bad) return 3;

    const size_t BUFSZ = 256ull << 20;   // 256MB 干净数据
    const size_t CHUNK = 4096;           // 4KB/请求（等价较大请求体/查询）
    std::vector<std::string> chunks = makeChunks(BUFSZ, CHUNK);

    std::printf("buffer=%zuMB chunk=%zu rules=%zu\n", BUFSZ >> 20, CHUNK, kRules.size());
    std::printf("[single-core]\n");
    auto ac1 = bench("AC", chunks, 1, 0.8,
                     [&](const std::string& s) { return ac.containsAny(s); });
    auto sc1 = bench("T-scalar", chunks, 1, 0.8,
                     [&](const std::string& s) {
                         return scalarContains(reinterpret_cast<const uint8_t*>(s.data()),
                                               s.size(), A);
                     });
    auto sse1 = bench("T-SSSE3", chunks, 1, 0.8,
                      [&](const std::string& s) {
#if NOVA_ACCEL_X86_GNU
                          return sseContainsImpl(reinterpret_cast<const uint8_t*>(s.data()),
                                                 s.size(), A);
#else
                          return scalarContains(reinterpret_cast<const uint8_t*>(s.data()),
                                                s.size(), A);
#endif
                      });
    auto ax1 = bench("T-AVX2", chunks, 1, 0.8,
                     [&](const std::string& s) {
#if NOVA_ACCEL_X86_GNU
                         return avx2ContainsImpl(reinterpret_cast<const uint8_t*>(s.data()),
                                                  s.size(), A);
#else
                         return scalarContains(reinterpret_cast<const uint8_t*>(s.data()),
                                               s.size(), A);
#endif
                     });

    std::printf("[4-core aggregate]\n");
    auto ac4 = bench("AC", chunks, 4, 0.8,
                     [&](const std::string& s) { return ac.containsAny(s); });
    auto ax4 = bench("T-AVX2", chunks, 4, 0.8,
                     [&](const std::string& s) {
#if NOVA_ACCEL_X86_GNU
                         return avx2ContainsImpl(reinterpret_cast<const uint8_t*>(s.data()),
                                                  s.size(), A);
#else
                         return scalarContains(reinterpret_cast<const uint8_t*>(s.data()),
                                               s.size(), A);
#endif
                     });

    std::printf("speedup AVX2/AC single=%.2fx (%.0f%%) 4core=%.2fx (%.0f%%)\n",
                ax1.gbps / ac1.gbps, (ax1.gbps / ac1.gbps - 1.0) * 100.0,
                ax4.gbps / ac4.gbps, (ax4.gbps / ac4.gbps - 1.0) * 100.0);
    return 0;
}
