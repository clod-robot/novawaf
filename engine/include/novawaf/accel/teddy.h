// NovaWAF - Teddy 多模式锚点预筛（Hyperscan Teddy 思路的精确 2 字节锚点实现）
//
// 核心思想（零漏报）：
//   每个长度>=2 的模式 P，取其前 2 字节 (P0,P1) 作为“锚点”。
//   任何 P 在文本中的出现，必然起始于一个与 (P0,P1) 完全相等的字节对。
//   Teddy 用 pshufb  nibble 表一次并行判断 16/32 个位置是否出现任一锚点：
//     * 完全没有锚点  -> 必不命中，可直接拒绝（fast reject，绝大多数干净流量在此返回）。
//     * 出现锚点      -> 仅对该位置做整串 memcmp 二次确认，确认通过才判定命中。
//   因为使用 4 张 nibble 表覆盖锚点的全部 4 个 nibble，锚点判断是“精确”的，
//   不会把非锚点字节对误判成锚点（无假阳性候选），确认只需比较锚点之后的字节。
//
// 正确性边界：
//   * 存在长度<2 的模式，或不同首字节对数量超过容量时，AnchorSet.usable=false，
//     AcAutomaton 自动回退原标量 AC（语义完全不变）。
//   * 非 x86 / 编译器非 GCC/Clang / 运行时 CPU 不支持时，使用标量 Teddy（结果一致）。
//
// 本文件为 header-only，平台无关部分可在 Windows/Linux 编译；SIMD 仅在 x86 GCC/Clang 且
// 运行时探测支持时启用，保证同一份引擎二进制在旧/新 CPU 上都能运行。
#pragma once

#include "novawaf/accel/i_matcher.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__)) && !defined(NOVA_FORCE_SCALAR)
#define NOVA_ACCEL_X86_GNU 1
#include <immintrin.h>
#else
#define NOVA_ACCEL_X86_GNU 0
#endif

namespace novawaf::accel {

constexpr int kLitPerBucket = 8;        // 每个 bucket 最多 8 个锚点（一个字节的 8 个 bit）
constexpr int kMaxBuckets = 8;          // 最多 8 个 bucket => 64 个不同首字节对
constexpr int kMaxAnchors = kLitPerBucket * kMaxBuckets;

// 一个 Teddy bucket：4 张 16 项 nibble 掩码表（低/高 nibble × 锚点首/次字节）
struct alignas(16) AnchorBucket {
    uint8_t lo0[16] = {0};  // 索引=首字节低 nibble，bit k=锚点 k 的首字节低 nibble 命中
    uint8_t hi0[16] = {0};  // 索引=首字节高 nibble
    uint8_t lo1[16] = {0};  // 索引=次字节低 nibble
    uint8_t hi1[16] = {0};  // 索引=次字节高 nibble
};

// 模式集导出的锚点结构
class AnchorSet {
public:
    bool usable = false;                       // false 时调用方必须回退标量 AC
    int bucketCount = 0;
    AnchorBucket buckets[kMaxBuckets];
    std::vector<std::string> patterns;                              // 模式副本（确认用）
    std::vector<int> slotPatterns[kMaxAnchors];                     // slot -> 模式 id 列表

    // 从模式集合构建锚点。返回 usable。
    bool build(const std::vector<std::string>& pats) {
        usable = false;
        bucketCount = 0;
        patterns.clear();
        for (auto& v : slotPatterns) v.clear();
        for (auto& b : buckets) b = AnchorBucket{};

        for (const auto& p : pats) {
            if (!p.empty()) patterns.push_back(p);
        }
        if (patterns.empty()) return false;                 // 无模式：交给 AC（AC 也判不命中）
        for (const auto& p : patterns) {
            if (p.size() < 2) return false;                 // 单字节模式：Teddy 不适用
        }

        // 为每个“不同的首字节对”分配一个 (bucket, bit)
        std::unordered_map<uint32_t, int> pairToSlot;
        pairToSlot.reserve(patterns.size() * 2);
        int nextSlot = 0;
        for (size_t pid = 0; pid < patterns.size(); ++pid) {
            const auto& p = patterns[pid];
            uint32_t key = (uint32_t)(uint8_t)p[0] << 8 | (uint8_t)p[1];
            auto it = pairToSlot.find(key);
            int slot;
            if (it == pairToSlot.end()) {
                slot = nextSlot++;
                if (slot >= kMaxAnchors) return false;      // 锚点过多：回退 AC
                pairToSlot.emplace(key, slot);
                int b = slot / kLitPerBucket;
                int k = slot % kLitPerBucket;
                uint8_t bit = (uint8_t)(1u << k);
                uint8_t a0 = (uint8_t)p[0], a1 = (uint8_t)p[1];
                buckets[b].lo0[a0 & 0x0F] |= bit;
                buckets[b].hi0[a0 >> 4]    |= bit;
                buckets[b].lo1[a1 & 0x0F] |= bit;
                buckets[b].hi1[a1 >> 4]    |= bit;
                if (b + 1 > bucketCount) bucketCount = b + 1;
            } else {
                slot = it->second;
            }
            slotPatterns[slot].push_back((int)pid);
        }
        usable = true;
        return true;
    }
};

// ---------------- 进程级开关与统计（header-only inline，零额外翻译单元） ----------------
// 默认关闭（等保：能力默认不启用，由管理面显式打开）。
inline std::atomic<bool> g_enabled{false};
inline std::atomic<int>  g_activeBackend{(int)BackendKind::Scalar};

inline void setEnabled(bool on) noexcept { g_enabled.store(on, std::memory_order_relaxed); }
inline bool enabled() noexcept { return g_enabled.load(std::memory_order_relaxed); }
inline void setActiveBackend(BackendKind k) noexcept {
    g_activeBackend.store((int)k, std::memory_order_relaxed);
}
inline BackendKind activeBackend() noexcept {
    return (BackendKind)g_activeBackend.load(std::memory_order_relaxed);
}
// 仅当总开关打开且确有向量后端时，AcAutomaton 才走 Teddy 快路径。
inline bool teddyActive() noexcept {
    return g_enabled.load(std::memory_order_relaxed) &&
           g_activeBackend.load(std::memory_order_relaxed) != (int)BackendKind::Scalar;
}

// 统计采用“按线程分片 + 缓存行填充”，避免多核 reactor 在同一计数行上乒乓，
// 保证加速路径本身不被统计开销拖慢（管理面汇总时把各分片求和）。
constexpr int kStatShards = 16;
struct alignas(64) StatShard {
    std::atomic<uint64_t> scans{0};      // 进入 Teddy 预筛次数
    std::atomic<uint64_t> rejected{0};   // 无锚点直接短路次数
    std::atomic<uint64_t> confirmed{0};  // 锚点确认命中次数
    std::atomic<uint64_t> fallback{0};   // 异常回退标量 AC 次数
};
inline StatShard* statShards() {
    static StatShard sh[kStatShards];
    return sh;
}
inline int statIndex() {
    static thread_local int idx = [] {
        static std::atomic<int> ctr{0};
        return ctr.fetch_add(1, std::memory_order_relaxed) % kStatShards;
    }();
    return idx;
}
inline void countTeddy(bool hit) noexcept {
    auto& s = statShards()[statIndex()];
    s.scans.fetch_add(1, std::memory_order_relaxed);
    if (hit) s.confirmed.fetch_add(1, std::memory_order_relaxed);
    else     s.rejected.fetch_add(1, std::memory_order_relaxed);
}
inline void countFallback() noexcept {
    statShards()[statIndex()].fallback.fetch_add(1, std::memory_order_relaxed);
}
inline uint64_t totalStat(std::atomic<uint64_t> StatShard::*m) {
    uint64_t sum = 0;
    StatShard* sh = statShards();
    for (int i = 0; i < kStatShards; ++i)
        sum += (sh[i].*m).load(std::memory_order_relaxed);
    return sum;
}
inline uint64_t totalScans()     { return totalStat(&StatShard::scans); }
inline uint64_t totalRejected()  { return totalStat(&StatShard::rejected); }
inline uint64_t totalConfirmed() { return totalStat(&StatShard::confirmed); }
inline uint64_t totalFallback()  { return totalStat(&StatShard::fallback); }

// ---------------- 二次确认：锚点位置 s 处，候选 bucket b 的掩码 mb 是否有整串命中 ----------------
inline bool confirmAt(const AnchorSet& A, const uint8_t* data, size_t len,
                      size_t s, int b, uint8_t mb) {
    while (mb) {
        int k = __builtin_ctz((unsigned)mb);
        mb &= (uint8_t)(mb - 1);
        for (int pid : A.slotPatterns[b * kLitPerBucket + k]) {
            const auto& p = A.patterns[(size_t)pid];
            size_t L = p.size();
            if (s + L <= len && std::memcmp(data + s, p.data(), L) == 0) return true;
        }
    }
    return false;
}

// ---------------- 标量 Teddy（可移植黄金实现，非 x86/无 SIMD 时使用） ----------------
inline bool scalarContains(const uint8_t* d, size_t len, const AnchorSet& A) {
    if (len < 2) return false;
    for (int b = 0; b < A.bucketCount; ++b) {
        const AnchorBucket& B = A.buckets[b];
        for (size_t i = 0; i + 1 < len; ++i) {
            uint8_t a0 = d[i], a1 = d[i + 1];
            uint8_t m = (uint8_t)(B.lo0[a0 & 0x0F] & B.hi0[a0 >> 4] &
                                  B.lo1[a1 & 0x0F] & B.hi1[a1 >> 4]);
            if (m && confirmAt(A, d, len, i, b, m)) return true;
        }
    }
    return false;
}

inline bool scalarContains(std::string_view text, const AnchorSet& A) {
    return scalarContains(reinterpret_cast<const uint8_t*>(text.data()), text.size(), A);
}

#if NOVA_ACCEL_X86_GNU
// ---------------- SSSE3 128 位内核（16 字节/拍） ----------------
__attribute__((target("ssse3")))
inline bool sseContainsImpl(const uint8_t* d, size_t len, const AnchorSet& A) {
    if (len < 2) return false;
    const __m128i mask0f = _mm_set1_epi8(0x0F);
    size_t p = 0;
    __m128i carry = _mm_setzero_si128();   // [15] = 上一块最后一个字节
    bool first = true;
    for (; p + 16 <= len; p += 16) {
        __m128i cur = _mm_loadu_si128(reinterpret_cast<const __m128i*>(d + p));
        __m128i prev = _mm_alignr_epi8(cur, carry, 15);  // prev[i]=cur[i-1]，prev[0]=carry[15]
        carry = cur;
        __m128i plo = _mm_and_si128(prev, mask0f);
        __m128i phi = _mm_and_si128(_mm_srli_epi16(prev, 4), mask0f);
        __m128i clo = _mm_and_si128(cur, mask0f);
        __m128i chi = _mm_and_si128(_mm_srli_epi16(cur, 4), mask0f);
        for (int b = 0; b < A.bucketCount; ++b) {
            const AnchorBucket& B = A.buckets[b];
            __m128i m = _mm_and_si128(
                _mm_and_si128(_mm_shuffle_epi8(_mm_load_si128((const __m128i*)B.lo0), plo),
                              _mm_shuffle_epi8(_mm_load_si128((const __m128i*)B.hi0), phi)),
                _mm_and_si128(_mm_shuffle_epi8(_mm_load_si128((const __m128i*)B.lo1), clo),
                              _mm_shuffle_epi8(_mm_load_si128((const __m128i*)B.hi1), chi)));
            unsigned flags = (unsigned)(~_mm_movemask_epi8(_mm_cmpeq_epi8(m, _mm_setzero_si128()))) & 0xFFFFu;
            if (first) flags &= ~1u;   // j=0 没有前驱字节，屏蔽
            if (flags) {
                alignas(16) uint8_t mb[16];
                _mm_store_si128(reinterpret_cast<__m128i*>(mb), m);
                while (flags) {
                    int j = __builtin_ctz(flags);
                    flags &= flags - 1;
                    size_t s = p + (size_t)j - 1;  // 锚点起始
                    if (confirmAt(A, d, len, s, b, mb[j])) return true;
                }
            }
        }
        first = false;
    }
    // 尾部不足 16 字节：回退标量（多查一个跨块边界位置，幂等无副作用）
    size_t tail = (p > 0) ? p - 1 : 0;
    for (int b = 0; b < A.bucketCount; ++b) {
        const AnchorBucket& B = A.buckets[b];
        for (size_t i = tail; i + 1 < len; ++i) {
            uint8_t a0 = d[i], a1 = d[i + 1];
            uint8_t m = (uint8_t)(B.lo0[a0 & 0x0F] & B.hi0[a0 >> 4] &
                                  B.lo1[a1 & 0x0F] & B.hi1[a1 >> 4]);
            if (m && confirmAt(A, d, len, i, b, m)) return true;
        }
    }
    return false;
}

// ---------------- AVX2 256 位内核（32 字节/拍，两个 128 lane，手工处理跨 lane 边界） ----------------
__attribute__((target("avx2")))
inline bool avx2ContainsImpl(const uint8_t* d, size_t len, const AnchorSet& A) {
    if (len < 2) return false;
    const __m256i mask0f = _mm256_set1_epi8(0x0F);
    size_t p = 0;
    __m128i carry = _mm_setzero_si128();   // [15]=上一块末字节
    bool first = true;
    for (; p + 32 <= len; p += 32) {
        __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(d + p));
        __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(d + p + 16));
        // 低 lane 的前驱：上一块末字节；高 lane 的前驱：本块低 lane 末字节（跨 lane 修正）
        __m128i prevLo = _mm_alignr_epi8(lo, carry, 15);
        __m128i prevHi = _mm_alignr_epi8(hi, lo, 15);
        carry = hi;
        __m256i cur = _mm256_set_m128i(hi, lo);
        __m256i prev = _mm256_set_m128i(prevHi, prevLo);
        __m256i plo = _mm256_and_si256(prev, mask0f);
        __m256i phi = _mm256_and_si256(_mm256_srli_epi16(prev, 4), mask0f);
        __m256i clo = _mm256_and_si256(cur, mask0f);
        __m256i chi = _mm256_and_si256(_mm256_srli_epi16(cur, 4), mask0f);
        for (int b = 0; b < A.bucketCount; ++b) {
            const AnchorBucket& B = A.buckets[b];
            __m256i tlo0 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i*)B.lo0));
            __m256i thi0 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i*)B.hi0));
            __m256i tlo1 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i*)B.lo1));
            __m256i thi1 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i*)B.hi1));
            __m256i m = _mm256_and_si256(
                _mm256_and_si256(_mm256_shuffle_epi8(tlo0, plo),
                                 _mm256_shuffle_epi8(thi0, phi)),
                _mm256_and_si256(_mm256_shuffle_epi8(tlo1, clo),
                                 _mm256_shuffle_epi8(thi1, chi)));
            unsigned flags = (unsigned)(~_mm256_movemask_epi8(
                _mm256_cmpeq_epi8(m, _mm256_setzero_si256()))) & 0xFFFFFFFFu;
            if (first) flags &= ~1u;   // 全局 j=0 无前驱
            if (flags) {
                alignas(32) uint8_t mb[32];
                _mm256_store_si256(reinterpret_cast<__m256i*>(mb), m);
                while (flags) {
                    int j = __builtin_ctz(flags);
                    flags &= flags - 1;
                    size_t s = p + (size_t)j - 1;
                    if (confirmAt(A, d, len, s, b, mb[j])) return true;
                }
            }
        }
        first = false;
    }
    // 尾部 <32：标量回退（含跨块边界，幂等）
    size_t tail = (p > 0) ? p - 1 : 0;
    for (int b = 0; b < A.bucketCount; ++b) {
        const AnchorBucket& B = A.buckets[b];
        for (size_t i = tail; i + 1 < len; ++i) {
            uint8_t a0 = d[i], a1 = d[i + 1];
            uint8_t m = (uint8_t)(B.lo0[a0 & 0x0F] & B.hi0[a0 >> 4] &
                                  B.lo1[a1 & 0x0F] & B.hi1[a1 >> 4]);
            if (m && confirmAt(A, d, len, i, b, m)) return true;
        }
    }
    return false;
}
#endif  // NOVA_ACCEL_X86_GNU

// 运行时选择的向量能力等级
enum class SimdLevel : int { None = 0, SSSE3 = 1, AVX2 = 2, AVX512 = 3 };

inline SimdLevel detectSimdLevel() {
#if NOVA_ACCEL_X86_GNU
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw"))
        return SimdLevel::AVX512;
    if (__builtin_cpu_supports("avx2")) return SimdLevel::AVX2;
    if (__builtin_cpu_supports("ssse3")) return SimdLevel::SSSE3;
#endif
    return SimdLevel::None;
}

// 统一入口：按运行时能力分发到 AVX2 / SSSE3 / 标量。
inline bool anchorContainsAny(std::string_view text, const AnchorSet& A) {
    if (!A.usable || text.size() < 2) return false;
    const uint8_t* d = reinterpret_cast<const uint8_t*>(text.data());
#if NOVA_ACCEL_X86_GNU
    static const SimdLevel lvl = detectSimdLevel();
    if (lvl == SimdLevel::AVX2) return avx2ContainsImpl(d, text.size(), A);
    if (lvl == SimdLevel::SSSE3) return sseContainsImpl(d, text.size(), A);
#endif
    return scalarContains(d, text.size(), A);
}

// 批量接口：对一批文本并行预筛（GPU/NPU 微批路径用同一签名；CPU 侧逐文本走 Teddy）。
// outHit[i] 置 1 表示文本 i 至少命中一个模式。
inline void batchAnchorContainsAny(const std::vector<std::string_view>& texts,
                                   const AnchorSet& A, uint8_t* outHit) {
    for (size_t i = 0; i < texts.size(); ++i) {
        outHit[i] = anchorContainsAny(texts[i], A) ? BatchHit::kHit : BatchHit::kNoHit;
    }
}

// 暴力参考实现：任一模式作为子串出现即命中（黄金对照，仅供自检/测试）
inline bool bruteForceAny(const std::vector<std::string>& patterns, std::string_view text) {
    for (const auto& p : patterns) {
        if (!p.empty() && text.find(p) != std::string_view::npos) return true;
    }
    return false;
}

}  // namespace novawaf::accel
