// NovaWAF - 客户端指纹提取（JA4 TLS 指纹 + HTTP 层指纹）
// 用途：把"同一个客户端"的连接稳定归一成指纹，用于黑指纹威胁情报匹配与 Bot 识别。
// 设计：纯函数、无状态、平台无关。
//   - ja4FromClientHello: 从 TLS ClientHello 原始字节计算 JA4 指纹（JA4 兼容子集）。
//   - httpFingerprint:    纯 HTTP 层也能稳定归并的指纹（方法+有序头部集合）。
// JA4 参考算法（简化兼容版）：
//   a = "t" + TLS版本(2位，映射) + SNI有无(1) + ALPN有无(1) + 前12位cipher哈希...
//   完整 JA4 = a_b_c，其中 b=前12字符(sha256(排序后的cipher列表))，c=前12字符(sha256(排序后的扩展列表))。
#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace novawaf {

// FNV-1a 64 位哈希（轻量、无依赖）
inline uint64_t fnv1a64(const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// 取哈希的前 n 个十六进制字符
inline std::string hexPrefix(uint64_t h, int n) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < n; ++i) {
        out.push_back(hexd[(h >> ((15 - i) * 4)) & 0xF]);
    }
    return out;
}

// ---- HTTP 层指纹：不依赖 TLS，对相同客户端稳定 ----
// 组成：方法 + 有序（按出现序去重）头部名称集合 的哈希。
// 真实浏览器与脚本/扫描器的头部集合差异显著，可用于粗粒度归并。
inline std::string httpFingerprint(const std::string& method,
                                   const std::unordered_map<std::string, std::string>& headers) {
    // 收集头部名，按字典序排序保证稳定
    std::vector<std::string> names;
    names.reserve(headers.size());
    for (auto& [k, v] : headers) {
        std::string lk = k;
        for (auto& c : lk) c = (char)tolower((unsigned char)c);
        names.push_back(lk);
    }
    std::sort(names.begin(), names.end());
    uint64_t h = fnv1a64(method.data(), method.size());
    for (auto& n : names) {
        h = fnv1a64(n.data(), n.size()) ^ (h * 1099511628211ULL);
    }
    return "h" + hexPrefix(h, 12);
}

// ---- JA4 指纹：从 TLS ClientHello 原始字节计算 ----
// 输入是完整的 TLS 记录（含 5 字节记录头）或直接 handshake。
// 返回形如 "t13d1516h2_8daaf6152771_e5627efa2ab1"（JA4 兼容子集）。
// 解析失败返回空串。
inline std::string ja4FromClientHello(const uint8_t* data, size_t len) {
    if (len < 5) return {};
    size_t off = 0;
    // 可选：跳过 TLS record 头 (content_type=0x16, version, length)
    if (data[0] == 0x16 && len >= 5) {
        uint16_t recLen = (data[3] << 8) | data[4];
        if (5 + recLen > len) return {};
        off = 5;
    }
    // Handshake: type(1)=0x01, length(3), version(2), random(32)
    if (off + 38 > len) return {};
    if (data[off] != 0x01) return {};  // ClientHello
    uint32_t hsLen = (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3];
    if (off + 4 + hsLen > len) return {};
    size_t p = off + 4;
    uint16_t legacyVersion = (data[p] << 8) | data[p + 1];
    p += 2 + 32;  // version + random
    if (p + 1 > len) return {};
    uint8_t sidLen = data[p++];
    p += sidLen;
    if (p + 2 > len) return {};
    uint16_t cipherLen = (data[p] << 8) | data[p + 1];
    p += 2;
    if (p + cipherLen > len) return {};
    // 收集 cipher suites（每个 2 字节）
    std::vector<uint16_t> ciphers;
    for (size_t i = 0; i + 1 < cipherLen; i += 2)
        ciphers.push_back((data[p + i] << 8) | data[p + i + 1]);
    p += cipherLen;
    if (p + 1 > len) return {};
    uint8_t compLen = data[p++];
    p += compLen;
    // 扩展
    bool hasSni = false, hasAlpn = false;
    std::vector<uint16_t> exts;
    if (p + 2 <= len) {
        uint16_t extTotal = (data[p] << 8) | data[p + 1];
        p += 2;
        size_t end = std::min(p + extTotal, len);
        while (p + 4 <= end) {
            uint16_t type = (data[p] << 8) | data[p + 1];
            uint16_t elen = (data[p + 2] << 8) | data[p + 3];
            exts.push_back(type);
            if (type == 0) hasSni = true;
            if (type == 16) hasAlpn = true;
            p += 4 + elen;
        }
    }
    // TLS 版本映射为 2 字符
    const char* vmap = "00";
    switch (legacyVersion) {
        case 0x0301: vmap = "10"; break;  // TLS1.0
        case 0x0302: vmap = "11"; break;  // TLS1.1
        case 0x0303: vmap = "12"; break;  // TLS1.2/1.3 常见
        case 0x0304: vmap = "13"; break;  // TLS1.3
        default: vmap = "12";
    }
    // 排序 cipher / ext 后哈希
    std::sort(ciphers.begin(), ciphers.end());
    std::sort(exts.begin(), exts.end());
    uint64_t hc = 1469598103934665603ULL;
    for (uint16_t c : ciphers) { hc ^= c; hc *= 1099511628211ULL; }
    uint64_t he = 1469598103934665603ULL;
    for (uint16_t e : exts) { he ^= e; he *= 1099511628211ULL; }

    std::string a = std::string("t") + vmap + (hasSni ? "d" : "i") +
                    (hasAlpn ? "h" : "0") + std::to_string(ciphers.size());
    return a + "_" + hexPrefix(hc, 12) + "_" + hexPrefix(he, 12);
}

}  // namespace novawaf
