// NovaWAF - 自实现 SHA-256（零第三方依赖，避免引入 OpenSSL 链接）
// 用于对上传文件计算指纹，供外部情报信誉查询缓存键使用。
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace novawaf {
namespace sha256 {

inline constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

class Digest {
public:
    Digest() { reset(); }
    void reset() {
        h_[0]=0x6a09e667; h_[1]=0xbb67ae85; h_[2]=0x3c6ef372; h_[3]=0xa54ff53a;
        h_[4]=0x510e527f; h_[5]=0x9b05688c; h_[6]=0x1f83d9ab; h_[7]=0x5be0cd19;
        bitlen_ = 0; buf_.clear();
    }
    void update(const void* data, size_t len) {
        const auto* p = (const uint8_t*)data;
        bitlen_ += (uint64_t)len * 8;
        buf_.insert(buf_.end(), p, p + len);
        size_t off = 0;
        while (off + 64 <= buf_.size()) { transform(buf_.data() + off); off += 64; }
        if (off) buf_.erase(buf_.begin(), buf_.begin() + off);
    }
    std::string hex() {
        uint64_t bl = bitlen_;
        // 直接在缓冲上做填充，不再走 update（避免污染 bitlen_）
        buf_.push_back(0x80);
        while (buf_.size() % 64 != 56) buf_.push_back(0x00);
        for (int i = 0; i < 8; ++i) buf_.push_back((uint8_t)(bl >> (56 - i * 8)));
        for (size_t off = 0; off < buf_.size(); off += 64) transform(buf_.data() + off);
        char out[65];
        for (int i = 0; i < 8; ++i) std::snprintf(out + i * 8, 9, "%08x", h_[i]);
        out[64] = 0;
        return std::string(out);
    }
private:
    void transform(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 | (uint32_t)block[i*4+2]<<8 | block[i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],hh=h_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=hh;
    }
    uint32_t h_[8];
    uint64_t bitlen_;
    std::vector<uint8_t> buf_;
};

inline std::string hashHex(const std::string& data) {
    Digest d; d.update(data.data(), data.size()); return d.hex();
}
inline std::string hashHex(const void* data, size_t len) {
    Digest d; d.update(data, len); return d.hex();
}

}  // namespace sha256
}  // namespace novawaf
