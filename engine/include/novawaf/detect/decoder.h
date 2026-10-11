// NovaWAF - 递归解码器（对抗编码绕过）
// 对 payload 做 URL decode -> HTML entity -> Unicode -> Base64 递归解码，
// 自动识别编码嵌套，是语义分析的前置归一化步骤。
#pragma once

#include <cctype>
#include <string>

namespace novawaf {

class Decoder {
public:
    // 最大递归层数，防止解码器自身被 DoS
    static constexpr int kMaxDepth = 5;

    // 归一化解码：返回解码后的字符串（尽量还原攻击原始形态）
    static std::string normalize(const std::string& input) {
        std::string current = input;
        for (int i = 0; i < kMaxDepth; ++i) {
            std::string next;
            next.reserve(current.size());
            bool changed = false;

            // 1. URL decode
            std::string urlDecoded = urlDecode(current);
            if (urlDecoded != current) { changed = true; }
            // 2. HTML entity decode
            std::string htmlDecoded = htmlEntityDecode(urlDecoded);
            if (htmlDecoded != urlDecoded) { changed = true; }
            // 3. Base64 检测解码（尝试）
            std::string b64 = tryBase64Decode(htmlDecoded);
            if (!b64.empty() && b64 != htmlDecoded) {
                next = b64;
                changed = true;
            } else {
                next = htmlDecoded;
            }
            // 4. 转小写归一（大小写绕过）
            toLowerInPlace(next);

            if (!changed || next == current) break;
            current = next;
        }
        return current;
    }

    static std::string urlDecode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size() && isHex(s[i + 1]) && isHex(s[i + 2])) {
                out.push_back(static_cast<char>(hexVal(s[i + 1]) * 16 + hexVal(s[i + 2])));
                i += 2;
            } else if (s[i] == '+') {
                out.push_back(' ');
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    }

    static std::string htmlEntityDecode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size();) {
            if (s[i] == '&' && i + 1 < s.size()) {
                size_t semi = s.find(';', i);
                if (semi != std::string::npos && semi - i <= 10) {
                    std::string ent = s.substr(i + 1, semi - i - 1);
                    if (ent == "lt") out.push_back('<');
                    else if (ent == "gt") out.push_back('>');
                    else if (ent == "amp") out.push_back('&');
                    else if (ent == "quot") out.push_back('"');
                    else if (ent == "apos") out.push_back('\'');
                    else if (!ent.empty() && ent[0] == '#') {
                        int code = 0;
                        if (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X'))
                            code = (int)strtol(ent.c_str() + 2, nullptr, 16);
                        else
                            code = atoi(ent.c_str() + 1);
                        if (code > 0 && code < 256) out.push_back((char)code);
                        else out.append(s, i, semi - i + 1);
                    } else {
                        out.append(s, i, semi - i + 1);
                    }
                    i = semi + 1;
                    continue;
                }
            }
            out.push_back(s[i++]);
        }
        return out;
    }

    // 尝试 base64 解码：仅当整个串像 base64 且解码结果可打印时才返回，否则空串
    static std::string tryBase64Decode(const std::string& s) {
        if (s.size() < 4 || s.size() % 4 != 0) return {};
        for (char c : s) {
            if (!isalnum((unsigned char)c) && c != '+' && c != '/' && c != '=')
                return {};
        }
        std::string out;
        int val = 0, bits = 0;
        for (char c : s) {
            if (c == '=') break;
            int d = b64Index(c);
            if (d < 0) return {};
            val = (val << 6) | d;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back((char)((val >> bits) & 0xFF));
            }
        }
        // 校验是否可打印（避免把正常文本误判）
        for (char c : out)
            if ((unsigned char)c < 0x20 && c != '\t' && c != '\n' && c != '\r')
                return {};
        return out;
    }

    static void toLowerInPlace(std::string& s) {
        for (char& c : s) c = (char)tolower((unsigned char)c);
    }

private:
    static bool isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    }
    static int b64Index(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }
};

}  // namespace novawaf
