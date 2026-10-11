// NovaWAF - 极简 JSON 解析器（零第三方依赖，header-only）
// 仅用于解析由本项目控制台写入 Redis 的规则 JSON（格式可控）。
// 支持：object / array / string / number / bool / null，字符串含常见转义。
// 设计取舍：不为通用性牺牲可读性；输入为可信内部数据，解析失败抛 std::runtime_error。
#pragma once

#include <cctype>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace novawaf {

struct JsonValue {
    enum Type { NUL, BOOL, NUMBER, STRING, ARRAY, OBJECT } type = NUL;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JsonValue> arr;
    std::map<std::string, JsonValue> obj;

    bool isObject() const { return type == OBJECT; }
    bool isArray()  const { return type == ARRAY; }
    bool isString() const { return type == STRING; }
    bool isNumber() const { return type == NUMBER; }
    bool isBool()   const { return type == BOOL; }

    // 对象取字段（不存在返回 NUL）
    const JsonValue& at(const std::string& k) const {
        static const JsonValue kNull;
        auto it = obj.find(k);
        return it == obj.end() ? kNull : it->second;
    }
    bool has(const std::string& k) const { return obj.find(k) != obj.end(); }
};

namespace json_detail {

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    JsonValue parse() {
        skipWs();
        JsonValue v = parseValue();
        skipWs();
        if (pos_ != s_.size()) throw std::runtime_error("json: trailing data");
        return v;
    }

private:
    const std::string& s_;
    size_t pos_ = 0;

    void skipWs() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' ||
                                    s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }
    char peek() { return pos_ < s_.size() ? s_[pos_] : '\0'; }
    char get()  { return pos_ < s_.size() ? s_[pos_++] : '\0'; }

    JsonValue parseValue() {
        skipWs();
        char c = peek();
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == '"') { JsonValue v; v.type = JsonValue::STRING; v.str = parseString(); return v; }
        if (c == 't' || c == 'f') return parseBool();
        if (c == 'n') return parseNull();
        return parseNumber();
    }

    JsonValue parseObject() {
        JsonValue v; v.type = JsonValue::OBJECT;
        get();  // {
        skipWs();
        if (peek() == '}') { get(); return v; }
        while (true) {
            skipWs();
            if (peek() != '"') throw std::runtime_error("json: expected string key");
            std::string key = parseString();
            skipWs();
            if (get() != ':') throw std::runtime_error("json: expected ':'");
            JsonValue val = parseValue();
            v.obj[key] = std::move(val);
            skipWs();
            char c = get();
            if (c == ',') continue;
            if (c == '}') break;
            throw std::runtime_error("json: expected ',' or '}'");
        }
        return v;
    }

    JsonValue parseArray() {
        JsonValue v; v.type = JsonValue::ARRAY;
        get();  // [
        skipWs();
        if (peek() == ']') { get(); return v; }
        while (true) {
            v.arr.push_back(parseValue());
            skipWs();
            char c = get();
            if (c == ',') continue;
            if (c == ']') break;
            throw std::runtime_error("json: expected ',' or ']'");
        }
        return v;
    }

    std::string parseString() {
        get();  // opening "
        std::string out;
        while (true) {
            char c = get();
            if (c == '\0') throw std::runtime_error("json: unterminated string");
            if (c == '"') break;
            if (c == '\\') {
                char e = get();
                switch (e) {
                    case '"':  out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/'); break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'n':  out.push_back('\n'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'u': {
                        // \uXXXX -> 仅处理 BMP，转 UTF-8
                        if (pos_ + 4 > s_.size()) throw std::runtime_error("json: bad \\u");
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = s_[pos_++];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                            else throw std::runtime_error("json: bad hex in \\u");
                        }
                        encodeUtf8(out, cp);
                        break;
                    }
                    default: throw std::runtime_error("json: bad escape");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    static void encodeUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out.push_back((char)cp);
        } else if (cp < 0x800) {
            out.push_back((char)(0xC0 | (cp >> 6)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else {
            out.push_back((char)(0xE0 | (cp >> 12)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        }
    }

    JsonValue parseBool() {
        JsonValue v; v.type = JsonValue::BOOL;
        if (s_.compare(pos_, 4, "true") == 0) { v.b = true; pos_ += 4; }
        else if (s_.compare(pos_, 5, "false") == 0) { v.b = false; pos_ += 5; }
        else throw std::runtime_error("json: bad literal");
        return v;
    }

    JsonValue parseNull() {
        JsonValue v; v.type = JsonValue::NUL;
        if (s_.compare(pos_, 4, "null") == 0) pos_ += 4;
        else throw std::runtime_error("json: bad literal");
        return v;
    }

    JsonValue parseNumber() {
        size_t start = pos_;
        if (peek() == '-' || peek() == '+') get();
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (std::isdigit((unsigned char)c) || c == '.' || c == 'e' || c == 'E' ||
                c == '+' || c == '-') ++pos_;
            else break;
        }
        if (pos_ == start) throw std::runtime_error("json: bad number");
        JsonValue v; v.type = JsonValue::NUMBER;
        v.num = std::strtod(s_.substr(start, pos_ - start).c_str(), nullptr);
        return v;
    }
};

}  // namespace json_detail

inline JsonValue parseJson(const std::string& s) {
    return json_detail::Parser(s).parse();
}

}  // namespace novawaf
