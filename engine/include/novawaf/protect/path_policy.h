// NovaWAF - API 路径级防护策略（联动管理控制台 novawaf:pathpolicy）
// 数据来源：Redis JSON 数组，元素：
//   {"id":1,"name":"portal-observe","prefix":"/api/portal/*","action":"log","enabled":true}
//   action: "block"=拦截(默认)  "log"=仅记录/观察(命中攻击只记事件不拦截、不联动封禁)
//            "pass"=跳过 WAF 检测直接放行(等同该路径白名单；DDoS/限流等体积防护仍生效)
// 匹配：prefix 支持末尾 '*' 通配；否则按目录前缀匹配(/a 命中 /a 与 /a/...)；最长(最具体)前缀优先。
// 热加载：版本号 novawaf:pathpolicy:version 变化时整体原子替换，热路径 match 无锁。
#pragma once

#include "novawaf/core/json.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace novawaf {

class PathPolicy {
public:
    enum class Verdict { NONE, BLOCK, LOG, PASS };

    static PathPolicy& instance() { static PathPolicy inst; return inst; }

    // 解析 JSON 并原子替换。返回启用条数；解析失败保留旧快照。
    size_t reload(const std::string& jsonBlob) {
        auto next = std::make_shared<Snapshot>();
        if (!jsonBlob.empty()) {
            JsonValue root;
            try { root = parseJson(jsonBlob); } catch (...) { auto old = snap_.load(); return old ? old->items.size() : 0; }
            if (root.isArray()) {
                for (auto& it : root.arr) {
                    if (!it.isObject()) continue;
                    const JsonValue& en = it.at("enabled");
                    if (en.isBool() && !en.b) continue;
                    const JsonValue& pf = it.at("prefix");
                    if (!pf.isString() || pf.str.empty()) continue;
                    Item m;
                    m.prefix = normalize(pf.str);
                    if (m.prefix.empty()) continue;
                    if (m.prefix.back() == '*') {          // 末尾通配
                        m.wildcard = true;
                        m.matchBase = m.prefix.substr(0, m.prefix.size() - 1);
                    } else {
                        m.wildcard = false;
                        m.matchBase = m.prefix;
                    }
                    const JsonValue& act = it.at("action");
                    if (act.isString()) {
                        if (act.str == "log")       m.verdict = Verdict::LOG;
                        else if (act.str == "pass") m.verdict = Verdict::PASS;
                        else                        m.verdict = Verdict::BLOCK;
                    }
                    next->items.push_back(std::move(m));
                }
            }
        }
        // 最具体(最长)前缀优先匹配
        std::sort(next->items.begin(), next->items.end(),
                  [](const Item& a, const Item& b){ return a.matchBase.size() > b.matchBase.size(); });
        size_t n = next->items.size();
        snap_.store(next, std::memory_order_release);
        return n;
    }

    // 返回路径命中的策略动作；未命中返回 NONE。
    Verdict match(const std::string& path) const {
        auto s = snap_.load(std::memory_order_acquire);
        if (!s || s->items.empty() || path.empty()) return Verdict::NONE;
        for (const auto& m : s->items) {
            if (m.wildcard) {
                if (path.size() >= m.matchBase.size() &&
                    path.compare(0, m.matchBase.size(), m.matchBase) == 0) return m.verdict;
            } else {
                if (path == m.matchBase) return m.verdict;
                if (path.size() > m.matchBase.size() &&
                    path.compare(0, m.matchBase.size(), m.matchBase) == 0 &&
                    path[m.matchBase.size()] == '/') return m.verdict;
            }
        }
        return Verdict::NONE;
    }

private:
    struct Item {
        std::string prefix;     // 原始(归一化)前缀
        std::string matchBase;  // 去掉末尾 '*' 后的匹配基串
        bool wildcard = false;
        Verdict verdict = Verdict::BLOCK;
    };
    struct Snapshot { std::vector<Item> items; };
    std::atomic<std::shared_ptr<Snapshot>> snap_{std::make_shared<Snapshot>()};

    static std::string normalize(std::string p) {
        // 去空白；统一不以 '/' 开头时补 '/'；不允许包含空格等畸形输入
        while (!p.empty() && (p.front() == ' ' || p.front() == '\t')) p.erase(p.begin());
        while (!p.empty() && (p.back() == ' ' || p.back() == '\t' || p.back() == '\r' || p.back() == '\n'))
            p.pop_back();
        if (p.empty()) return p;
        if (p[0] != '/') p.insert(p.begin(), '/');
        return p;
    }
};

}  // namespace novawaf
