// NovaWAF - 蜜罐诱捕检测（Honeypot）
// 思路：部署一批正常用户永不触达的诱饵路径（/.git/、/wp-admin、/phpmyadmin 等），
// 它们不在站点地图、无任何页面链接、业务从不引用——任何访问即为确定性恶意探测
// （扫描器/手工踩点），命中即阻断并联动防火墙封禁源 IP，实现「发现即阻断」。
//
// 设计模式：单例 + COW（copy-on-write）热更新——后台 Redis 加载线程构建新表，
// 原子交换发布；多 reactor 热路径经 atomic<shared_ptr<const>> 无锁读，零拷贝零加锁。
// 高级算法：精确路径走哈希集 O(1)，前缀诱饵走 Trie 逐字符下降 O(path 长度)，
// 内存占用与诱饵条数线性、与路径长度共享前缀压缩。
#pragma once

#include <atomic>
#include <cctype>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "novawaf/detect/http_model.h"

namespace novawaf {

class HoneypotGuard {
public:
    static HoneypotGuard& instance() {
        static HoneypotGuard g;
        return g;
    }

    // 判定请求路径是否命中蜜罐诱饵。命中返回 BLOCK（HONEYPOT-001）。
    // 热路径无锁：读取当前发布的不可变表。
    DetectionResult assess(const std::string& path) const {
        auto tbl = table_.load();
        if (!tbl) return {};
        // 精确诱饵（哈希 O(1)）
        if (tbl->exact.count(path)) {
            return {Action::BLOCK, "HONEYPOT-001", "Honeypot",
                    "honeypot trap touched", path};
        }
        // 前缀诱饵（Trie 下降，途经 terminal 即命中）
        const TrieNode* node = &tbl->trieRoot;
        for (char c : path) {
            auto it = node->ch.find(c);
            if (it == node->ch.end()) { node = nullptr; break; }
            node = it->second.get();
            if (node->terminal) break;  // 命中最短前缀即可，无需继续下降
        }
        if (node && node->terminal) {
            return {Action::BLOCK, "HONEYPOT-001", "Honeypot",
                    "honeypot prefix touched", path};
        }
        return {};
    }

    // 热加载诱饵清单（后台线程调用）。文本格式：每行一条路径；
    // 行尾 * 表示前缀诱饵（如 /.git/* 匹配其下所有路径），否则精确匹配；
    // # 开头为注释。内置默认诱饵集始终并入，外部清单为增量补充。
    // 返回当前生效诱饵总条数（含内置）。
    size_t reload(const std::string& blob) {
        auto tbl = std::make_shared<Table>();
        for (const char* d : kDefaults) addLine(*tbl, d);
        for (const std::string& raw : splitLines(blob)) {
            std::string line = trim(raw);
            if (line.empty() || line[0] == '#') continue;
            addLine(*tbl, line);
        }
        table_.store(std::shared_ptr<const Table>(std::move(tbl)));
        return tableCount();
    }

    // 当前生效诱饵条数（观测用）
    size_t tableCount() const {
        auto tbl = table_.load();
        return tbl ? tbl->count : 0;
    }

private:
    HoneypotGuard() { reload(""); }  // 内置默认诱饵开箱即用

    struct TrieNode {
        std::unordered_map<char, std::unique_ptr<TrieNode>> ch;
        bool terminal = false;
    };
    struct Table {
        std::unordered_set<std::string> exact;  // 精确诱饵
        TrieNode trieRoot;                      // 前缀诱饵 Trie
        size_t count = 0;
    };

    // 内置默认诱饵：全部是与本站业务（/nac/、/api/）零交集的经典踩点路径。
    // 前缀诱饵以 * 结尾。
    static constexpr const char* kDefaults[] = {
        "/.git/*", "/.svn/*", "/.hg/*", "/.env", "/.aws/*", "/.ssh/*",
        "/wp-admin/*", "/wp-login.php", "/wp-includes/*", "/wordpress/*",
        "/phpmyadmin/*", "/pma/*", "/phpinfo.php", "/admin.php",
        "/shell.php", "/c99.php", "/r57.php", "/cmd.php",
        "/backup.sql", "/backup.zip", "/db.sql", "/dump.sql",
        "/config.php.bak", "/web.config", "/server-status",
        "/actuator/*", "/HNAP1/*", "/solr/*", "/jenkins/*",
    };

    static void addLine(Table& t, const std::string& line) {
        if (line.size() < 2 || line[0] != '/') return;  // 诱饵必须是绝对路径
        if (line.back() == '*') {
            std::string pfx = line.substr(0, line.size() - 1);
            if (pfx.empty()) return;
            TrieNode* node = &t.trieRoot;
            for (char c : pfx) node = node->ch.try_emplace(c, std::make_unique<TrieNode>()).first->second.get();
            if (!node->terminal) { node->terminal = true; t.count++; }
        } else {
            if (t.exact.insert(line).second) t.count++;
        }
    }

    static std::vector<std::string> splitLines(const std::string& blob) {
        std::vector<std::string> lines;
        std::string cur;
        for (char c : blob) {
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else if (c != '\r') cur += c;
        }
        if (!cur.empty()) lines.push_back(cur);
        return lines;
    }
    static std::string trim(const std::string& s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace((unsigned char)s[a])) a++;
        while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
        return s.substr(a, b - a);
    }

    // COW 发布点：C++20 std::atomic<shared_ptr> 原子读写，热路径无锁
    std::atomic<std::shared_ptr<const Table>> table_;
};

}  // namespace novawaf
