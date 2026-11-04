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
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
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

    // 命中路径对应的诱饵键（精确诱饵=路径本身；前缀诱饵=命中的前缀）。
    // 未命中返回空串。供「按不同诱饵计数」的升级判定使用（/.git/config 与
    // /.git/HEAD 同属 "/.git/*" 一个诱饵，避免同一诱饵翻文件刷计数）。
    std::string keyFor(const std::string& path) const {
        auto tbl = table_.load();
        if (!tbl) return {};
        if (tbl->exact.count(path)) return path;
        const TrieNode* node = &tbl->trieRoot;
        const TrieNode* lastTerm = nullptr;
        size_t depth = 0, termDepth = 0;
        for (char c : path) {
            auto it = node->ch.find(c);
            if (it == node->ch.end()) break;
            node = it->second.get();
            ++depth;
            if (node->terminal) { lastTerm = node; termDepth = depth; }
        }
        if (!lastTerm) return {};
        return path.substr(0, termDepth) + "*";
    }

    // 命中记账的返回：distinct 供升级判定；isNew 标识本次是否窗口内首次触达
    // 该诱饵，供上层抑制重复观察事件（同一攻击者对同一诱饵的高频重复访问
    // 只记一条，不再逐条刷屏事件流）。
    struct HitInfo {
        int distinct = 0;
        bool isNew = false;
    };

    // 命中记账：滑窗（默认 600s，NOVA_HONEY_WIN_SEC）内不同诱饵计数。
    // distinct 达到升级阈值（NOVA_HONEY_ESCALATE_N，默认 3）后由上层升级为封禁。
    // 设计依据（复测设计评审）：「命中即封禁」让攻击者立刻知晓被处置、取证链
    // 中断；改为「记录+打标+诱饵放行」，触达 N 个不同诱饵（扫描器踩点特征，
    // 正常用户数学上不可能触达多个无链接路径）再升级。
    HitInfo noteHit(const std::string& ip, const std::string& baitKey) {
        int64_t now = (int64_t)time(nullptr);
        auto& sh = hitShards_[std::hash<std::string>{}(ip) & (kHitShards - 1)];
        std::lock_guard<std::mutex> lk(sh.mtx);
        auto& st = sh.hits[ip];
        if (now - st.winStart >= winSec_) { st.winStart = now; st.baits.clear(); }
        bool isNew = st.baits.insert(baitKey).second;
        // 惰性回收：单片超 512 时清理窗口外 IP，防内存增长
        if (sh.hits.size() > 512) {
            for (auto it = sh.hits.begin(); it != sh.hits.end();) {
                if (now - it->second.winStart >= winSec_) it = sh.hits.erase(it);
                else ++it;
            }
        }
        return {(int)st.baits.size(), isNew};
    }

    // 升级阈值（不同诱饵数），供上层判定
    static int escalateN() {
        const char* e = std::getenv("NOVA_HONEY_ESCALATE_N");
        return (e && *e) ? std::atoi(e) : 3;
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

    // 命中记账（升级判定用）：分片锁，IP → 窗口起点 + 已触达诱饵集合
    struct HitState {
        int64_t winStart = 0;
        std::unordered_set<std::string> baits;
    };
    struct HitShard {
        std::mutex mtx;
        std::unordered_map<std::string, HitState> hits;
    };
    static constexpr size_t kHitShards = 16;
    HitShard hitShards_[kHitShards];
    const int64_t winSec_ = [] {
        const char* e = std::getenv("NOVA_HONEY_WIN_SEC");
        return (e && *e) ? (int64_t)std::atoll(e) : (int64_t)600;
    }();
};

}  // namespace novawaf
