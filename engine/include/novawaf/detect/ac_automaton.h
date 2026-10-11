// NovaWAF - Aho-Corasick 多模式匹配自动机
// 用于关键词预筛：O(n) 扫描一次即可命中所有规则关键词，是检测流水线的第一道快速过滤。
#pragma once

#include <cstdint>
#include <queue>
#include <string>
#include <vector>

namespace novawaf {

class AcAutomaton {
public:
    AcAutomaton() { nodes_.emplace_back(); }

    // 添加一个模式串，返回其 id
    int addPattern(const std::string& pattern) {
        int cur = 0;
        for (unsigned char c : pattern) {
            if (nodes_[cur].children[c] == 0) {
                nodes_[cur].children[c] = static_cast<int>(nodes_.size());
                nodes_.emplace_back();
            }
            cur = nodes_[cur].children[c];
        }
        nodes_[cur].output.push_back(static_cast<int>(patterns_.size()));
        patterns_.push_back(pattern);
        built_ = false;
        return static_cast<int>(patterns_.size()) - 1;
    }

    // 构建 failure 指针（必须在所有 pattern 添加后调用一次）
    void build() {
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            if (nodes_[0].children[c] != 0) {
                nodes_[nodes_[0].children[c]].fail = 0;
                q.push(nodes_[0].children[c]);
            }
        }
        while (!q.empty()) {
            int u = q.front();
            q.pop();
            for (int c = 0; c < 256; ++c) {
                int v = nodes_[u].children[c];
                if (v != 0) {
                    int f = nodes_[u].fail;
                    while (f != 0 && nodes_[f].children[c] == 0)
                        f = nodes_[f].fail;
                    nodes_[v].fail = nodes_[f].children[c];
                    // 合并输出
                    for (int o : nodes_[nodes_[v].fail].output)
                        nodes_[v].output.push_back(o);
                    q.push(v);
                }
            }
        }
        built_ = true;
    }

    struct Hit {
        int patternId;
        size_t endPos;  // 命中结束位置
    };

    // 扫描文本，返回所有命中
    std::vector<Hit> scan(const std::string& text) const {
        std::vector<Hit> hits;
        if (!built_) return hits;
        int cur = 0;
        for (size_t i = 0; i < text.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            while (cur != 0 && nodes_[cur].children[c] == 0)
                cur = nodes_[cur].fail;
            cur = nodes_[cur].children[c];
            for (int pid : nodes_[cur].output)
                hits.push_back({pid, i});
        }
        return hits;
    }

    bool containsAny(const std::string& text) const {
        if (!built_) return false;
        int cur = 0;
        for (size_t i = 0; i < text.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            while (cur != 0 && nodes_[cur].children[c] == 0)
                cur = nodes_[cur].fail;
            cur = nodes_[cur].children[c];
            if (!nodes_[cur].output.empty()) return true;
        }
        return false;
    }

    size_t patternCount() const { return patterns_.size(); }
    const std::string& pattern(int id) const { return patterns_[id]; }

private:
    struct Node {
        int children[256] = {0};
        int fail = 0;
        std::vector<int> output;
    };

    std::vector<Node> nodes_;
    std::vector<std::string> patterns_;
    bool built_ = false;
};

}  // namespace novawaf
