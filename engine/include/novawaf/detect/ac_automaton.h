// NovaWAF - Aho-Corasick 多模式匹配自动机
// 用于关键词预筛：O(n) 扫描一次即可命中所有规则关键词，是检测流水线的第一道快速过滤。
#pragma once

#include "novawaf/accel/teddy.h"

#include <cstdint>
#include <memory>
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
        // 同步构建 Teddy 锚点（硬件加速快路径）。不可用时 anchors_->usable=false，
        // containsAny 自动回退下面的标量 AC，检测语义完全不变。
        anchors_ = std::make_unique<accel::AnchorSet>();
        anchors_->build(patterns_);
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
        // 硬件加速快路径：总开关开启且本自动机锚点可用时，走 Teddy（AVX2/SSSE3，运行时分发）。
        // Teddy 仅做精确锚点预筛 + 整串确认，结果与 AC 完全等价（零漏报）；任一条件不满足回退 AC。
        if (anchors_ && anchors_->usable && accel::teddyActive()) {
            bool hit = accel::anchorContainsAny(std::string_view(text), *anchors_);
            accel::countTeddy(hit);
            return hit;
        }
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
    bool accelUsable() const { return anchors_ && anchors_->usable; }

private:
    struct Node {
        int children[256] = {0};
        int fail = 0;
        std::vector<int> output;
    };

    std::vector<Node> nodes_;
    std::vector<std::string> patterns_;
    std::unique_ptr<accel::AnchorSet> anchors_;
    bool built_ = false;
};

}  // namespace novawaf
