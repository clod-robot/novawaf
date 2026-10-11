// NovaWAF - 检测流水线（责任链模式）
// 按顺序执行各检测器，任一命中即短路返回。支持运行时增删检测器、规则热加载。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

namespace novawaf {

class DetectionPipeline {
public:
    DetectionPipeline() {
        // 默认加载全套检测器
        detectors_.push_back(std::make_unique<SqlInjectionDetector>());
        detectors_.push_back(std::make_unique<XssDetector>());
        detectors_.push_back(std::make_unique<CommandInjectionDetector>());
        detectors_.push_back(std::make_unique<PathTraversalDetector>());
    }

    void addDetector(std::unique_ptr<IDetector> d) {
        std::lock_guard<std::mutex> lk(mtx_);
        detectors_.push_back(std::move(d));
    }

    // 线程安全的检测入口（共享只读，热更新时整体替换）
    DetectionResult detect(const HttpRequest& req) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& d : detectors_) {
            DetectionResult r = d->detect(req);
            if (r.action != Action::PASS) return r;
        }
        return {};
    }

    size_t detectorCount() const { return detectors_.size(); }

private:
    mutable std::mutex mtx_;
    std::vector<std::unique_ptr<IDetector>> detectors_;
};

}  // namespace novawaf
