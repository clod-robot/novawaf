// NovaWAF - 检测流水线（责任链模式）
// 按顺序执行各检测器，任一命中即短路返回。
// 性能关键：detect() 热路径无锁 —— 检测器只读，用 shared_ptr 原子交换实现 copy-on-write 热更新。
#pragma once

#include "novawaf/detect/detectors.h"
#include "novawaf/detect/http_model.h"

#include <atomic>
#include <memory>
#include <vector>

namespace novawaf {

class DetectionPipeline {
public:
    using DetectorList = std::vector<std::unique_ptr<IDetector>>;

    DetectionPipeline() {
        auto list = std::make_shared<DetectorList>();
        // 威胁情报优先（IOC 命中即处置，最快）
        list->push_back(std::make_unique<SqlInjectionDetector>());
        list->push_back(std::make_unique<XssDetector>());
        list->push_back(std::make_unique<CommandInjectionDetector>());
        list->push_back(std::make_unique<PathTraversalDetector>());
        list->push_back(std::make_unique<SstiDetector>());
        list->push_back(std::make_unique<XxeDetector>());
        list->push_back(std::make_unique<SsrfDetector>());
        list->push_back(std::make_unique<CrlfDetector>());
        // 反序列化/代码注入/上传/CSRF（专项，置于通用泄露与扫描器之前）
        list->push_back(std::make_unique<FileUploadDetector>());
        list->push_back(std::make_unique<JavaCodeInjectionDetector>());
        list->push_back(std::make_unique<JavaDeserializationDetector>());
        list->push_back(std::make_unique<PhpDeserializationDetector>());
        list->push_back(std::make_unique<AspCodeInjectionDetector>());
        list->push_back(std::make_unique<CsrfDetector>());
        list->push_back(std::make_unique<InfoLeakDetector>());
        list->push_back(std::make_unique<ScannerDetector>());
        detectors_.store(list, std::memory_order_release);
    }

    // 热更新：整体替换检测器列表（copy-on-write，与 detect 无锁竞争）
    void setDetectors(std::shared_ptr<DetectorList> list) {
        detectors_.store(list, std::memory_order_release);
    }

    void addDetector(std::unique_ptr<IDetector> d) {
        auto cur = detectors_.load(std::memory_order_acquire);
        auto next = std::make_shared<DetectorList>();
        next->reserve(cur->size() + 1);
        for (auto& up : *cur) next->push_back(up->clone());
        next->push_back(std::move(d));
        detectors_.store(next, std::memory_order_release);
    }

    // 无锁检测入口：原子 load 一次 shared_ptr，期间检测器只读
    DetectionResult detect(const HttpRequest& req) {
        auto list = detectors_.load(std::memory_order_acquire);
        for (auto& d : *list) {
            DetectionResult r = d->detect(req);
            if (r.action != Action::PASS) return r;
        }
        return {};
    }

    size_t detectorCount() const {
        return detectors_.load(std::memory_order_acquire)->size();
    }

private:
    std::atomic<std::shared_ptr<DetectorList>> detectors_;
};

}  // namespace novawaf
