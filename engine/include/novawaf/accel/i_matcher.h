// NovaWAF - 硬件加速：批量匹配后端的统一抽象与后端枚举
// 设计见 docs/design/2026-10-16-gpu-acceleration-design.md
//
// 安全/稳定性约束：
//   * 加速只做“必要条件预筛”，最终判定仍回原 AC/语义逻辑，保证零漏报。
//   * 加速总开关默认关闭；无设备/自检失败/连续错误时自动熔断回 Scalar。
//   * GPU/NPU 厂商库只允许固定 SONAME 白名单 dlopen，内核源码内嵌，不接受外部传入。
#pragma once

#include <cstdint>

namespace novawaf::accel {

// 加速后端种类。Scalar 永远可用（基线）；其余按需探测、自动降级。
enum class BackendKind : int {
    Scalar = 0,    // 标量 AC 基线（关闭加速或无硬件时）
    SimdAVX2 = 1,  // x86 AVX2 Teddy（32 字节/拍）
    SimdAVX512 = 2,// x86 AVX-512 Teddy（64 字节/拍，本机不支持则不可用）
    OpenCL = 3,    // Intel 核显 / AMD / NVIDIA 通用
    CUDA = 4,      // NVIDIA
    HIP = 5,       // AMD 新卡 / 海光 DCU
    CANN = 6       // 华为昇腾
};

inline const char* backendName(BackendKind k) {
    switch (k) {
        case BackendKind::Scalar:    return "Scalar";
        case BackendKind::SimdAVX2:  return "AVX2";
        case BackendKind::SimdAVX512:return "AVX-512";
        case BackendKind::OpenCL:    return "OpenCL";
        case BackendKind::CUDA:      return "CUDA";
        case BackendKind::HIP:       return "HIP";
        case BackendKind::CANN:      return "CANN";
    }
    return "Unknown";
}

// 后端健康状态机（配合熔断器）
enum class BackendState : int {
    Unavailable = 0,  // 无设备 / 无驱动 / 无 ICD
    Closed = 1,       // 正常可用（熔断器闭合）
    Open = 2,         // 熔断中（连续失败，已切回下层）
    HalfOpen = 3      // 半开试探（放行一次自检，成功恢复）
};

inline const char* stateName(BackendState s) {
    switch (s) {
        case BackendState::Unavailable: return "unavailable";
        case BackendState::Closed:      return "healthy";
        case BackendState::Open:        return "circuit_open";
        case BackendState::HalfOpen:    return "half_open";
    }
    return "unknown";
}

// 单次/批量匹配的最小结果载体（接口层不依赖 AnchorSet 具体布局）
struct BatchHit {
    static constexpr uint8_t kNoHit = 0;
    static constexpr uint8_t kHit = 1;
};

}  // namespace novawaf::accel
