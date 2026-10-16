// NovaWAF - 硬件加速运行时：设备探测 / 配置热加载 / 熔断降级 / 状态上报
//
// 职责：
//   1. 启动时探测 CPU 指令集（AVX2/AVX-512/SSSE3）与 GPU/NPU（OpenCL/CUDA/HIP/CANN）。
//   2. 从 Redis novawaf:accel:config 热加载总开关与批处理参数（默认关闭）。
//   3. 维护各后端熔断器；自检失败/连续错误自动回退 SIMD->Scalar。
//   4. 周期把设备清单、后端健康、聚合计数写入 novawaf:accel:status，供管理面透传展示。
//
// 安全（等保）：
//   * 厂商库仅按固定 SONAME 白名单 dlopen，不接受环境变量/外部路径，杜绝任意库装载。
//   * 状态上报只含设备型号、驱动版本与聚合计数，不含任何业务流量内容。
//   * 主开关默认 false；Redis 不可达时保持安全默认（关闭）。
#pragma once

#include "novawaf/accel/i_matcher.h"
#include "novawaf/accel/teddy.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <dlfcn.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include "novawaf/core/redis_client.h"
#endif

namespace novawaf::accel {

// ---------------- 熔断器：CLOSED -> OPEN -> HALF_OPEN -> CLOSED ----------------
class CircuitBreaker {
public:
    void failure() {
        int n = ++failures_;
        if (state_ == BackendState::HalfOpen || n >= threshold_) {
            state_ = BackendState::Open;
            openedAt_ = clock::now();
        }
    }
    void success() { failures_ = 0; state_ = BackendState::Closed; }
    // OPEN 超过冷却窗口后放行一次试探 -> HALF_OPEN
    bool allow() {
        if (state_ != BackendState::Open) return true;
        if (clock::now() - openedAt_ >= std::chrono::seconds(cooldownSec_)) {
            state_ = BackendState::HalfOpen;
            return true;
        }
        return false;
    }
    BackendState state() const { return state_; }
    void setUnavailable() { state_ = BackendState::Unavailable; }

private:
    using clock = std::chrono::steady_clock;
    BackendState state_ = BackendState::Closed;
    int failures_ = 0;
    int threshold_ = 3;
    int cooldownSec_ = 60;
    clock::time_point openedAt_{};
};

struct DeviceInfo {
    std::string type;      // cpu / gpu / npu
    std::string vendor;
    std::string name;
    std::string driver;
    std::string backend;   // CPU/OpenCL/CUDA/HIP/CANN
    int computeUnits = 0;
    bool healthy = false;
};

struct AccelConfig {
    bool enabled = false;                 // 默认关闭
    std::string preferredBackend = "auto";
    int batchGateMinN = 8;
    int batchMaxWaitUs = 2000;
    bool offloadIocRebuild = true;
    int64_t updatedAt = 0;
};

#if defined(__linux__)
// Redis 短连接辅助（仅后台线程使用，不进请求热路径）
inline void redisGetEnvKey(const char* key, std::string& out) {
    const char* rh = std::getenv("NOVA_REDIS_HOST");
    if (!rh || !*rh) return;
    int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
    const char* pass = std::getenv("NOVA_REDIS_PASS");
    int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
    RedisClient r;
    if (r.connect(rh, port, pass ? pass : "", db)) {
        if (auto v = r.get(key)) out = *v;
    }
}
inline void redisSetEnvKey(const char* key, const std::string& val) {
    const char* rh = std::getenv("NOVA_REDIS_HOST");
    if (!rh || !*rh) return;
    int port = std::getenv("NOVA_REDIS_PORT") ? std::atoi(std::getenv("NOVA_REDIS_PORT")) : 6379;
    const char* pass = std::getenv("NOVA_REDIS_PASS");
    int db = std::getenv("NOVA_REDIS_DB") ? std::atoi(std::getenv("NOVA_REDIS_DB")) : 0;
    RedisClient r;
    if (r.connect(rh, port, pass ? pass : "", db)) r.set(key, val);
}
#endif

class AccelRuntime {
public:
    static AccelRuntime& instance() {
        static AccelRuntime inst;
        return inst;
    }

    // 启动探测 + 后台配置轮询/状态上报（main 调用一次）
    void start() {
        probeCpu();
        probeGpuNpu();
        simdHealthy_ = runSelfTest();
        {
            std::lock_guard<std::mutex> lk(mu_);
            lastRaw_ = readRawConfig();
            applyConfigLocked(parseConfig(lastRaw_));
        }
#if defined(__linux__)
        if (started_.exchange(true)) return;
        std::thread([this] {
            int tick = 0;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                std::string raw = readRawConfig();
                bool changed = false;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (raw != lastRaw_) { lastRaw_ = raw; applyConfigLocked(parseConfig(raw)); changed = true; }
                }
                (void)changed;
                if ((++tick % 3) == 0) publishStatus();  // 每 ~6s 上报一次
            }
        }).detach();
#endif
    }

    AccelConfig config() const {
        std::lock_guard<std::mutex> lk(mu_);
        return config_;
    }
    std::vector<DeviceInfo> devices() const {
        std::lock_guard<std::mutex> lk(mu_);
        return devices_;
    }
    bool simdHealthy() const { return simdHealthy_.load(); }
    SimdLevel simdLevel() const { return simdLevel_; }

    // 管理面展示用状态 JSON（仅设备/健康/聚合统计，不含业务数据）
    std::string statusJson() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::string s;
        s.reserve(896);
        s += "{\"enabled\":"; s += config_.enabled ? "true" : "false";
        s += ",\"preferredBackend\":\"" + esc(config_.preferredBackend) + "\"";
        s += ",\"activeBackend\":\"" + std::string(backendName(activeBackend())) + "\"";
        s += ",\"batchGateMinN\":" + std::to_string(config_.batchGateMinN);
        s += ",\"batchMaxWaitUs\":" + std::to_string(config_.batchMaxWaitUs);
        s += ",\"offloadIocRebuild\":"; s += config_.offloadIocRebuild ? "true" : "false";
        s += ",\"cpu\":{\"model\":\"" + esc(cpuModel_) + "\",\"vendor\":\"" + esc(cpuVendor_) +
             "\",\"cores\":" + std::to_string(cpuCores_) +
             ",\"simd\":\"" + simdName() + "\",\"flags\":\"" + esc(cpuFlags_) + "\"}";
        s += ",\"devices\":[";
        for (size_t i = 0; i < devices_.size(); ++i) {
            const auto& d = devices_[i];
            if (i) s += ",";
            s += "{\"type\":\"" + esc(d.type) + "\",\"vendor\":\"" + esc(d.vendor) +
                 "\",\"name\":\"" + esc(d.name) + "\",\"driver\":\"" + esc(d.driver) +
                 "\",\"backend\":\"" + esc(d.backend) + "\",\"computeUnits\":" +
                 std::to_string(d.computeUnits) + ",\"healthy\":" + (d.healthy ? "true" : "false") + "}";
        }
        s += "],\"backends\":[";
        appendBackend(s, BackendKind::Scalar, BackendState::Closed, "baseline");
        appendBackend(s, BackendKind::SimdAVX2, simdLevel_ >= SimdLevel::AVX2
                        ? BackendState::Closed : BackendState::Unavailable, "");
        appendBackend(s, BackendKind::SimdAVX512, simdLevel_ >= SimdLevel::AVX512
                        ? BackendState::Closed : BackendState::Unavailable, "");
        appendBackend(s, BackendKind::OpenCL, openclBr_.state(), openclDetail_);
        appendBackend(s, BackendKind::CUDA, cudaBr_.state(), cudaDetail_);
        appendBackend(s, BackendKind::HIP, hipBr_.state(), hipDetail_);
        appendBackend(s, BackendKind::CANN, cannBr_.state(), cannDetail_);
        s += "],\"stats\":{";
        s += "\"scans\":" + std::to_string(totalScans()) +
             ",\"rejected\":" + std::to_string(totalRejected()) +
             ",\"confirmed\":" + std::to_string(totalConfirmed()) +
             ",\"fallback\":" + std::to_string(totalFallback()) +
             ",\"batchFlush\":0,\"gpuBatch\":0";
        s += "},\"updatedAt\":" + std::to_string(config_.updatedAt) + "}";
        return s;
    }

    // 黄金样本自检：锚点预筛必须与暴力子串匹配完全一致；不一致判 SIMD 不健康（熔断回 Scalar）
    static bool runSelfTest() {
        static const std::vector<std::string> pats = {
            "union select", "<script", "../", "javascript:", "sleep(", "or 1=1", "concat("};
        AnchorSet A;
        if (!A.build(pats)) return false;
        static const char* cases[] = {
            "1 UNION SELECT password", "<script>alert(1)</script>", "../../etc/passwd",
            "javascript:alert(1)", "id=1;select sleep(5)", "normal clean request /index.html",
            "or 1=1--", "concat(user)", "hello world no hit", "x<scr ipt y"};
        for (const char* t : cases) {
            bool fast = anchorContainsAny(std::string_view(t), A);
            bool gold = bruteForceAny(pats, std::string_view(t));
            if (fast != gold) { countFallback(); return false; }
        }
        return true;
    }

private:
    AccelRuntime() = default;
    AccelRuntime(const AccelRuntime&) = delete;
    AccelRuntime& operator=(const AccelRuntime&) = delete;

    mutable std::mutex mu_;
    std::atomic<bool> started_{false};
    std::atomic<bool> simdHealthy_{false};
    SimdLevel simdLevel_ = SimdLevel::None;
    std::string cpuModel_, cpuVendor_, cpuFlags_;
    int cpuCores_ = 0;
    std::vector<DeviceInfo> devices_;
    AccelConfig config_;
    std::string lastRaw_;
    CircuitBreaker openclBr_, cudaBr_, hipBr_, cannBr_;
    std::string openclDetail_, cudaDetail_, hipDetail_, cannDetail_;

    static std::string esc(const std::string& v) {
        std::string o;
        o.reserve(v.size());
        for (char c : v) {
            if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
            else if (c == '\n' || c == '\r') o.push_back(' ');
            else o.push_back(c);
        }
        return o;
    }
    static void appendBackend(std::string& s, BackendKind k, BackendState st,
                              const std::string& detail) {
        if (s.back() != '[') s += ",";
        s += "{\"name\":\"" + std::string(backendName(k)) + "\",\"state\":\"" +
             stateName(st) + "\",\"detail\":\"" + esc(detail) + "\"}";
    }
    const char* simdName() const {
        switch (simdLevel_) {
            case SimdLevel::AVX512: return "AVX-512";
            case SimdLevel::AVX2:   return "AVX2";
            case SimdLevel::SSSE3:  return "SSSE3";
            default:                return "none";
        }
    }

    void probeCpu() {
        simdLevel_ = detectSimdLevel();
        cpuCores_ = (int)std::thread::hardware_concurrency();
#if defined(__linux__)
        std::ifstream f("/proc/cpuinfo");
        std::string line;
        while (std::getline(f, line)) {
            if (cpuModel_.empty() && line.rfind("model name", 0) == 0) {
                auto p = line.find(':');
                if (p != std::string::npos) cpuModel_ = trim(line.substr(p + 1));
            }
            if (cpuVendor_.empty() && line.rfind("vendor_id", 0) == 0) {
                auto p = line.find(':');
                if (p != std::string::npos) cpuVendor_ = trim(line.substr(p + 1));
            }
            if (line.rfind("flags", 0) == 0 || line.rfind("Features", 0) == 0) {
                auto p = line.find(':');
                if (p != std::string::npos) {
                    std::string all = trim(line.substr(p + 1));
                    static const char* want[] = {"ssse3", "sse4_2", "avx", "avx2", "avx512f",
                                                 "pclmulqdq", "bmi2", "popcnt"};
                    for (const char* w : want)
                        if (all.find(w) != std::string::npos) { if (!cpuFlags_.empty()) cpuFlags_ += ' '; cpuFlags_ += w; }
                }
                break;
            }
        }
#else
        cpuModel_ = "unknown(non-linux)";
        cpuVendor_ = "unknown";
#endif
        DeviceInfo cpu;
        cpu.type = "cpu"; cpu.vendor = cpuVendor_; cpu.name = cpuModel_;
        cpu.backend = (simdLevel_ >= SimdLevel::AVX2) ? "AVX2" : "Scalar";
        cpu.computeUnits = cpuCores_; cpu.healthy = true;
        devices_.push_back(cpu);
    }
    static std::string trim(std::string s) {
        size_t a = s.find_first_not_of(" \t");
        size_t b = s.find_last_not_of(" \t\r\n");
        if (a == std::string::npos) return "";
        return s.substr(a, b - a + 1);
    }

#if defined(__linux__)
    // ---- 固定 SONAME 白名单（安全：不读环境变量、不接受路径） ----
    static void* openWhitelisted(const char* soname) {
        return ::dlopen(soname, RTLD_LAZY | RTLD_LOCAL);
    }
    template <typename Fn>
    static Fn sym(void* h, const char* name) {
        return h ? reinterpret_cast<Fn>(::dlsym(h, name)) : nullptr;
    }

    void probeOpenCL() {
        void* h = openWhitelisted("libOpenCL.so.1");
        if (!h) { openclDetail_ = "libOpenCL.so.1 not found"; openclBr_.setUnavailable(); return; }
        using clGetPlatformIDs_t = int(*)(unsigned, void**, unsigned*);
        using clGetDeviceIDs_t = int(*)(void*, unsigned long, unsigned, void**, unsigned*);
        using clGetDeviceInfo_t = int(*)(void*, unsigned, size_t, void*, size_t*);
        auto getPlatforms = sym<clGetPlatformIDs_t>(h, "clGetPlatformIDs");
        auto getDevices = sym<clGetDeviceIDs_t>(h, "clGetDeviceIDs");
        auto getInfo = sym<clGetDeviceInfo_t>(h, "clGetDeviceInfo");
        if (!getPlatforms || !getDevices || !getInfo) {
            openclDetail_ = "OpenCL symbols missing"; openclBr_.setUnavailable(); ::dlclose(h); return;
        }
        unsigned np = 0;
        if (getPlatforms(0, nullptr, &np) != 0 || np == 0) {
            openclDetail_ = "no OpenCL platform"; openclBr_.setUnavailable(); ::dlclose(h); return;
        }
        std::vector<void*> plats(np);
        getPlatforms(np, plats.data(), nullptr);
        constexpr unsigned long CL_DEVICE_TYPE_ALL = 0xFFFFFFFFUL;
        constexpr unsigned CL_DEVICE_MAX_COMPUTE_UNITS = 0x1002;
        constexpr unsigned CL_DEVICE_NAME = 0x102B;
        constexpr unsigned CL_DEVICE_VENDOR = 0x102C;
        constexpr unsigned CL_DRIVER_VERSION = 0x102D;
        int found = 0;
        for (void* plat : plats) {
            unsigned nd = 0;
            if (getDevices(plat, CL_DEVICE_TYPE_ALL, 0, nullptr, &nd) != 0 || nd == 0) continue;
            std::vector<void*> devs(nd);
            getDevices(plat, CL_DEVICE_TYPE_ALL, nd, devs.data(), nullptr);
            for (void* dev : devs) {
                auto getStr = [&](unsigned name)->std::string {
                    char buf[256] = {0}; size_t sz = 0;
                    if (getInfo(dev, name, sizeof(buf), buf, &sz) == 0) return std::string(buf);
                    return "";
                };
                DeviceInfo d;
                d.type = "gpu"; d.backend = "OpenCL"; d.healthy = true;
                d.vendor = getStr(CL_DEVICE_VENDOR);
                d.name = getStr(CL_DEVICE_NAME);
                d.driver = getStr(CL_DRIVER_VERSION);
                unsigned units = 0;
                if (getInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(units), &units, nullptr) == 0)
                    d.computeUnits = (int)units;
                devices_.push_back(d);
                ++found;
            }
        }
        if (found) { openclBr_.success(); openclDetail_ = std::to_string(found) + " OpenCL device(s)"; }
        else { openclBr_.setUnavailable(); openclDetail_ = "no OpenCL device"; }
        ::dlclose(h);
    }

    void probeCuda() {
        void* h = openWhitelisted("libcuda.so.1");
        if (!h) { cudaBr_.setUnavailable(); return; }
        using cuInit_t = int(*)(unsigned);
        using cuGetCount_t = int(*)(int*);
        auto init = sym<cuInit_t>(h, "cuInit");
        auto cnt = sym<cuGetCount_t>(h, "cuDeviceGetCount");
        int n = 0;
        if (init && cnt && init(0) == 0 && cnt(&n) == 0 && n > 0) {
            cudaBr_.success(); cudaDetail_ = std::to_string(n) + " CUDA device(s)";
        } else { cudaBr_.setUnavailable(); }
        ::dlclose(h);
    }

    void probeHip() {
        void* h = openWhitelisted("libamdhip64.so");
        if (!h) h = openWhitelisted("libamdhip64.so.5");
        if (!h) { hipBr_.setUnavailable(); return; }
        using getCount_t = int(*)(int*);
        auto cnt = sym<getCount_t>(h, "hipGetDeviceCount");
        int n = 0;
        if (cnt && cnt(&n) == 0 && n > 0) {
            hipBr_.success(); hipDetail_ = std::to_string(n) + " HIP/DCU device(s)";
        } else { hipBr_.setUnavailable(); }
        ::dlclose(h);
    }

    void probeCann() {
        bool hasNode = (::access("/dev/davinci0", F_OK) == 0);
        void* h = openWhitelisted("libascendcl.so");
        if (h || hasNode) {
            cannBr_.success();
            cannDetail_ = hasNode ? "Ascend NPU node + libascendcl" : "libascendcl loaded";
        } else { cannBr_.setUnavailable(); }
        if (h) ::dlclose(h);
    }

    void probeGpuNpu() { probeOpenCL(); probeCuda(); probeHip(); probeCann(); }

    std::string readRawConfig() {
        std::string raw;
        if (const char* rh = std::getenv("NOVA_REDIS_HOST"); rh && *rh)
            redisGetEnvKey("novawaf:accel:config", raw);
        return raw;
    }
    void publishStatus() { redisSetEnvKey("novawaf:accel:status", statusJson()); }

    static bool jsonBool(const std::string& j, const char* k, bool def) {
        auto p = j.find(k); if (p == std::string::npos) return def;
        p = j.find(':', p); if (p == std::string::npos) return def;
        size_t i = p + 1; while (i < j.size() && (j[i]==' '||j[i]=='\t')) ++i;
        if (j.compare(i, 4, "true") == 0) return true;
        if (j.compare(i, 5, "false") == 0) return false;
        return def;
    }
    static int64_t jsonInt(const std::string& j, const char* k, int64_t def) {
        auto p = j.find(k); if (p == std::string::npos) return def;
        p = j.find(':', p); if (p == std::string::npos) return def;
        char* end = nullptr;
        long long v = std::strtoll(j.c_str() + p + 1, &end, 10);
        return end == j.c_str() + p + 1 ? def : (int64_t)v;
    }
    static std::string jsonStr(const std::string& j, const char* k, const std::string& def) {
        auto p = j.find(k); if (p == std::string::npos) return def;
        p = j.find(':', p); if (p == std::string::npos) return def;
        size_t i = p + 1; while (i < j.size() && (j[i]==' '||j[i]=='\t')) ++i;
        if (i >= j.size() || j[i] != '"') return def;
        ++i; std::string v;
        while (i < j.size() && j[i] != '"') { if (j[i]=='\\' && i+1<j.size()) ++i; v.push_back(j[i++]); }
        return v;
    }

    AccelConfig parseConfig(const std::string& raw) {
        AccelConfig cfg;  // 默认：关闭
        if (const char* e = std::getenv("NOVA_ACCEL_ENABLED")) cfg.enabled = (std::string(e) == "1");
        if (const char* e = std::getenv("NOVA_ACCEL_BACKEND")) cfg.preferredBackend = e;
        if (raw.empty()) return cfg;
        cfg.enabled = jsonBool(raw, "enabled", cfg.enabled);
        cfg.preferredBackend = jsonStr(raw, "preferredBackend", cfg.preferredBackend);
        cfg.batchGateMinN = (int)jsonInt(raw, "batchGateMinN", cfg.batchGateMinN);
        cfg.batchMaxWaitUs = (int)jsonInt(raw, "batchMaxWaitUs", cfg.batchMaxWaitUs);
        cfg.offloadIocRebuild = jsonBool(raw, "offloadIocRebuild", cfg.offloadIocRebuild);
        cfg.updatedAt = jsonInt(raw, "updatedAt", 0);
        return cfg;
    }

    void applyConfigLocked(const AccelConfig& cfg) {
        config_ = cfg;
        setEnabled(cfg.enabled);
        bool forceScalar = (cfg.preferredBackend == "scalar");
        if (cfg.enabled && !forceScalar && simdHealthy_.load() &&
            simdLevel_ >= SimdLevel::SSSE3) {
            setActiveBackend(simdLevel_ >= SimdLevel::AVX512 ? BackendKind::SimdAVX512
                           : simdLevel_ >= SimdLevel::AVX2   ? BackendKind::SimdAVX2
                                                             : BackendKind::SimdAVX2);
        } else {
            setActiveBackend(BackendKind::Scalar);
        }
    }
#else
    void probeGpuNpu() {}
    std::string readRawConfig() { return ""; }
    void publishStatus() {}
    AccelConfig parseConfig(const std::string&) {
        AccelConfig cfg;
        if (const char* e = std::getenv("NOVA_ACCEL_ENABLED")) cfg.enabled = (std::string(e) == "1");
        return cfg;
    }
    void applyConfigLocked(const AccelConfig& cfg) {
        config_ = cfg;
        setEnabled(cfg.enabled);
        setActiveBackend(cfg.enabled && simdHealthy_.load() ? BackendKind::SimdAVX2
                                                            : BackendKind::Scalar);
    }
#endif
};

}  // namespace novawaf::accel
