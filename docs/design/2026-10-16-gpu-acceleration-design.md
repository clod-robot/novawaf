# NovaWAF 硬件加速层设计（CPU SIMD / OpenCL / CUDA / HIP / 昇腾 CANN）

- 日期：2026-10-16
- 状态：已上线（总开关默认关闭）。实测与验收结论见
  [2026-10-16-hardware-acceleration-report.md](../2026-10-16-hardware-acceleration-report.md)；
  §7.2 中“短报文 e2e ≥ +50%”的预测经本机实测修正为“匹配子系统 7.56×、短报文代理 e2e 中性不劣化”。
- 适用模块：`engine/`（C++20 检测引擎）、`admin-server/`（Java 管理面）、`admin-web/`（Vue 管理台）

## 1. 背景与目标

NovaWAF 检测引擎在线热路径为「HTTP 解析 → 17 个规则检测器（每个内部都跑一次
Aho-Corasick `containsAny` 扫描）→ AI 复核 → 事件/转发」。检测密集型流量下，
同一请求文本被重复全量扫描十余次，是主要 CPU 开销。

本设计引入统一硬件加速层，目标：

1. **性能**：检测密集型负载下 RPS 提升目标 **≥ 50%**（加速开 vs 关，同硬件同负载）。
2. **自适应降级**：服务器无 GPU / 无驱动 / 加速内核自检失败 / 运行期连续出错时，
   自动熔断回退到 CPU SIMD，再回退到标量 AC，业务不中断。
3. **可观测可控制**：管理台「硬件加速」页显示当前服务器 CPU/GPU/NPU 设备参数、
   运行时与健康状态，提供总开关（**未识别到可用加速设备时默认关闭**）与批参数，
   配置热生效。
4. **一份二进制到处跑**：所有 GPU/NPU 后端只在运行时 `dlopen` 厂商运行时库，
   构建期零厂商 SDK 依赖；无卡机器编译/运行不受任何影响。
5. **多厂商**：Intel / AMD CPU（AVX2/AVX-512）、Intel 核显与各厂商 OpenCL 设备、
   NVIDIA CUDA、AMD GPU 与海光 DCU（HIP/ROCm）、华为昇腾（CANN/AscendCL）。

## 2. 关键技术判断

### 2.1 在线 WAF 场景 GPU 的适用性

- 单请求检测为微秒级，PCIe H2D/D2H 一次 10–50μs，同步逐请求调用 GPU 是负优化。
- GPU 收益来自**批量并行**：
  - **数据面微批闸门**：epoll 一轮返回多个就绪连接（DDoS/高并发时 n 很大）时，
    对整批请求文本做一次批量多模式扫描，无命中请求直接跳过全部 AC 型检测器；
  - **旁路批量**：大 IOC 名单重建（去重/规整）、设备自检、规则编译期校验。
- CPU 侧收益来自 **SIMD Teddy 预筛**（Intel Hyperscan 的同款核心思想：
  nibble-shuffle 向量查表做候选过滤，候选再交 AC 确认），单请求同步执行、零等待，
  是常态流量的主要收益来源。

### 2.2 正确性论证（零漏报是安全产品红线）

预筛只做「必要条件」判断：对每个模式取前 2 字节锚点，锚点未出现则模式必不命中。

- 单文本路径：Teddy 无候选 ⇒ 该 AC 自动机必无命中，可直接返回 `false`；
  有候选则回退完整 AC 确认。可能多做确认，绝不漏报。
- 批量路径：批量文本取 `Decoder::normalize(整个请求原始字节)`，
  其结果在字节序列上包含各检测字段（path/query/header/body）各自 normalize 的结果
  （URL/HTML 解码只做局部展开，整串解码是字段解码的超集方向）。
  整串无锚点候选 ⇒ 所有字段的 AC 扫描必无命中 ⇒ 可安全跳过纯 AC 型检测器；
  有候选则走完整检测流水线。跨界解码只会产生额外候选（误报方向，安全）。
- GPU/SIMD 内核与标量内核共享同一份锚点表与同一套语义；
  规则加载/切换时以标量 AC 结果为黄金基准做一致性自检，不一致则该后端熔断。

## 3. 总体架构

```
                         管理台「硬件加速」页 (admin-web/Accel.vue)
                                     │ GET/PUT /api/system/accel
                                     ▼
                          AccelController (Java)
                                     │  Redis
              novawaf:accel:config / novawaf:accel:status / :version
                                     │
 ┌───────────────────────────────────┴───────────────────────────────────┐
 │                              引擎进程 (C++)                             │
 │                                                                         │
 │   AccelRuntime（单例）                                                   │
 │     ├─ 设备探测：cpuid / /proc/cpuinfo / dlopen 探针 / OpenCL 平台枚举  │
 │     ├─ 配置热加载（订阅 novawaf:accel:version）                          │
 │     ├─ 后端健康自检（黄金样本一致性）+ 连续失败熔断/半开恢复             │
 │     └─ 状态周期上报 Redis（JSON）                                       │
 │                                                                         │
 │   IBatchMatcher（统一批量多模式匹配接口）                                │
 │     ├─ ScalarMatcher   标量 AC（基线，永远可用）                        │
 │     ├─ SimdMatcher     AVX2/AVX-512 Teddy，cpuid 运行时分发             │
 │     ├─ OpenClMatcher   libOpenCL.so.1，在线编译 .cl 内核（Intel/AMD/N） │
 │     ├─ CudaMatcher     libcuda.so + libnvrtc.so，RTC 编译 PTX（NVIDIA） │
 │     ├─ HipMatcher      libamdhip64.so + libhiprtc.so（AMD/海光 DCU）    │
 │     └─ CannMatcher     libascendcl.so，ACL 单算子（昇腾）               │
 │                                                                         │
 │   数据面：                                                               │
 │     [常态] AcAutomaton::containsAny → 内部 Teddy 快速排除（AVX2）       │
 │     [高并发批量] reactor 一轮事件 → batchScan → HttpRequest 预筛 hint    │
 │                  └─ 纯 AC 型检测器对 hint=0 的请求整体跳过              │
 │   旁路：IOC 重建批处理 / 周期自检                                        │
 └─────────────────────────────────────────────────────────────────────────┘
```

## 4. 核心模块设计

### 4.1 加速后端抽象 `accel/i_matcher.h`

```cpp
enum class BackendKind { Scalar, SimdAVX2, SimdAVX512, OpenCL, CUDA, HIP, CANN };

struct AnchorSet {                 // 由 AcAutomaton::build() 同步生成
    std::array<uint8_t, 2> anchor; // 每模式前 2 字节（短模式取实际长度）
    /* nibble 分桶掩码，8 模式/桶，超桶置“必确认” */
};

class IBatchMatcher {
public:
    virtual ~IBatchMatcher() = default;
    virtual BackendKind kind() const = 0;
    // 健康自检：设备初始化 + 黄金样本；失败返回 false（runtime 熔断）
    virtual bool selfCheck(const AnchorSet& a,
                           std::span<const std::string> goldenTexts) = 0;
    // 批量“是否命中任一模式锚点”，结果写 hits[i]（0/1）；语义与标量完全一致
    virtual void batchAnyAnchor(const AnchorSet& a,
                                std::span<const std::string_view> texts,
                                std::span<uint8_t> hits) = 0;
};
```

后端选择优先级（运行时探测 + 配置 + 健康状态共同决定）：

```
CUDA/HIP/CANN（配置显式指定时） > OpenCL（GPU 类设备存在） > AVX-512 > AVX2 > Scalar
```

### 4.2 Teddy 预筛 `accel/teddy.h`

- 锚点：每模式前 2 字节；按首字节高低 nibble 建 16 项 shuffle 表，
  每桶 8 个模式槽；模式数超桶容量的桶标记为 `always-confirm`（安全降级）。
- 内核：
  - 标量版：逐字节查表 AND（可移植、作黄金参考）；
  - AVX2 版：`_mm256_shuffle_epi8` 双 lane 一次处理 32 字节，
    `_mm256_movemask_epi8` 归约，2 字节锚点做跨块 carry 移位 AND；
  - AVX-512 版：一次 64 字节（`__mmask64`），供新 Intel/AMD；
  - 函数多版本：`__attribute__((target("avx2")))` + `__builtin_cpu_supports`
    运行时分发；非 x86 平台（如国产 ARM 服务器）编译期自动只保留标量版。
- 输出：`true` = 可能命中（交 AC 确认），`false` = 必无命中。

### 4.3 厂商后端（全部 dlopen + 运行时编译，零构建依赖）

| 后端 | 动态库 | 编译方式 | 设备 |
|---|---|---|---|
| OpenCL | `libOpenCL.so.1` | `clCreateProgramWithSource`+`clBuildProgram` | Intel 核显/AMD/NVIDIA/各类加速卡 |
| CUDA | `libcuda.so.1`+`libnvrtc.so` | NVRTC 编译内嵌 CUDA C 源码为 PTX，Driver API 加载 | NVIDIA GPU |
| HIP | `libamdhip64.so`+`libhiprtc.so` | hipRTC 编译内嵌 HIP 源码 | AMD GPU / 海光 DCU（同一份内核） |
| CANN | `libascendcl.so` | ACL 单算子（Equal/ReduceAny 组合） | 华为昇腾 NPU |

GPU kernel 语义：每 work-item 处理一个文本的一个 32B 块，
nibble 表放 `__constant__`/constant memory，块内归约后跨块 `reduce_or`；
批大小 = 文本数 × 块数，一维 grid 启动。

每个后端统一生命周期：`dlopen → 取函数指针 → init/deviceCount → 编译内核 →
黄金样本自检 → healthy`；任何一步失败标记 `unavailable`，不影响其他后端。

### 4.4 运行时与熔断 `accel/accel_runtime.h`

- 单例；启动探测 + 读 Redis 配置；后台线程每 5s 轮询 `novawaf:accel:version`
  热加载开关/批参数；每 30s 上报状态 JSON。
- 熔断：某后端连续 3 次调用失败（或内核执行超时 >50ms）→ OPEN（切 SIMD/Scalar），
  60s 后半开试探一次，成功则关闭熔断。
- 配置：

```json
{
  "enabled": false,              // 总开关，默认 false；识别到可用设备也需人工开启
  "preferredBackend": "auto",   // auto|opencl|cuda|hip|cann|simd
  "batchGateMinN": 8,           // reactor 一轮事件数 ≥ 该值才启用批量闸门
  "batchMaxWaitUs": 2000,       // 微批最大等待预算（保护 P99）
  "offloadIocRebuild": true,    // IOC 重建旁路加速
  "updatedAt": 0
}
```

- 状态：

```json
{
  "enabled": false, "activeBackend": "Scalar", "circuitOpen": false,
  "devices": [
    {"type":"cpu","vendor":"GenuineIntel","model":"Intel(R) Core(TM) i5-6200U ...",
     "cores":4,"features":["avx2","sse4_2","bmi2"]},
    {"type":"gpu","vendor":"Intel","model":"HD Graphics 520","backend":"opencl",
     "memoryMb":0,"driver":"","healthy":false,"reason":"OpenCL ICD 未安装"},
    {"type":"gpu","vendor":"AMD","model":"Radeon 520 Mobile","backend":"opencl",
     "memoryMb":0,"driver":"","healthy":false,"reason":"ROCm 不支持该代显卡(gfx older)"}
  ],
  "backends": {"scalar":"healthy","simd_avx2":"healthy","opencl":"unavailable",
               "cuda":"unavailable","hip":"unavailable","cann":"unavailable"},
  "stats": {"scans":0,"shortCircuited":0,"batchFlushes":0,"gpuBatches":0,"fallbacks":0},
  "updatedAt": 1792000000
}
```

### 4.5 数据面集成

1. **常态路径（无延迟风险）**：`AcAutomaton::build()` 同步构建 `AnchorSet`；
   `containsAny()` 在加速开关开启时先跑 Teddy（AVX2），无候选直接返回 `false`。
2. **批量闸门（高并发）**：reactor 每轮 `epoll_wait` 后、逐连接处理前，
   收集本轮 inbuf 已含完整请求的连接文本（normalize 后），调用
   `AccelRuntime::batchScan()`（GPU healthy 用 GPU，否则 SIMD 批量版），
   结果写入 `HttpRequest::accelHint`（0=全部 AC 必无命中）。
   - `IDetector::isPureAc()` 标识纯 AC 型检测器（SQLi/XSS/CMDi/…/Custom/Ti）；
   - `DetectionPipeline::detect()` 对 `accelHint==0 && isPureAc()` 的检测器整体跳过；
   - 非 AC 防护（Geo/CC/Bot/速率限制/AI 复核）不受影响，照常执行；
   - 单事件轮次（n<batchGateMinN）不设 hint，走常态 Teddy 路径。
3. **旁路**：IOC 大名单热加载后的规整/去重、启动与周期性黄金自检走批量接口。

## 5. 管理面设计

### 5.1 Java 后端

- `AccelService`：读写 `novawaf:accel:config/status`（状态由引擎上报，
  管理面只读透传）；保存配置后 INCR `novawaf:accel:version` 触发热生效；
  附加管理面本机 `lscpu`/`lspci` 探测结果作为交叉展示。
- `AccelController`：
  - `GET  /api/system/accel`         设备 + 后端健康 + 统计 + 配置
  - `PUT  /api/system/accel`         更新开关/参数（权限 `system:accel:edit`）
  - `POST /api/system/accel/selftest` 触发一次全后端黄金样本自检

### 5.2 前端

- 新页面 `/common/accel`「硬件加速」（系统管理分组）：
  - 设备清单表：类型/厂商/型号/核心数或显存/驱动/对应后端/健康状态；
  - 后端状态卡：Scalar/AVX2/OpenCL/CUDA/HIP/CANN 六格健康灯；
  - 控制区：总开关（默认关闭）、首选后端、批量闸门阈值、微批等待预算、
    IOC 旁路加速开关；保存即热生效；
  - 统计区：扫描总量 / 短路次数 / GPU 批次数 / 熔断回退次数。

## 6. 构建

- 默认构建仅含 Scalar + 平台原生 SIMD（x86 自动 AVX2 多版本），零外部依赖。
- GPU/NPU 后端源码始终参与编译（纯标准 C++ + `dlopen`，只需要 `<dlfcn.h>`），
  不需要安装 CUDA/ROCm/CANN SDK；运行期按需加载。
- CMake 选项：`-DNOVA_WITH_OPENCL=ON/OFF`（默认 ON，仅编译期开关，无链接依赖），
  CUDA/HIP/CANN 同理；`-DNOVA_FORCE_SCALAR=ON` 可彻底排除 SIMD 内核（兼容旧编译器）。
- 单元测试 `test_core` 新增：锚点表构建、Teddy 标量/AVX2 与 AC 黄金一致性
  （含随机 fuzz 用例）、批量接口与逐文本结果一致性、无设备后端降级、熔断器状态机。

## 7. 部署与实测方案

### 7.1 目标环境（已实测硬件）

| 节点 | 角色 | 硬件 |
|---|---|---|
| 192.168.100.2 | 被测引擎 | Intel i5-6200U（AVX2，无 AVX-512）/ HD 520 核显 / AMD Radeon 520（Oland 老核，ROCm 不支持） |
| 192.168.100.4 | 压测负载机 | Python asyncio 发压，与被测分离 |

- 本机实测范围：**Scalar vs AVX2**（确定路径）；OpenCL 视 ICD 可装性实测，
  CUDA/HIP/CANN 做无设备自动降级验证（对应硬件到位后即可启用，无需重新编译）。
- 运行时依赖：OpenCL 仅需 `intel-opencl-icd`（运行期 dlopen，缺失则自动显示
  unavailable 并降级）。

### 7.2 四组对比（核心验收）

| 组 | 加速 | DDoS 防护 | 流量 |
|---|---|---|---|
| A | 关（Scalar） | 关 | 检测密集：70% POST 带 SQLi/XSS/CMDi payload，30% 正常 GET |
| B | 开（AVX2，GPU 按可用性） | 关 | 同上 |
| C | 关（Scalar） | 开 | 同上 + HTTP Flood 攻击流（超阈值 IP） |
| D | 开（AVX2，GPU 按可用性） | 开 | 同上 |

每组 60s，3 轮取中位数。指标：RPS、p50/p95/p99、引擎 CPU%、
攻击拦截率（必须 100% 拦截测试 payload，零漏报）、错误率。
验收：B/A 的 RPS 提升 ≥ 50%；D 组在 DDoS 洪水下吞吐与 P99 不劣于 C，
攻击拦截率保持 100%。所有数据如实报告。

> 实测结论（2026-10-16，i5-6200U / 100.4 发压）：B/A = −0.8%、D/C = −0.9%（短报文代理
> 路径中性、不劣化，P99 持平），攻击零漏报；匹配微基准 AVX2 7.56×（4 核 8.71×）。
> 即“≥50% 端到端”目标在本机短报文负载上**未达成**，根因为 Amdahl（瓶颈在网络/转发而非匹配），
> 数据与分析见 [实测报告](../2026-10-16-hardware-acceleration-report.md)。

### 7.3 回归

完成后执行既有全量长时间测试守护（L1/L2/L3/L4，13 项接口回归 + 热加载 +
远程压测），确保功能零回归；新 accel 单测随 `ctest` 全绿。

## 8. 安全与等保考虑

- 总开关默认关闭；开启加速不改变任何拦截判定结果（预筛仅做无漏报的必要条件过滤）。
- GPU/NPU 运行时库以 dlopen 白名单方式加载（固定 SONAME 与全路径候选），
  不执行任何外部传入内核；RTC 内核源码全部内嵌于引擎二进制，设备自检样本内置。
- 配置写入需要管理权限与会话审计（复用现有 `@RequirePerms` + 审计日志）。
- 状态上报只含设备型号/驱动版本/聚合计数，不含业务流量内容。
