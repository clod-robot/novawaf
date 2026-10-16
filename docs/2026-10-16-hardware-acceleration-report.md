# NovaWAF 硬件加速层 · 实测与验收报告（CPU SIMD / GPU 旁路微批）

- 日期：2026-10-16
- 状态：已上线，**默认关闭**（管理台一键热开启）
- 对应设计：[2026-10-16-gpu-acceleration-design.md](design/2026-10-16-gpu-acceleration-design.md)
- 实测机：192.168.100.2（引擎）+ 192.168.100.4（独立负载机）
- 结论口径：所有数据均为本机真实压测/单测原始结果，如实报告（含未达预期项与原因）。

---

## 1. 一页结论

1. **安全红线达成：攻击零漏报。** 端到端四组矩阵共约 **162 万请求、其中攻击约 113 万条**，
   每一组 `attack_miss = 0`；Teddy 预筛与各内核相对暴力参考做了
   **每内核 20000 条 + 8 万条随机 fuzz** 黄金一致性自检，全部一致（`FAIL:0`）。
2. **匹配子系统大幅加速。** 微基准（18 条真实规则、256MB 干净数据、4KB/请求）：
   单核吞吐 AC 标量 **0.217 → AVX2 1.639 GB/s = 7.56×（+656%）**；
   4 核聚合 **0.342 → 2.98 GB/s = 8.71×（+771%）**。
3. **短报文代理端到端 RPS 中性（−0.8% / −0.9%，即不劣化），未达成设计初稿假设的 +50%。**
   根因是 Amdahl：在该边缘盒 + 短报文负载下，瓶颈在 reactor/网络/上游（请求延迟约 100ms），
   模式匹配占比很小；匹配能力（约 8.3 万 req/s）远超代理路径上限（约 3.3k RPS）。
   详见 §4 与 §7。
4. **无 GPU/无驱动自动降级全部验证通过。** 本机 AVX2 在线、AVX-512 不可用；
   OpenCL（离线无 ICD）、CUDA、HIP、CANN 均显示 `unavailable` 并自动回退 Scalar，业务无感。
5. **全量回归零功能回归**（L1/L2/L3/L4，见 §6）；测试后已恢复生产安全基线，加速保持默认关闭。

> 对设计目标的修正：初稿“检测密集型短报文 e2e RPS ≥ +50%”是基于“匹配是主要 CPU 开销”的
> 假设。实测表明该假设在**本机短报文代理路径**上不成立；加速价值在**大报文/高规则数/
> IOC 大名单重建**等匹配占比高的场景与更强算力机型上兑现（§7）。

---

## 2. 测试环境

| 项 | 实测值 |
|---|---|
| CPU | Intel Core i5-6200U @ 2.30GHz，2 物理核 / 4 线程 |
| 指令集 | ssse3、sse4.2、avx、avx2、pclmulqdq、bmi2、popcnt；**无 AVX-512** |
| 编译器 | g++ 15.2.0，`-std=c++20 -O2 -pthread` |
| 引擎 | 4 个 SO_REUSEPORT reactor worker（`novawaf-engine 8099 4`），systemd 托管 |
| Redis | 127.0.0.1:6379（无密码，配置/状态/版本热通道） |
| 上游 | 本地应答器 127.0.0.1:18092（BENCH 应用 id=99，Host=bench.test） |
| 负载机 | 192.168.100.4，4 核，Python 3.12（磁盘满，脚本经 SSH stdin 内存执行，免落盘） |
| 工具 | `scripts/accel_bench.py`（多进程+多线程 keep-alive）、`scripts/run_matrix.py`（四组编排）、`engine/tests/bench_teddy.cpp`（匹配微基准） |

---

## 3. 功能与正确性验证

### 3.1 单元 / Fuzz（随 `test_core`，两种构建配置）

- 汇总：**`PASS: 184494  FAIL: 0`**（含 8 万条随机 fuzz）。
- Teddy 标量 / SSSE3 / AVX2 三套内核与暴力参考逐条比对，外加微基准内建自检
  **每内核 20000/20000 零不一致**。
- 正确性原理：预筛只做“必要条件”（每模式前 2 字节锚点未出现 ⇒ 必不命中）；
  有候选一律回退完整 AC 确认。只可能多做确认，**结构上不可能漏报**；
  规则加载/切换以标量 AC 为黄金基准做一致性自检，不一致即熔断该后端。

### 3.2 端到端拦截（四组矩阵）

| 组 | 匹配后端 | DDoS/CC 防护 | RPS 中位 | P99 | 攻击漏报 attack_miss |
|---|---|---|---|---|---|
| A | Scalar | 关 | 3209.7 | ~99ms | **0** |
| B | AVX2 | 关 | 3182.9（B/A = **−0.8%**） | ~98ms | **0** |
| C | Scalar | 开 | 3260.8 | ~95ms | **0** |
| D | AVX2 | 开 | 3233.0（D/C = **−0.9%**） | ~99ms | **0** |

- 条件：128 并发、70% 攻击（SQLi/XSS/CMDi）、30% 正常 GET、每组 3×60s。
- 连接错误率 < 1%（keep-alive 重连噪声）。
- 正常请求误拦：每组 12–23 条 / 约 5.8 万正常（0.03%），且 **Scalar 与 AVX2 完全一致**
  —— 属既有其他检测器现象，与 Teddy 无关（加速开关不改变任何判定结果）。
- 验收含义：**D 组在防护开启 + 洪水背景下吞吐/P99 不劣于 C，攻击拦截保持 100%**，达成。

### 3.3 DDoS / CC 防护联动（功能证据）

- 在临时收紧档（NEWCONN=20、RPS=20）下对引擎发起 96 并发连接风暴：
  观测到 **55,468 次连接被拒**。引擎 `DdosGuard::onConnect()` 对超限/封禁 IP
  在 accept 后**直接 `close()` 丢弃**（不消耗应用层资源），客户端表现为连接被重置/空 FIN；
  封禁为内存态 TTL 300s，到期自动解封，重启即清空。
- 说明：负载地址 192.168.100.4 同时承载了**其他任务**的长期发压器
  （`/tmp/loadgen.py` 已连续运行数日），为遵守任务隔离与不干扰他任务的约束，
  未在该共享 IP 上继续追求“单一 IP 的干净 HTTP 429”复现；连接层静默丢弃本身即
  标准的抗洪水处置，拦截有效性已由上述连接拒绝数与 §3.2 零漏报共同佐证。
- 恢复基线后本机复测：`/health` 与良性 `/product?id=42` = **200**，
  SQLi `UNION SELECT` 与 XSS `<script>` 均 = **403**。

---

## 4. 匹配子系统微基准（`engine/tests/bench_teddy.cpp`）

18 条真实规则、256MB 干净文本、4KB/请求，计时前预切 chunk 串以排除分配干扰：

| 内核 | 单核 GB/s | 4 核聚合 GB/s | 相对标量 AC |
|---|---|---|---|
| AC 标量基线 | 0.217 | 0.342 | 1.00× |
| Teddy 标量预筛 | 0.111 | — | 锚点过滤路径 |
| Teddy SSSE3 | 0.933 | — | 4.30× |
| **Teddy AVX2** | **1.639** | **2.98** | **单核 7.56× / 4核 8.71×** |

- 匹配子系统能力约 **8.3 万 req/s**，而本环境代理路径上限约 **3.3k RPS**，相差约 25 倍：
  匹配不是当前端到端瓶颈，故 e2e 收益被 Amdahl 稀释到噪声范围（§7）。

---

## 5. 多后端与无设备降级

管理台「硬件加速」页与 `GET /api/system/accel` 实测状态：

```
cpu  Intel i5-6200U, cores=4, simd=AVX2 (ssse3/sse4_2/avx/avx2/pclmulqdq/bmi2/popcnt)
backends:
  Scalar   healthy   (baseline)
  AVX2     healthy
  AVX-512  unavailable          # cpuid 不支持
  OpenCL   unavailable          # no OpenCL platform（离线环境无 ICD）
  CUDA     unavailable
  HIP      unavailable
  CANN     unavailable
```

- 所有 GPU/NPU 后端仅在运行时以**固定 SONAME** `dlopen`（OpenCL `libOpenCL.so.1`、
  CUDA `libcuda.so.1`+`libnvrtc.so`、HIP `libamdhip64.so`+`libhiprtc.so`、
  CANN `libascendcl.so`），构建期零厂商 SDK 依赖；加载/初始化/自检任一步失败即
  `unavailable` 并回退，不影响其他后端与业务。
- 离线环境启用 OpenCL（在有 GPU/核显且联网装包后）：

  ```bash
  sudo apt-get update && sudo apt-get install -y pocl-opencl-icd   # 通用 CPU/多设备 POCL
  # 或 Intel 核显/CPU：sudo apt-get install -y intel-opencl-icd
  # 重启或等待 6s 状态发布周期后，管理台 OpenCL 灯转 healthy，无需重新编译引擎
  ```

  本次在**无 ICD 的离线下**已验证：加载器路径探测正常、平台枚举为空时优雅降级为 Scalar。
- CUDA/HIP/CANN 已做“无设备/无运行时库”自动降级验证；对应硬件到位后装驱动即可启用，无需重新编译。

---

## 6. 全量回归（恢复基线后，本机真实执行）

`scripts/long_test_full.py`（L1 存活 / L2 接口 / L3 热加载）+ `scripts/l4_stress.py`（L4 远程）：

- **L1 PASS**：8099 引擎 / 18081 后端 / 9000 前端端口均通，Redis OK，引擎日志近 10 分钟无 ERROR/CRITICAL。
- **L2 PASS：13/13**：登录成功/无 token 401、Geo 策略保存与非法 mode、IP 组 CRUD/同名拒绝/
  导入/条目/删除、部署配置与 NAT 探测等全部符合预期码。
- **L3 PASS（热加载）**：Geo 保存后版本号 `396 → 398` 引擎日志增量生效；
  IOC 校验和 `a5849ce7cf4f5915` 存在；iplist version = 377。
- **L4（自 100.4 打 9000，三接口）`fail=0`、`login_ok=true`**：
  - 登录压测：10 成功 / 0 失败（bcrypt 校验本身约 1.7s/次，为限速型重端点，非缺陷）；
  - `/waf/ipgroup/list`：174 成功，p50 66ms / p99 314ms；
  - `/waf/iplist?type=black`：36 成功，p99 约 1.55s。
  - L4 延迟偏高系该 4 核机同时承载他任务约 3.2 万 req/s 的 :8099 洪水所致（共址竞争），
    **全程零失败、零错误码**，功能正确。

---

## 7. 为何 e2e 未达 +50%（Amdahl 根因，如实分析）

1. **瓶颈不在匹配。** 微基准显示匹配能力约 8.3 万 req/s，而代理端到端被 reactor、
   socket、上游往返限制在约 3.3k RPS；开启 AVX2 后引擎 CPU 仍约 98% 饱和，
   但消耗主要在系统态/网络与转发，单请求延迟约 100ms。
2. **短报文放大不了匹配占比。** GET 短请求参与扫描的文本很短，Teddy 的单请求扫描
   本就只占极小时间片；把这部分加速 7.5× 对总时延的改善落在测量噪声内（±1%）。
3. **加速的兑现场景**（已在微基准验证其上限）：
   - 大 Body 检测（大 POST / 文件上传 WAF 检查）；
   - 高规则数 / 大 IOC 名单下的多模式扫描与 IOC 重建旁路批处理；
   - 核数更多、网络与上游不再是瓶颈的机型（AVX-512、GPU 微批闸门可进一步摊薄）。
4. **大 POST 的独立发现（与加速无关，不在本期继续追）**：单发良性 16KB POST 为
   11–27ms/200；但 128 并发时 Scalar 与 AVX2 **都**塌缩到约 92 RPS、CPU 仅约 72%，
   说明瓶颈在 body/AI 复核流水线（非 CPU、非匹配），不是硬件加速层问题。

---

## 8. 安全与等保合规设计

- **默认关闭、最小变更**：`novawaf:accel:config.enabled=false`，`activeBackend=Scalar`；
  开启加速不改变任何拦截判定结果（预筛仅做零漏报的必要条件过滤）。
- **零外部内核注入**：GPU/NPU 的 RTC 内核源码全部内嵌于引擎二进制，自检黄金样本内置；
  运行时库以固定 SONAME + 全路径候选 `dlopen` 白名单加载，不执行任何外部传入内核。
- **熔断保业务连续性**：连续失败 / 内核超时即 OPEN，自动回退 SIMD→Scalar，60s 后半开试探。
- **权限与审计**：开关/参数写入需 `system:accel:edit` 权限，复用现有 `@RequirePerms`
  与审计日志；配置经 Redis `version` 通道热生效（引擎 2s 轮询）。
- **最小暴露面**：`novawaf:accel:status` 仅含设备型号/驱动版本/聚合计数，
  不含任何业务流量内容或载荷。
- **降级可信**：无设备/无驱动/自检失败均安全回退，保证在国产/存量等无 GPU 环境中功能一致。

---

## 9. 交付物清单

- 引擎：`engine/include/novawaf/accel/teddy.h`、`accel_runtime.h`、
  `engine/include/novawaf/detect/ac_automaton.h` 接入、`engine/src/main.cpp`、`engine/CMakeLists.txt`、
  新增微基准 `engine/tests/bench_teddy.cpp` 与 `engine/tests/test_core.cpp` 用例。
- 管理面后端：`admin-server` 的 `AccelService` / `AccelController`（含菜单与 SQL）。
- 管理面前端：`admin-web` 的 `Accel.vue`、路由、布局菜单、API 封装。
- 脚本：`scripts/accel_remote.py`、`accel_redis.py`、`accel_api_check.py`、
  `bench_origin.py`、`accel_bench.py`、`run_matrix.py`、`long_test_full.py`、`l4_stress.py`。
- 文档：设计文档与本报告。

## 10. 测试后现场（已恢复安全基线）

- 删除本次临时 systemd drop-in `/etc/systemd/system/novawaf-engine.service.d/override.conf`，
  保留目录内原有 `bench.conf`、`trusted-proxy.conf`；已 `daemon-reload` 并重启，服务 active，内存封禁清空。
- 加速配置恢复 `enabled=false`，状态确认 `activeBackend=Scalar`。
- 清理了本任务回归遗留的 `l4_stress.py` 孤儿进程；**未改动**其他任务的 `loadgen.py` 等进程与其文件。
