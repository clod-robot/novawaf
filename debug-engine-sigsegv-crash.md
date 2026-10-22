# 调试记录: engine-sigsegv-crash

## 症状
- novawaf-engine (C++, systemd: novawaf-engine.service, :8099) 7 天 SIGSEGV 崩溃 185 次
- 10-21 单日 64 次，约 5~8 分钟一次
- 崩溃窗口内经引擎反代的 /api 直接 502（已观测 /api/waf/stream 502×2、10-20 18:52 /api/auth/system/info 502）
- 用户要求：优先排查 core dump，定位根因

## 环境
- 服务器 192.168.100.2，二进制 /home/mao/novawaf/bin/novawaf-engine
- 修复前编译: g++ -std=c++20 -O2 -I include src/main.cpp -pthread -lyara（无 -g/-rdynamic）
- 修复后编译: g++ -std=c++20 -O2 -g -rdynamic -I include src/main.cpp -o /tmp/novawaf-engine-new -pthread -lyara
- 最近部署: 10-21 (ev:archive 归档队列), 10-22 09:22 (policyId 策略计数链路)
- DEBUG_EVIDENCE_DIR: C:\Users\Administrator\AppData\Local\Temp\trae-debug\engine-sigsegv-crash
- 证据源: dmesg segfault 记录 + journalctl + nm 符号反查 + 代码审计
- core dump 已启用：core_pattern=/tmp/core.%e.%p.%t + systemd override LimitCORE=infinity

## 假设
- H1: 历史遗留崩溃，早于近期部署，与新代码无关 → 验证: 崩溃时间线 vs 部署时间
- H2: conns 跨线程数据竞争（结构性缺陷）→ 验证: 崩溃栈位置 + 代码审计
- H3: YARA 扫描段错误 → 验证: core 栈帧在 yara_*
- H4: GeoIP/IP 解析畸形输入 → 验证: 栈在 geo/ip 路径
- H5: Redis 重连回调野指针 → 验证: 崩溃前 Redis 错误日志 + 栈在 hiredis

## 证据链

### 1. 崩溃时间线（journalctl + dmesg）
- 10-19 15:00 起爆发（此前 ~2 次/天基线），跨 10-21/10-22 多个构建持续
- 结论：非单次部署引入（H1 部分成立：历史问题），但需解释爆发时机

### 2. 崩溃点定位（dmesg ip 偏移 + nm 反查，当前构建 3 次崩溃 09:14/09:21/09:30）
- `ip ...+14cf0 error 4 in novawaf-engine[...]` → nm 反查 = `_Map_base<int, ConnState>::operator[]`（0x14cb0 邻域）
- `ip ...+13730` → `_Hashtable<ConnState>::erase(int)`（0x136b0 邻域）
- 0x139d0 = onComplete lambda（UpstreamForwarder IO 线程回调）
- 三次崩溃全部落在 `std::unordered_map<int, ConnState>` 模板函数内，栈不在 yara/geo/hiredis

### 3. 代码审计（engine/src/main.cpp reactorLoop）
- `conns`（unordered_map<int, ConnState>）在 reactor 线程 ~10 处无锁访问（accept 插入 / read append / inbuf.erase / outQ.assign / lastActiveMs 更新 / find）
- UpstreamForwarder 完成回调 onComplete 在 **IO 线程**执行（upstream_forwarder.h L52 注释明示），回调内无锁 `conns.find/erase`
- 结论：unordered_map 并发读写 → rehash 时 reactor 线程迭代器/桶指针失效 → SIGSEGV。error 4（用户态读越权）与 rehash 踩空一致
- H1 确认（历史结构缺陷，10-15 onComplete 机制 34f20b2 引入，10-19 洪水压测后流量模式触发爆发）；H2 确认为根因；H3/H4/H5 排除（栈不在对应符号域）

## 最小修复（2026-10-22，main.cpp）
1. **conns 全访问点统一 busyMtx 加锁**：reactor 线程所有访问点 + IO 线程 onComplete 回调统一持 `busyMtx`；EPOLLOUT 排空块重构为「锁内决策 / 锁外 closeConn」；onComplete 内先 epoll_ctl 挂回再解锁，避免 reactor 看到未注册非 busy fd 的窗口
2. **SIGSEGV/SIGBUS 自取证 handler**（`// region debug-point segv-bt`）：崩溃时写 /tmp/novawaf-crash.log（时间戳 + backtrace 48 帧 + backtrace_symbols_fd，glibc 免 malloc）后恢复 SIG_DFL 重抛，供 systemd 产生 core
3. 编译带 `-g -rdynamic`，崩溃栈可直接符号化

## 部署（2026-10-22 10:16）
- 上传 md5: 7971a4b6e090c2298550586fb7395ad6（本地=远程一致）
- 编译 exit=0；部署 /home/mao/novawaf/bin/novawaf-engine；10:16:09 启动
- 验证：service active、NRestarts=0、/tmp/novawaf-crash.log 不存在、journal 无错误
- 代理链路：Host a.test→200、Host b.test→200、Host nac→500（上游 192.168.100.2:8080 直连同 500，为上游应用自身行为，非引擎问题）

## 假设结论
- H1: CONFIRMED（崩溃为历史结构缺陷，非近期单次部署引入）
- H2: CONFIRMED（根因：conns 跨线程无锁数据竞争）
- H3/H4/H5: REJECTED（崩溃栈全部在 unordered_map<ConnState> 模板内）

## Post-fix 验证
- 判定标准：修复前 5~8 分钟一崩（30 分钟窗口预期崩 4~6 次）；修复后 NRestarts 保持 0 且 /tmp/novawaf-crash.log 无新增即为根因实证
- [2026-10-22 10:16 部署] 修复版二进制：10:16→10:37 运行 21 分钟，NRestarts=0、无 crash.log（随后因 uri/host 功能部署正常重启）
- [2026-10-22 10:37 部署] 修复+uri/host 版二进制：至 10:51 运行 14 分钟，NRestarts=0、无 crash.log、无新 core
- 累计 35 分钟 0 崩溃（修复前同窗口预期崩 4~6 次）→ **根因实证，修复生效**
