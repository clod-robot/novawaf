# NovaWAF

高性能 Web 应用防火墙（WAF）。C++20 自研检测引擎（多 Reactor + epoll），管理面含 C++(Drogon) 控制台与 Spring Boot 后端 + Vue 前端，XDP/eBPF 内核态前置过滤，Nginx 网关接入，检测数据与控制指令经 Redis 解耦。

## 架构

```
客户端 → Nginx 网关(TLS/反代) → C++ 检测引擎 → 回源业务
                ↑                    ↓ 事件/统计落 Redis
           管理控制台 / 管理后端(Vue+Spring Boot) ← 规则下发(热加载)
流量入口 → XDP/eBPF 内核态前置过滤(可选，线速丢黑名单/畸形包)
```

- **检测引擎（C++20）**：多 Reactor（epoll + SO_REUSEPORT）、无锁 MPMC 队列、线程池、零拷贝 Buffer、Aho-Corasick 多模式匹配、递归解码器、责任链检测流水线、令牌桶限流。纯逻辑核心平台无关。
- **异步反向代理**：上游连接池 + keep-alive 复用，支持普通响应、chunked 解码、以及 SSE/WebSocket 流式双向中继（边收边发，不缓冲断流）。
- **前置过滤（XDP/eBPF）**：网卡驱动层丢弃黑名单 IP / 畸形包，线速处理。
- **网关（Nginx）**：TLS 终结与反向代理，业务流量送检引擎。
- **管理面**：C++(Drogon) 控制台 + Spring Boot 后端（RBAC、JWT、操作审计）+ Vue3 前端大屏，规则/应用模式热更新，不碰数据面。

## 已实现功能

### 检测与防护
| 类别 | 能力 |
|---|---|
| 注入类 | SQLi、XSS、RCE/命令注入、SSTI、SSRF、路径遍历、XXE |
| 行为类 | CC 防护、Bot 行为识别、动态自适应屏蔽、JA4/HTTP 指纹 |
| 地理 | GeoIP 地理围栏（离线 CIDR→国家，黑/白名单，XFF 真实 IP） |
| 洪水 | DDoS/速率/并发限流、连接级防护、自动封禁联动 |
| 内容/文件 | YARA 规则扫描、OLE/Office 宏检测、勒索软件熵检测、ClamAV 流式杀毒 |
| 情报 | 威胁情报 IOC 匹配、外部情报富集 |

### 代理与可用性
- 反向代理 + 上游连接池 / keep-alive 复用
- **SSE / WebSocket(WSS) 流式双向中继**：长连接协议经 WAF 透传且受请求层防护
- **chunked 响应正确解码**：避免无 Content-Length 响应阻塞到超时
- 引擎故障 fail-open（不影响业务可用性）

### 管理与运营
- 规则 CRUD + Redis 热加载（`novawaf:rules`），无需重启
- 应用三模式：防护 / 观察 / 维护，热切换
- 安全态势大屏：攻击事件、流量统计、TopN 落 Redis + 统计 API
- RBAC 权限、JWT 鉴权、操作审计日志
- 防火墙（iptables/nftables）自动封禁联动

## 目录结构

```
novawaf/
├── engine/          C++20 检测引擎 (核心)
├── xdp/             XDP/eBPF 内核态过滤器
├── gateway/         Nginx 网关配置示例
├── console/         C++(Drogon) 管理控制台
├── admin-server/    Spring Boot 管理后端 (RBAC/JWT/审计)
├── admin-web/       Vue3 管理前端 (大屏/规则/应用)
├── management/      早期 Spring Boot 管理后台 (保留)
├── rules/           默认规则
├── yara-rules/      YARA 规则
├── deploy/          Docker / systemd / 编排
└── scripts/         构建与部署脚本
```

## 快速开始

### 引擎构建（Linux，需 g++、libyara）
```bash
cd engine
g++ -std=c++20 -O2 -pthread -I include src/main.cpp -o novawaf-engine -lpthread -lyara
NOVA_REDIS_HOST=127.0.0.1 ./novawaf-engine 8099 4   # 端口 线程数
```
或 `bash scripts/build.sh`（CMake），`ctest --test-dir build` 跑单测。

### 管理后端
```bash
cd admin-server && mvn -DskipTests package
java -jar target/novawaf-admin.jar        # 默认 :18081
```

### 管理前端
```bash
cd admin-web && npm install && npm run build
# 产物 admin-web/dist 部署到 nginx 站点目录
```

### Docker 编排
```bash
cd deploy && docker compose up -d
```

## 配置（环境变量，节选）
| 变量 | 说明 |
|---|---|
| `NOVA_REDIS_HOST/PORT/PASS/DB` | Redis 连接（规则/事件/统计） |
| `NOVA_YARA_RULES` | YARA 规则目录 |
| `NOVA_GEO_BLOCK` / `NOVA_GEO_ALLOW` | 国家黑/白名单，逗号分隔 |
| `NOVAAI_ENABLE/ENDPOINT/MODEL` | AI 深度审核（可选，异步非阻塞） |
| `NOVA_IO_THREADS` | 上游异步转发线程数 |

## 性能
实测经 WAF 转发较直连仅增加 **~2-3ms** 开销（chunked/普通/SSE 响应）。

## 安全合规
- 管理面全接口认证 + RBAC + BCrypt + JWT
- 引擎故障 fail-open，规则热加载不重启、操作可审计
- 安全响应头（CSP / X-Frame-Options / nosniff 等）由网关与后端统一注入

## 开源协议
本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）**，详见 [LICENSE](./LICENSE)。强 copyleft：修改后必须开源；作为网络服务对外提供时同样需向用户提供修改后的源代码。

Copyright © 2026 NovaWAF Contributors.
