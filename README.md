# NovaWAF

高性能 Web 应用防火墙（WAF）。采用 C++20 重写检测引擎，Spring Boot 管理面，XDP/eBPF 内核态前置过滤，Nginx 网关接入。

## 架构

```
流量 → XDP/eBPF 前置过滤(内核态) → Nginx 网关 → C++ 检测引擎 → 回源
                                         ↑ 规则下发/日志上报
                                   Spring Boot 管理面
```

- **检测引擎（C++20）**：多 Reactor（epoll + SO_REUSEPORT）、无锁 MPMC 队列、线程池、零拷贝 Buffer、Aho-Corasick 多模式匹配、递归解码器、责任链检测流水线、令牌桶限流。纯逻辑核心平台无关，已通过 35 项单元测试。
- **前置过滤（XDP/eBPF）**：网卡驱动层丢弃黑名单 IP / 畸形包，线速处理。
- **网关（Nginx）**：复用成熟组件做 TLS 终结与反向代理，通过子请求送检。
- **管理面（Spring Boot）**：规则管理、日志查询、RBAC（Spring Security），不碰数据面。

## 目录结构

```
novawaf/
├── engine/        C++20 检测引擎 (核心)
├── xdp/           XDP/eBPF 内核态过滤器
├── gateway/       Nginx 网关配置
├── management/    Spring Boot 管理后台
├── rules/         默认规则
├── deploy/        Docker / systemd / 编排
└── scripts/       构建与部署脚本
```

## 快速开始

### Linux 一键构建
```bash
bash scripts/build.sh
./build/novawaf-engine 8080        # 启动引擎
ctest --test-dir build --output-on-failure   # 跑单测
```

### Docker 编排
```bash
cd deploy && docker compose up -d
```

### 管理后台
```bash
cd management && mvn spring-boot:run   # http://localhost:9000
```

## 性能目标
| 配置 | 预期 QPS | P99 |
|------|---------|-----|
| 4C8G | 3~5 万 | <2ms |
| 16C32G | 20 万+ | <1ms |

## 安全合规
- 管理面全接口认证 + RBAC + BCrypt
- 检测引擎故障 fail-open（网关层保证可用性）
- 规则热加载不重启、操作可审计
