# NovaWAF 运行包 · 部署手册

开箱即用的 Linux 运行包，无需在目标机编译。包含：检测引擎二进制、管理后端 jar、管理前端静态资源、规则数据、捆绑的 libyara，以及一键安装/启停脚本。

## 包结构
```
novawaf-release/
├── bin/   novawaf-engine(ELF)  novawaf-admin.jar
├── lib/   libyara.so.10（引擎运行依赖）
├── web/   管理前端静态文件（部署到 nginx 站点根）
├── rules/ yara/ geoip.txt ioc.txt default_rules.json
├── conf/  novawaf-engine.service(systemd)  application.yml  nac.conf(nginx 示例)
├── install.sh  start.sh  stop.sh  status.sh
├── env.example
└── README-部署.md
```

## 环境要求
- Linux x86_64（内核 ≥ 3.2），已验证 Debian/Ubuntu 系
- Java 17+（运行管理后端 jar）
- Redis（规则热加载 / 事件 / 统计；`apt install redis-server`）
- Nginx（作为网关反代到引擎 8099；可选，引擎也可直连）
- 建议 root 或具备 sudo

## 最短路径启动
```bash
tar xzf novawaf-release.tar.gz
cd novawaf-release
sudo ./install.sh            # 幂等安装到 /opt/novawaf
# 首次安装会生成 /opt/novawaf/novawaf.env，按实际修改 Redis/端口
sudo /opt/novawaf/start.sh
sudo /opt/novawaf/status.sh  # 确认 :8099 与 :18081 监听
```
- 管理前端：把 `web/` 内容放到 nginx 站点根（如 `/var/www/novawaf-admin`），反代 `/api` → `127.0.0.1:18081`
- 业务流量：nginx 反代到引擎 `127.0.0.1:8099`，由引擎转发到业务网关；参考 `conf/nac.conf`
- 默认管理账号：`admin / admin123`（首次登录后请修改）

## 配置清单（必改项 checklist）
| 项 | 文件 | 说明 |
|---|---|---|
| 引擎端口 | `novawaf.env` ENGINE_PORT | 网关反代目标，默认 8099 |
| 管理后端端口 | `novawaf.env` ADMIN_PORT | 默认 18081 |
| Redis 地址/密码 | `novawaf.env` NOVA_REDIS_* | 规则与事件中枢 |
| 可信反向代理 | `novawaf.env`/systemd 单元 `NOVA_TRUSTED_PROXIES` | 网关地址；仅命中才采信 XFF/X-Real-IP，同机填 `127.0.0.1` |
| 网关透传真实IP | nginx 站点配置 | XFF 必须用 `$remote_addr`（替换式），勿用 `$proxy_add_x_forwarded_for`（可被伪造） |
| 引擎→业务上游 | 引擎 apps 配置 / Redis `novawaf:apps` | 受保护业务的 host:port |
| 站点域名/证书 | nginx 站点配置 | 生产请配 TLS |

## 多端口路由约束
系统存在多后端，路由关系固定如下，改端口需同步修改对应文件：
| 前缀 | 目标 | 涉及配置 |
|---|---|---|
| 业务 `/api`、`/ws`、SSE | 引擎 8099 → 业务网关 | nginx 站点 + 引擎 apps 配置 |
| 管理 `/api` | 管理后端 18081 | 管理前端 nginx 反代 |

## 常用操作
```bash
/opt/novawaf/start.sh    # 启动
/opt/novawaf/stop.sh     # 停止
/opt/novawaf/status.sh   # 状态
journalctl -u novawaf-engine -f   # 引擎日志（若用 systemd）
tail -f /opt/novawaf/logs/engine.log /opt/novawaf/logs/admin.log
```

## 安全合规建议
- 生产环境修改默认管理员密码；管理面启用 TLS
- 规则热加载不重启、操作经后端审计落库
- 引擎故障由网关 fail-open 保障业务可用性
- 源 IP 识别：网关以替换式 `$remote_addr` 透传真实 IP，并在引擎 `NOVA_TRUSTED_PROXIES` 中加入网关地址；NAT 类型决定能否还原外网真实源 IP（DNAT 保留 / L7 注入 XFF / SNAT 丢失，详见仓库 README「源 IP 识别与网关 NAT」）

## 许可证
AGPL-3.0，详见源码仓库 LICENSE。
