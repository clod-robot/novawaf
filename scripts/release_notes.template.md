## NovaWAF {{TAG}}

{{PRERELEASE_TEXT}}

### 新特性
- **CVE 虚拟补丁管理界面**：管理控制台新增「CVE虚拟补丁」页（列表/新增/编辑/启停/删除/JSON 导入导出/下发保存/热加载），补丁格式内置说明
- **RegexPatchDetector**：正则虚拟补丁挂入同一检测链（ECMAScript|icase，COW 无锁热更），ReDoS 护栏（≤100 条/≤256 字符/禁嵌套量词/body 扫前 16KB）
- 字面量补丁走 AC 多模（Aho-Corasick 单自动机），正则补丁补复杂指纹场景
- 既有特性：SIEM 出口（webhook/syslog）、响应 DLP 脱敏、CVE 虚拟补丁引擎

### 版本号管理
- 仓库根 `VERSION` 文件为唯一事实源（{{VERSION}}）
- admin-server `pom.xml` / admin-web `package.json` 同步
- 引擎 `NOVAWAF_VERSION` 宏，启动横幅打印版本

### 制品
| 文件 | 说明 |
|---|---|
| `novawaf-engine_{{VERSION}}_linux_amd64` | WAF 检测引擎（Ubuntu 22.04 x86_64, g++ -O2, 依赖 libyara） |
| `novawaf-admin_{{VERSION}}.jar` | 管理控制台后端（Spring Boot 3 / JDK21，端口 18081） |
| `novawaf-admin-web_{{VERSION}}.tar.gz` | 管理控制台前端静态包（解压至 nginx 站点目录） |

部署要点：引擎 systemd `novawaf-engine`；admin `java -jar`（systemd `novawaf-admin`）；前端解压至 `/var/www/novawaf-admin`。Redis 为热更通道（规则/补丁/应用配置）。
