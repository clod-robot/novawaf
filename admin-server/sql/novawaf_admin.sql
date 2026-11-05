-- ============================================================
-- NovaWAF 管理后台 RBAC 库 DDL  (MySQL 8.x, utf8mb4)
-- 业务库名建议: novawaf_admin
-- 无外键约束(按业务字段关联), 全部走索引; 密码 BCrypt 存储
-- ============================================================
CREATE DATABASE IF NOT EXISTS novawaf_admin DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE novawaf_admin;

-- ---------- 用户 ----------
CREATE TABLE IF NOT EXISTS sys_user (
  id            BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
  username      VARCHAR(64)  NOT NULL COMMENT '登录名',
  password      VARCHAR(100) NOT NULL COMMENT 'BCrypt 密文',
  nickname      VARCHAR(64)  DEFAULT NULL COMMENT '昵称',
  email         VARCHAR(128) DEFAULT NULL,
  phone         VARCHAR(32)  DEFAULT NULL,
  status        TINYINT      NOT NULL DEFAULT 1 COMMENT '1启用 0禁用',
  dept_id       BIGINT       DEFAULT NULL,
  create_time   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_username (username),
  KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户';

-- ---------- 角色 ----------
CREATE TABLE IF NOT EXISTS sys_role (
  id          BIGINT      NOT NULL AUTO_INCREMENT,
  role_code   VARCHAR(64) NOT NULL COMMENT '角色编码 admin/auditor/operator',
  role_name   VARCHAR(64) NOT NULL,
  status      TINYINT     NOT NULL DEFAULT 1,
  remark      VARCHAR(255) DEFAULT NULL,
  create_time DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_role_code (role_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色';

-- ---------- 用户-角色 ----------
CREATE TABLE IF NOT EXISTS sys_user_role (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  KEY idx_role (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户角色关联';

-- ---------- 菜单/权限 ----------
CREATE TABLE IF NOT EXISTS sys_menu (
  id        BIGINT      NOT NULL AUTO_INCREMENT,
  parent_id BIGINT      NOT NULL DEFAULT 0,
  menu_name VARCHAR(64) NOT NULL,
  perms     VARCHAR(128) DEFAULT NULL COMMENT '权限标识 如 waf:log:list',
  type      TINYINT     NOT NULL COMMENT '1目录 2菜单 3按钮',
  path      VARCHAR(255) DEFAULT NULL,
  component VARCHAR(255) DEFAULT NULL,
  icon      VARCHAR(64)  DEFAULT NULL,
  sort      INT          NOT NULL DEFAULT 0,
  visible   TINYINT      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  KEY idx_parent (parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='菜单权限';

-- ---------- 角色-菜单 ----------
CREATE TABLE IF NOT EXISTS sys_role_menu (
  role_id BIGINT NOT NULL,
  menu_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, menu_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色菜单关联';

-- ---------- 登录/操作审计日志 ----------
CREATE TABLE IF NOT EXISTS sys_oper_log (
  id          BIGINT       NOT NULL AUTO_INCREMENT,
  username    VARCHAR(64)  DEFAULT NULL,
  module      VARCHAR(64)  DEFAULT NULL COMMENT '模块',
  operation   VARCHAR(255) DEFAULT NULL COMMENT '操作描述',
  method      VARCHAR(16)  DEFAULT NULL,
  ip          VARCHAR(64)  DEFAULT NULL,
  status      TINYINT      DEFAULT 1 COMMENT '1成功 0失败',
  error_msg   VARCHAR(1000) DEFAULT NULL,
  cost_ms     INT          DEFAULT NULL,
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_user (username),
  KEY idx_time (create_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='操作审计日志';

-- ---------- 登录日志 ----------
CREATE TABLE IF NOT EXISTS sys_login_log (
  id          BIGINT      NOT NULL AUTO_INCREMENT,
  username    VARCHAR(64) DEFAULT NULL,
  ip          VARCHAR(64) DEFAULT NULL,
  status      TINYINT     DEFAULT 1 COMMENT '1成功 0失败',
  msg         VARCHAR(255) DEFAULT NULL,
  create_time DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_time (create_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='登录日志';

-- ---------- API 路径级防护策略(引擎经 Redis novawaf:pathpolicy 热加载) ----------
CREATE TABLE IF NOT EXISTS waf_api_policy (
  id          BIGINT       NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64)  NOT NULL COMMENT '策略名称',
  app_id      VARCHAR(32)  DEFAULT NULL COMMENT '所属应用ID(NULL=全部应用)',
  prefix      VARCHAR(255) NOT NULL COMMENT '路径前缀，末尾*为通配',
  action      VARCHAR(16)  NOT NULL DEFAULT 'block' COMMENT '动作: block拦截/log仅记录/pass放行',
  enabled     TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否启用',
  remark      VARCHAR(255) DEFAULT NULL COMMENT '备注',
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_app_prefix (app_id, prefix),
  KEY idx_app (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API路径级防护策略';

-- ---------- 部署方式-HA配置(单行 id=1；保存后发布 Redis novawaf:deploy:config) ----------
CREATE TABLE IF NOT EXISTS waf_deploy_config (
  id          BIGINT       NOT NULL COMMENT '固定为 1',
  ha_mode     VARCHAR(16)  NOT NULL DEFAULT 'single' COMMENT 'single单机/master-backup主备/cluster集群',
  vip         VARCHAR(64)  DEFAULT NULL COMMENT '虚拟IP(可空)',
  nodes       TEXT         DEFAULT NULL COMMENT '节点JSON数组: name/ip/role/priority/enabled',
  remark      VARCHAR(255) DEFAULT NULL COMMENT '备注',
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='部署方式-HA配置(单行)';

-- ---------- IP 组(通用设置-IP组)：组元数据；条目本体在 Redis SET novawaf:ipgroup:{id} ----------
CREATE TABLE IF NOT EXISTS waf_ip_group (
  id          BIGINT       NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64)  NOT NULL COMMENT '组名',
  type        VARCHAR(16)  NOT NULL DEFAULT 'custom' COMMENT 'custom自定义/threat威胁情报',
  action      VARCHAR(16)  NOT NULL DEFAULT 'block' COMMENT 'custom生效动作: block并入黑名单/allow并入白名单; threat固定block',
  source_url  VARCHAR(512) DEFAULT NULL COMMENT '自定义源URL(手动更新拉取)',
  remark      VARCHAR(255) DEFAULT NULL COMMENT '备注',
  enabled     TINYINT      NOT NULL DEFAULT 1 COMMENT '禁用后从生效通道摘除',
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_waf_ip_group_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='IP 组';

-- ---------- GeoIP 地域访问策略(单行 id=1；保存后发布 Redis novawaf:geo:policy, 引擎 3s 热加载) ----------
CREATE TABLE IF NOT EXISTS waf_geo_policy (
  id          BIGINT      NOT NULL COMMENT '固定为 1',
  enabled     TINYINT     NOT NULL DEFAULT 0 COMMENT '策略开关',
  mode        VARCHAR(16) NOT NULL DEFAULT 'whitelist' COMMENT 'whitelist仅允许/blacklist封禁',
  countries   TEXT        DEFAULT NULL COMMENT 'ISO两位国家码JSON数组',
  update_time DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='GeoIP 地域访问策略(单行)';

-- ---------- API 资产登记清单(引擎经 Redis novawaf:api:inventory 热加载；未登记=影子，长期无流量=僵尸) ----------
CREATE TABLE IF NOT EXISTS waf_api_asset (
  id          BIGINT       NOT NULL AUTO_INCREMENT,
  app_id      VARCHAR(32)  DEFAULT NULL COMMENT '所属应用ID(NULL=全部应用)',
  method      VARCHAR(16)  NOT NULL DEFAULT 'ANY' COMMENT '请求方法，ANY发布时展开全部方法',
  path        VARCHAR(255) NOT NULL COMMENT '路径模板，支持 {id} 占位与末尾*通配',
  name        VARCHAR(128) DEFAULT NULL COMMENT '资产名称',
  owner       VARCHAR(64)  DEFAULT NULL COMMENT '责任人',
  enabled     TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否纳入已登记清单',
  remark      VARCHAR(255) DEFAULT NULL COMMENT '备注',
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_api_asset (app_id, method, path),
  KEY idx_api_asset_app (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API资产登记清单';

-- ---------- API 级别限流/令牌策略(引擎经 Redis novawaf:api:guard 热加载) ----------
CREATE TABLE IF NOT EXISTS waf_api_guard_rule (
  id             BIGINT       NOT NULL AUTO_INCREMENT,
  name           VARCHAR(64)  NOT NULL COMMENT '策略名称',
  app_id         VARCHAR(32)  DEFAULT NULL COMMENT '所属应用ID(NULL=全部应用)',
  method         VARCHAR(16)  NOT NULL DEFAULT 'ANY' COMMENT '请求方法，ANY=全部',
  path           VARCHAR(255) NOT NULL COMMENT '路径，末尾*为前缀通配',
  qps            INT          NOT NULL DEFAULT 10 COMMENT '每秒令牌数',
  burst          INT          NOT NULL DEFAULT 20 COMMENT '突发桶容量',
  scope          VARCHAR(16)  NOT NULL DEFAULT 'ip' COMMENT 'ip按IP/token按令牌/global全局',
  action         VARCHAR(16)  NOT NULL DEFAULT '429' COMMENT 'monitor仅记录/429限流/ban封禁',
  ban_sec        INT          NOT NULL DEFAULT 60 COMMENT '封禁秒数',
  token_required TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '是否要求合法令牌',
  enabled        TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否启用',
  remark         VARCHAR(255) DEFAULT NULL,
  create_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_api_guard (app_id, method, path),
  KEY idx_api_guard_app (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API级别限流策略';

-- ---------- API 防护全局配置(单行 id=1；发布 novawaf:api:guard + novawaf:dlp:config) ----------
CREATE TABLE IF NOT EXISTS waf_api_guard_config (
  id                   BIGINT       NOT NULL COMMENT '固定为 1',
  enabled              TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '限流总开关',
  stage                VARCHAR(16)  NOT NULL DEFAULT 'monitor' COMMENT 'monitor观察期/enforce正式',
  token_enabled        TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '令牌校验开关',
  token_enforce        TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '严格拒绝(0=灰度只记录)',
  token_mode           VARCHAR(16)  NOT NULL DEFAULT 'any' COMMENT 'jwt/opaque/any',
  token_alg            VARCHAR(64)  DEFAULT 'HS256' COMMENT '允许算法，逗号分隔',
  token_secret         VARCHAR(512) DEFAULT NULL COMMENT 'JWT HMAC 密钥(空=不校验签名)',
  token_max_age        INT          NOT NULL DEFAULT 86400 COMMENT '令牌最大有效期(秒)',
  token_require_iat    TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '是否强制 iat',
  token_reuse_window   INT          NOT NULL DEFAULT 60 COMMENT '令牌复用检测窗口(秒)',
  token_reuse_max_ips  INT          NOT NULL DEFAULT 8 COMMENT '窗口内最大来源IP数',
  token_enforce_reuse  TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '复用异常是否直接401',
  dlp_enabled          TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '响应脱敏开关',
  dlp_action           VARCHAR(16)  NOT NULL DEFAULT 'mask' COMMENT 'mask脱敏/log记录/block拦截/off关闭',
  dlp_max_bytes        BIGINT       NOT NULL DEFAULT 1048576 COMMENT '脱敏处理响应体上限(字节)',
  update_time          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='API防护全局配置(单行)';

-- ---------- 不透明令牌白名单(发布 Redis novawaf:api:tokens) ----------
CREATE TABLE IF NOT EXISTS waf_api_token (
  id          BIGINT       NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64)  NOT NULL COMMENT '令牌名称',
  token       VARCHAR(512) NOT NULL COMMENT '完整令牌值',
  app_id      VARCHAR(32)  DEFAULT NULL COMMENT '限定应用(NULL=全部)',
  enabled     TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否启用',
  expire_time DATETIME     DEFAULT NULL COMMENT '过期时间(NULL=永久)',
  remark      VARCHAR(255) DEFAULT NULL,
  create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_api_token (token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='不透明令牌白名单';

-- ---------- Agentic AI 引擎配置(单行 id=1；发布 novawaf:ai:agentic) ----------
CREATE TABLE IF NOT EXISTS waf_agentic_config (
  id               BIGINT       NOT NULL COMMENT '固定为 1',
  enabled          TINYINT(1)   NOT NULL DEFAULT 0 COMMENT 'Agentic引擎开关',
  block            TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '1=拦截 0=仅告警',
  threshold        DOUBLE       NOT NULL DEFAULT 0.6 COMMENT '判定阈值 0~1',
  max_steps        INT          NOT NULL DEFAULT 4 COMMENT '代理循环最大步数',
  budget_per_min   INT          NOT NULL DEFAULT 20 COMMENT '每分钟大模型调用预算',
  cache_ttl_sec    INT          NOT NULL DEFAULT 300 COMMENT '指纹判定缓存TTL(秒)',
  trace_max        INT          NOT NULL DEFAULT 2000 COMMENT '审计轨迹保留条数',
  llm_enabled      TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '大模型接入开关',
  llm_endpoint     VARCHAR(255) DEFAULT NULL COMMENT '大模型API完整地址',
  llm_api_key      VARCHAR(512) DEFAULT NULL COMMENT 'API Key(接口返回脱敏)',
  llm_model        VARCHAR(64)  DEFAULT NULL COMMENT '模型名',
  llm_timeout_ms   INT          NOT NULL DEFAULT 8000 COMMENT '调用超时(毫秒)',
  llm_max_retries  INT          NOT NULL DEFAULT 1 COMMENT '失败重试次数',
  llm_max_tokens   INT          NOT NULL DEFAULT 512 COMMENT '最大输出token',
  update_time      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Agentic AI引擎配置(单行)';

-- 单行配置初始种子：默认全部关闭，避免上线即拦截
INSERT INTO waf_api_guard_config (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id;
INSERT INTO waf_agentic_config (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id;

-- ============================================================
-- 初始数据: admin / Admin@2026 (BCrypt)
-- ============================================================
INSERT INTO sys_user (id, username, password, nickname, status) VALUES
 (1, 'admin', '$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2', '超级管理员', 1),
 (2, 'auditor', '$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2', '审计员', 1)
 ON DUPLICATE KEY UPDATE username=VALUES(username);

INSERT INTO sys_role (id, role_code, role_name, remark) VALUES
 (1, 'admin', '超级管理员', '全部权限'),
 (2, 'auditor', '审计员', '只读:日志/统计'),
 (3, 'operator', '运营员', '规则/IOC管理')
 ON DUPLICATE KEY UPDATE role_code=VALUES(role_code);

INSERT INTO sys_user_role (user_id, role_id) VALUES (1,1),(2,2)
 ON DUPLICATE KEY UPDATE role_id=VALUES(role_id);

INSERT INTO sys_menu (id, parent_id, menu_name, perms, type, path, component, sort) VALUES
 (1, 0, '仪表盘',  'dashboard',     2, '/dashboard','dashboard/index',1),
 (2, 0, 'WAF管理', NULL,           1, '/waf',      NULL,            2),
 (3, 2, '攻击日志', 'waf:log:list', 2, '/waf/log',  'waf/log',       1),
 (4, 2, '规则管理', 'waf:rule:list',2, '/waf/rule', 'waf/rule',      2),
 (5, 2, '威胁IOC', 'waf:ioc:list', 2, '/waf/ioc',  'waf/ioc',       3),
 (6, 0, '系统管理', NULL,           1, '/system',   NULL,            9),
 (7, 6, '用户管理', 'sys:user:list',2, '/system/user','system/user',1),
 (8, 6, '角色管理', 'sys:role:list',2,'/system/role','system/role',2),
 (9, 6, '审计日志', 'sys:log:list', 2, '/system/log','system/log',  3),
 (10,0, '通用设置', NULL,             1, '/common',        NULL,                   8),
 (11,10,'防护策略', NULL,             1, '/common/protect',NULL,                   1),
 (12,11,'API防护策略','waf:apipolicy:list',2,'/common/protect/api-policy','common/ApiPolicy',1),
 (13,10,'部署方式','system:deploy:view',2,'/common/deploy','common/Deploy',2),
 (14,10,'IP 组','waf:ipgroup:list',2,'/common/ipgroup','common/IpGroup',3),
 (15,10,'硬件加速','system:accel:list',2,'/common/accel','common/Accel',4),
 (16,15,'加速配置修改','system:accel:edit',3,NULL,NULL,1),
 (17,11,'API资产与防护','waf:apiasset:list',2,'/common/protect/api-assets','common/ApiAssets',2)
 ON DUPLICATE KEY UPDATE menu_name=VALUES(menu_name);

-- admin 全部菜单; auditor 只读(1,3,5,9); operator 规则/ioc
-- 部署方式(13)/IP 组(14)/硬件加速(15,16) 仅授予 admin：HA 编辑、地域拦截与加速开关均属高危运维操作
INSERT INTO sys_role_menu (role_id, menu_id) VALUES
 (1,1),(1,2),(1,3),(1,4),(1,5),(1,6),(1,7),(1,8),(1,9),(1,10),(1,11),(1,12),(1,13),(1,14),(1,15),(1,16),(1,17),
 (2,1),(2,3),(2,5),(2,9),
 (3,1),(3,4),(3,5)
 ON DUPLICATE KEY UPDATE menu_id=VALUES(menu_id);

-- HA 配置初始单行：单机模式、空节点
INSERT INTO waf_deploy_config (id, ha_mode, vip, nodes, remark) VALUES
 (1, 'single', NULL, '[]', '初始化')
 ON DUPLICATE KEY UPDATE id=id;
