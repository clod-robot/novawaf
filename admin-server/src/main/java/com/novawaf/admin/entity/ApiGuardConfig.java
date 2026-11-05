package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * API 防护全局配置（单行 id=1）：总开关、生效阶段、Token 校验、响应脱敏。
 * 保存后发布 Redis novawaf:api:guard（限流+令牌配置）与 novawaf:dlp:config（脱敏），并递增各自版本号。
 */
@Data
public class ApiGuardConfig {
    private Long id;
    /** 限流总开关 */
    private Boolean enabled;
    /** monitor=观察期(只记录不拦截) / enforce=正式生效 */
    private String stage;

    /* ---- Token 合法性校验 ---- */
    private Boolean tokenEnabled;
    /** false=灰度（校验结果只记录不拒绝） */
    private Boolean tokenEnforce;
    /** jwt / opaque / any */
    private String tokenMode;
    /** 允许的签名算法，逗号分隔，如 HS256 */
    private String tokenAlg;
    /** JWT HMAC 校验密钥（留空则不校验签名，仅校验结构/时效） */
    private String tokenSecret;
    /** 令牌最大有效期（秒） */
    private Integer tokenMaxAge;
    /** 是否强制要求 iat */
    private Boolean tokenRequireIat;
    /** 令牌复用检测窗口（秒） */
    private Integer tokenReuseWindow;
    /** 窗口内允许的最大来源 IP 数，超过判定复用盗用 */
    private Integer tokenReuseMaxIps;
    /** 复用异常是否直接 401 */
    private Boolean tokenEnforceReuse;

    /* ---- 敏感数据脱敏 ---- */
    private Boolean dlpEnabled;
    /** mask / log / block / off */
    private String dlpAction;
    /** 脱敏处理的最大响应体字节数（超出跳过） */
    private Long dlpMaxBytes;

    private Date updateTime;
}
