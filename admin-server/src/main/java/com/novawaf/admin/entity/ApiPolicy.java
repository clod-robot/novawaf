package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * API 路径级防护策略。
 * 动作：block=拦截(默认) / log=仅记录(观察期，命中攻击只记事件不拦截) / pass=跳过WAF检测放行。
 * 作用域：appId 指定所属应用，仅对该应用的请求生效；为空表示全部应用(全局策略)。
 * 持久化于表 waf_api_policy；每次增删改后整表发布到 Redis novawaf:pathpolicy 并递增版本号，引擎热生效。
 */
@Data
public class ApiPolicy {
    private Long id;
    /** 策略名称（管理用） */
    private String name;
    /** 所属应用 ID；空=全部应用 */
    private String appId;
    /** 路径匹配串，如 /api/portal/* 、/api/auth/login；须以 / 开头 */
    private String prefix;
    /** block / log / pass */
    private String action;
    /** 是否启用 */
    private Boolean enabled;
    /** 备注 */
    private String remark;
    private Date createTime;
    private Date updateTime;

    /* ---- 以下为展示用字段，不落库 ---- */
    /** 所属应用名称（appId 为空时为“全部应用”） */
    private String appName;
    /** 命中该策略的访问次数（引擎累计，Redis novawaf:pathpolicy:stat） */
    private Long hitCount;
    /** 拦截次数 */
    private Long blockCount;
    /** 放行次数 */
    private Long passCount;
}
