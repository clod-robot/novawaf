package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * API 路径级防护策略。
 * 动作：block=拦截(默认) / log=仅记录(观察期，命中攻击只记事件不拦截) / pass=跳过WAF检测放行。
 * 持久化于表 waf_api_policy；每次增删改后整表发布到 Redis novawaf:pathpolicy 并递增版本号，引擎热生效。
 */
@Data
public class ApiPolicy {
    private Long id;
    /** 策略名称（管理用） */
    private String name;
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
}
