package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * API 级别限流策略（按 应用 + 方法 + 路径模板 精确/前缀匹配）。
 * scope=ip 按来源 IP；token 按令牌；global 全局。
 * action=monitor 仅记录 / 429 限流 / ban 超限后临时封禁。
 * 持久化于表 waf_api_guard_rule；变更后整表发布 Redis novawaf:api:guard。
 */
@Data
public class ApiGuardRule {
    private Long id;
    private String name;
    /** 所属应用；空=全部应用 */
    private String appId;
    /** 请求方法；空或 ANY=全部方法 */
    private String method;
    /** 路径模板，末尾 * 为前缀通配 */
    private String path;
    /** 每秒放行令牌数 */
    private Integer qps;
    /** 突发桶容量 */
    private Integer burst;
    /** ip / token / global */
    private String scope;
    /** monitor / 429 / ban */
    private String action;
    /** ban 动作的封禁秒数 */
    private Integer banSec;
    /** 是否要求携带合法令牌（未携带/非法即 401） */
    private Boolean tokenRequired;
    private Boolean enabled;
    private String remark;
    private Date createTime;
    private Date updateTime;

    /* ---- 展示用，不落库 ---- */
    private String appName;
}
