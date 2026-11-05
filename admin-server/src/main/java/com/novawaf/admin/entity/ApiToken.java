package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * 不透明令牌白名单（mode=opaque/any 时生效）。
 * 持久化于表 waf_api_token；启用且未过期的令牌整表发布 Redis novawaf:api:tokens。
 */
@Data
public class ApiToken {
    private Long id;
    private String name;
    /** 完整令牌值（接口返回时脱敏展示） */
    private String token;
    /** 限定应用；空=全部应用 */
    private String appId;
    private Boolean enabled;
    private Date expireTime;
    private String remark;
    private Date createTime;
    private Date updateTime;

    /* ---- 展示用，不落库 ---- */
    private String appName;
    /** token 脱敏展示（前 6 后 4） */
    private String tokenMask;
}
