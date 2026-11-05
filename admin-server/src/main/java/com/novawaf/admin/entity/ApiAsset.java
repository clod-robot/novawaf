package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * API 资产登记（资产清单真值）。
 * 引擎仅把「清单内」的 API 视为已登记；未登记的线上 API 判为影子 API，登记后长期无流量判为僵尸 API。
 * 持久化于表 waf_api_asset；每次变更整表发布到 Redis novawaf:api:inventory 并递增版本号，引擎热生效。
 */
@Data
public class ApiAsset {
    private Long id;
    /** 所属应用 ID；空=全部应用（引擎按 appId 为空视为通配） */
    private String appId;
    /** 请求方法：GET/POST/... ；ANY 发布时展开为全部方法 */
    private String method;
    /** 路径模板：支持引擎归一后的 {id} 占位，如 /api/user/{id} */
    private String path;
    /** 资产名称（管理用） */
    private String name;
    /** 责任人 */
    private String owner;
    private Boolean enabled;
    private String remark;
    private Date createTime;
    private Date updateTime;

    /* ---- 展示用，不落库 ---- */
    private String appName;
}
