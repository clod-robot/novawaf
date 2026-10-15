package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * GeoIP 地域访问策略（单行表 waf_geo_policy，固定 id=1）。
 * mode：whitelist=仅允许选中国家 / blacklist=封禁选中国家；enabled=false 表示策略关闭。
 * countries：ISO 两位国家码 JSON 数组（如 ["CN","SG"]）。
 * 保存后发布 Redis novawaf:geo:policy 并递增 novawaf:geo:policy:version，引擎 3s 内热加载。
 */
@Data
public class GeoPolicy {
    private Long id;
    private Boolean enabled;
    private String mode;
    private String countries;
    private Date updateTime;
}
