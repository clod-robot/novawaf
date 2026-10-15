package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * IP 组（通用设置-IP组）。
 * type：custom 自定义组 / threat 威胁情报组；
 * action：custom 组的生效动作 block=并入黑名单 / allow=并入白名单；threat 组固定 block（走引擎威胁情报通道 novawaf:ioc）。
 * sourceUrl：可选自定义源（http/https 文本，每行 IP/CIDR），后台「更新」按钮手动拉取。
 * 条目本体存 Redis SET novawaf:ipgroup:{id}，不进 MySQL（可到 20 万条）。
 */
@Data
public class IpGroup {
    private Long id;
    private String name;
    private String type;
    private String action;
    private String sourceUrl;
    private String remark;
    private Boolean enabled;
    private Date createTime;
    private Date updateTime;
}
