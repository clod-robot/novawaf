package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * 部署方式 - HA 配置（单行表 waf_deploy_config，固定 id=1）。
 * haMode：single 单机 / master-backup 主备 / cluster 集群。
 * nodes：JSON 数组文本，元素结构 {name,ip,role(master/backup/node),priority,enabled}。
 * 保存后发布到 Redis novawaf:deploy:config 并递增版本号；当前不驱动 keepalived/VIP（见实现计划边界说明）。
 */
@Data
public class DeployConfig {
    private Long id;
    /** single / master-backup / cluster */
    private String haMode;
    /** 虚拟 IP，可空 */
    private String vip;
    /** 节点列表 JSON 文本 */
    private String nodes;
    /** 备注 */
    private String remark;
    private Date createTime;
    private Date updateTime;
}
