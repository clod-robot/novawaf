package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.DeployConfig;
import org.apache.ibatis.annotations.*;

/**
 * 部署方式-HA 配置单行读写（表 waf_deploy_config，固定 id=1）。
 * 采用显式 upsert 而非 ON DUPLICATE KEY，兼容不同 MySQL 版本且 SQL 意图清晰。
 */
@Mapper
public interface DeployConfigMapper {

    @Select("SELECT id, ha_mode, vip, nodes, remark, create_time, update_time " +
            "FROM waf_deploy_config WHERE id = 1")
    DeployConfig selectSingleton();

    @Insert("INSERT INTO waf_deploy_config(id, ha_mode, vip, nodes, remark, create_time, update_time) " +
            "VALUES(1, #{haMode}, #{vip}, #{nodes}, #{remark}, NOW(), NOW())")
    int insertSingleton(DeployConfig c);

    @Update("UPDATE waf_deploy_config SET ha_mode=#{haMode}, vip=#{vip}, nodes=#{nodes}, " +
            "remark=#{remark}, update_time=NOW() WHERE id=1")
    int updateSingleton(DeployConfig c);
}
