package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiGuardRule;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** API 级别限流策略 CRUD（注解式，表 waf_api_guard_rule）。 */
@Mapper
public interface ApiGuardRuleMapper {

    String COLS = "id, name, app_id AS appId, method, path, qps, burst, scope, action, ban_sec AS banSec, " +
            "token_required AS tokenRequired, enabled, remark, create_time, update_time ";

    @Select("SELECT " + COLS + "FROM waf_api_guard_rule ORDER BY app_id ASC, path ASC, id ASC")
    List<ApiGuardRule> selectAll();

    @Select("SELECT " + COLS + "FROM waf_api_guard_rule WHERE enabled = 1 ORDER BY id ASC")
    List<ApiGuardRule> selectEnabled();

    @Select("SELECT " + COLS + "FROM waf_api_guard_rule WHERE id = #{id}")
    ApiGuardRule selectById(@Param("id") Long id);

    /** 应用 + 方法 + 路径唯一 */
    @Select("SELECT COUNT(1) FROM waf_api_guard_rule WHERE app_id <=> #{appId} AND method = #{method} " +
            "AND path = #{path} AND (#{id} IS NULL OR id <> #{id})")
    long countByKey(@Param("appId") String appId, @Param("method") String method,
                    @Param("path") String path, @Param("id") Long excludeId);

    @Insert("INSERT INTO waf_api_guard_rule(name, app_id, method, path, qps, burst, scope, action, ban_sec, " +
            "token_required, enabled, remark, create_time, update_time) VALUES(#{name}, #{appId}, #{method}, #{path}, " +
            "#{qps}, #{burst}, #{scope}, #{action}, #{banSec}, #{tokenRequired}, #{enabled}, #{remark}, NOW(), NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(ApiGuardRule r);

    @Update("UPDATE waf_api_guard_rule SET name=#{name}, app_id=#{appId}, method=#{method}, path=#{path}, qps=#{qps}, " +
            "burst=#{burst}, scope=#{scope}, action=#{action}, ban_sec=#{banSec}, token_required=#{tokenRequired}, " +
            "enabled=#{enabled}, remark=#{remark}, update_time=NOW() WHERE id=#{id}")
    int update(ApiGuardRule r);

    @Update("UPDATE waf_api_guard_rule SET enabled=#{enabled}, update_time=NOW() WHERE id=#{id}")
    int updateEnabled(@Param("id") Long id, @Param("enabled") Boolean enabled);

    @Delete("DELETE FROM waf_api_guard_rule WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
