package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiPolicy;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** API 路径防护策略 CRUD（注解式，表 waf_api_policy）。 */
@Mapper
public interface ApiPolicyMapper {

    String COLS = "id, name, app_id AS appId, prefix, action, enabled, remark, create_time, update_time ";

    @Select("SELECT " + COLS + "FROM waf_api_policy ORDER BY app_id ASC, id ASC")
    List<ApiPolicy> selectAll();

    /** 同应用下前缀唯一（appId 为空=全部应用策略，同样做唯一约束） */
    @Select("SELECT COUNT(1) FROM waf_api_policy WHERE prefix = #{prefix} " +
            "AND (app_id <=> #{appId}) AND (#{id} IS NULL OR id <> #{id})")
    long countByPrefix(@Param("prefix") String prefix, @Param("appId") String appId, @Param("id") Long excludeId);

    @Select("SELECT " + COLS + "FROM waf_api_policy WHERE id = #{id}")
    ApiPolicy selectById(@Param("id") Long id);

    @Insert("INSERT INTO waf_api_policy(name, app_id, prefix, action, enabled, remark, create_time, update_time) " +
            "VALUES(#{name}, #{appId}, #{prefix}, #{action}, #{enabled}, #{remark}, NOW(), NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(ApiPolicy p);

    @Update("UPDATE waf_api_policy SET name=#{name}, app_id=#{appId}, prefix=#{prefix}, action=#{action}, " +
            "enabled=#{enabled}, remark=#{remark}, update_time=NOW() WHERE id=#{id}")
    int update(ApiPolicy p);

    @Update("UPDATE waf_api_policy SET enabled=#{enabled}, update_time=NOW() WHERE id=#{id}")
    int updateEnabled(@Param("id") Long id, @Param("enabled") Boolean enabled);

    @Delete("DELETE FROM waf_api_policy WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
