package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiPolicy;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** API 路径防护策略 CRUD（注解式，表 waf_api_policy）。 */
@Mapper
public interface ApiPolicyMapper {

    @Select("SELECT id, name, prefix, action, enabled, remark, create_time, update_time " +
            "FROM waf_api_policy ORDER BY id ASC")
    List<ApiPolicy> selectAll();

    @Select("SELECT COUNT(1) FROM waf_api_policy WHERE prefix = #{prefix} AND (#{id} IS NULL OR id <> #{id})")
    long countByPrefix(@Param("prefix") String prefix, @Param("id") Long excludeId);

    @Select("SELECT id, name, prefix, action, enabled, remark, create_time, update_time " +
            "FROM waf_api_policy WHERE id = #{id}")
    ApiPolicy selectById(@Param("id") Long id);

    @Insert("INSERT INTO waf_api_policy(name, prefix, action, enabled, remark, create_time, update_time) " +
            "VALUES(#{name}, #{prefix}, #{action}, #{enabled}, #{remark}, NOW(), NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(ApiPolicy p);

    @Update("UPDATE waf_api_policy SET name=#{name}, prefix=#{prefix}, action=#{action}, " +
            "enabled=#{enabled}, remark=#{remark}, update_time=NOW() WHERE id=#{id}")
    int update(ApiPolicy p);

    @Update("UPDATE waf_api_policy SET enabled=#{enabled}, update_time=NOW() WHERE id=#{id}")
    int updateEnabled(@Param("id") Long id, @Param("enabled") Boolean enabled);

    @Delete("DELETE FROM waf_api_policy WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
