package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiToken;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** 不透明令牌白名单 CRUD（注解式，表 waf_api_token）。 */
@Mapper
public interface ApiTokenMapper {

    String COLS = "id, name, token, app_id AS appId, enabled, expire_time AS expireTime, remark, create_time, update_time ";

    @Select("SELECT " + COLS + "FROM waf_api_token ORDER BY id DESC")
    List<ApiToken> selectAll();

    /** 发布用：启用且未过期（expire_time 为空表示永久） */
    @Select("SELECT " + COLS + "FROM waf_api_token WHERE enabled = 1 " +
            "AND (expire_time IS NULL OR expire_time > NOW()) ORDER BY id ASC")
    List<ApiToken> selectActive();

    @Select("SELECT " + COLS + "FROM waf_api_token WHERE id = #{id}")
    ApiToken selectById(@Param("id") Long id);

    @Select("SELECT COUNT(1) FROM waf_api_token WHERE token = #{token} AND (#{id} IS NULL OR id <> #{id})")
    long countByToken(@Param("token") String token, @Param("id") Long excludeId);

    @Insert("INSERT INTO waf_api_token(name, token, app_id, enabled, expire_time, remark, create_time, update_time) " +
            "VALUES(#{name}, #{token}, #{appId}, #{enabled}, #{expireTime}, #{remark}, NOW(), NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(ApiToken t);

    @Update("UPDATE waf_api_token SET name=#{name}, token=#{token}, app_id=#{appId}, enabled=#{enabled}, " +
            "expire_time=#{expireTime}, remark=#{remark}, update_time=NOW() WHERE id=#{id}")
    int update(ApiToken t);

    @Update("UPDATE waf_api_token SET enabled=#{enabled}, update_time=NOW() WHERE id=#{id}")
    int updateEnabled(@Param("id") Long id, @Param("enabled") Boolean enabled);

    @Delete("DELETE FROM waf_api_token WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
