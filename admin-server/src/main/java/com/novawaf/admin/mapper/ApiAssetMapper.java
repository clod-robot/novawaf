package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.ApiAsset;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** API 资产登记 CRUD（注解式，表 waf_api_asset）。 */
@Mapper
public interface ApiAssetMapper {

    String COLS = "id, app_id AS appId, method, path, name, owner, enabled, remark, create_time, update_time ";

    @Select("SELECT " + COLS + "FROM waf_api_asset ORDER BY app_id ASC, path ASC, method ASC")
    List<ApiAsset> selectAll();

    @Select("SELECT " + COLS + "FROM waf_api_asset WHERE enabled = 1 ORDER BY app_id ASC, path ASC")
    List<ApiAsset> selectEnabled();

    @Select("SELECT " + COLS + "FROM waf_api_asset WHERE id = #{id}")
    ApiAsset selectById(@Param("id") Long id);

    /** 应用 + 方法 + 路径模板唯一 */
    @Select("SELECT COUNT(1) FROM waf_api_asset WHERE app_id <=> #{appId} AND method = #{method} " +
            "AND path = #{path} AND (#{id} IS NULL OR id <> #{id})")
    long countByKey(@Param("appId") String appId, @Param("method") String method,
                    @Param("path") String path, @Param("id") Long excludeId);

    @Insert("INSERT INTO waf_api_asset(app_id, method, path, name, owner, enabled, remark, create_time, update_time) " +
            "VALUES(#{appId}, #{method}, #{path}, #{name}, #{owner}, #{enabled}, #{remark}, NOW(), NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(ApiAsset a);

    @Update("UPDATE waf_api_asset SET app_id=#{appId}, method=#{method}, path=#{path}, name=#{name}, owner=#{owner}, " +
            "enabled=#{enabled}, remark=#{remark}, update_time=NOW() WHERE id=#{id}")
    int update(ApiAsset a);

    @Update("UPDATE waf_api_asset SET enabled=#{enabled}, update_time=NOW() WHERE id=#{id}")
    int updateEnabled(@Param("id") Long id, @Param("enabled") Boolean enabled);

    @Delete("DELETE FROM waf_api_asset WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
