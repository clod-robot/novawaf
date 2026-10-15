package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.GeoPolicy;
import org.apache.ibatis.annotations.*;

/** GeoIP 地域访问策略单行读写（表 waf_geo_policy，固定 id=1）。 */
@Mapper
public interface GeoPolicyMapper {

    @Select("SELECT id, enabled, mode, countries, update_time FROM waf_geo_policy WHERE id = 1")
    GeoPolicy selectSingleton();

    @Insert("INSERT INTO waf_geo_policy(id, enabled, mode, countries) VALUES(1, #{enabled}, #{mode}, #{countries})")
    int insertSingleton(GeoPolicy p);

    @Update("UPDATE waf_geo_policy SET enabled=#{enabled}, mode=#{mode}, countries=#{countries} WHERE id = 1")
    int updateSingleton(GeoPolicy p);
}
