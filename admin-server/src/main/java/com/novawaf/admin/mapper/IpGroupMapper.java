package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.IpGroup;
import org.apache.ibatis.annotations.*;

import java.util.List;

/** IP 组元数据读写（条目本体在 Redis SET novawaf:ipgroup:{id}）。 */
@Mapper
public interface IpGroupMapper {

    @Select("SELECT id, name, type, action, source_url, remark, enabled, create_time, update_time " +
            "FROM waf_ip_group ORDER BY id")
    List<IpGroup> selectAll();

    @Select("SELECT id, name, type, action, source_url, remark, enabled, create_time, update_time " +
            "FROM waf_ip_group WHERE id = #{id}")
    IpGroup selectById(Long id);

    @Select("SELECT id, name, type, action, source_url, remark, enabled, create_time, update_time " +
            "FROM waf_ip_group WHERE type = #{type} ORDER BY id")
    List<IpGroup> selectByType(String type);

    @Select("SELECT id, name, type, action, source_url, remark, enabled, create_time, update_time " +
            "FROM waf_ip_group WHERE name = #{name} LIMIT 1")
    IpGroup selectByName(String name);

    @Insert("INSERT INTO waf_ip_group(name, type, action, source_url, remark, enabled) " +
            "VALUES(#{name}, #{type}, #{action}, #{sourceUrl}, #{remark}, #{enabled})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(IpGroup g);

    @Update("UPDATE waf_ip_group SET name=#{name}, type=#{type}, action=#{action}, " +
            "source_url=#{sourceUrl}, remark=#{remark}, enabled=#{enabled} WHERE id=#{id}")
    int update(IpGroup g);

    @Delete("DELETE FROM waf_ip_group WHERE id = #{id}")
    int deleteById(Long id);
}
