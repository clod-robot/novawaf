package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.SysOperLog;
import org.apache.ibatis.annotations.*;
import java.util.List;

@Mapper
public interface SysOperLogMapper {

    @Insert("INSERT INTO sys_oper_log(username,module,operation,method,ip,status,error_msg,cost_ms) " +
            "VALUES(#{username},#{module},#{operation},#{method},#{ip},#{status},#{errorMsg},#{costMs})")
    int insert(SysOperLog log);

    @Select("<script>SELECT * FROM sys_oper_log WHERE 1=1 " +
            "<if test='username!=null and username!=\"\"'> AND username=#{username} </if>" +
            " ORDER BY id DESC LIMIT #{offset},#{size}</script>")
    List<SysOperLog> selectPage(@Param("username") String username,
                                @Param("offset") int offset, @Param("size") int size);

    @Select("<script>SELECT COUNT(*) FROM sys_oper_log WHERE 1=1 " +
            "<if test='username!=null and username!=\"\"'> AND username=#{username} </if></script>")
    long count(@Param("username") String username);
}
