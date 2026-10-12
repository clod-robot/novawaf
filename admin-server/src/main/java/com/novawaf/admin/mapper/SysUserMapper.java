package com.novawaf.admin.mapper;

import com.novawaf.admin.entity.SysUser;
import org.apache.ibatis.annotations.*;
import java.util.List;

@Mapper
public interface SysUserMapper {

    @Select("SELECT * FROM sys_user WHERE username = #{username} LIMIT 1")
    SysUser selectByUsername(@Param("username") String username);

    @Select("SELECT * FROM sys_user WHERE id = #{id}")
    SysUser selectById(@Param("id") Long id);

    @Select("<script>" +
            "SELECT * FROM sys_user WHERE 1=1 " +
            "<if test='username!=null and username!=\"\"'> AND username LIKE CONCAT('%',#{username},'%') </if>" +
            " ORDER BY id DESC LIMIT #{offset}, #{size}" +
            "</script>")
    List<SysUser> selectPage(@Param("username") String username,
                             @Param("offset") int offset, @Param("size") int size);

    @Select("<script>SELECT COUNT(*) FROM sys_user WHERE 1=1 " +
            "<if test='username!=null and username!=\"\"'> AND username LIKE CONCAT('%',#{username},'%') </if>" +
            "</script>")
    long count(@Param("username") String username);

    @Insert("INSERT INTO sys_user(username,password,nickname,email,phone,status) " +
            "VALUES(#{username},#{password},#{nickname},#{email},#{phone},#{status})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(SysUser u);

    @Update("UPDATE sys_user SET nickname=#{nickname},email=#{email},phone=#{phone},status=#{status} WHERE id=#{id}")
    int update(SysUser u);

    @Update("UPDATE sys_user SET password=#{password} WHERE id=#{id}")
    int updatePassword(@Param("id") Long id, @Param("password") String password);

    @Delete("DELETE FROM sys_user WHERE id=#{id}")
    int deleteById(@Param("id") Long id);
}
