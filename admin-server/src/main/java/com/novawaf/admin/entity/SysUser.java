package com.novawaf.admin.entity;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class SysUser {
    private Long id;
    private String username;
    private String password;
    private String nickname;
    private String email;
    private String phone;
    private Integer status;
    private Long deptId;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;
}
