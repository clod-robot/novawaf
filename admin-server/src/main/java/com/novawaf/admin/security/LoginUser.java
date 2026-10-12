package com.novawaf.admin.security;

import lombok.Data;
import java.util.Set;

@Data
public class LoginUser {
    private Long userId;
    private String username;
    private Set<String> perms;   // 权限标识集合
    private boolean admin;       // super admin 全权限
    private String token;
}
