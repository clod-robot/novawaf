package com.novawaf.admin.security;

import java.lang.annotation.*;

/** 方法级权限校验, 防止越权访问 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequirePerms {
    String value();   // 权限标识, 如 "waf:log:list"
}
