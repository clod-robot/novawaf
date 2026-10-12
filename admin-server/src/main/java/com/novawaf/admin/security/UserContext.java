package com.novawaf.admin.security;

/** 当前登录用户 ThreadLocal 持有者 */
public final class UserContext {
    private static final ThreadLocal<LoginUser> CTX = new ThreadLocal<>();
    private UserContext() {}
    public static void set(LoginUser u) { CTX.set(u); }
    public static LoginUser get() { return CTX.get(); }
    public static void clear() { CTX.remove(); }
}
