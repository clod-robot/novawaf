package com.novawaf.admin.controller;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.IpUtil;
import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.LoginUser;
import com.novawaf.admin.security.SessionService;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final AuditService auditService;
    @Value("${nova.jwt.expire-minutes:120}") private long expireMinutes;

    @Data
    public static class LoginReq {
        private String username;
        private String password;
    }

    @PostMapping("/login")
    public Result<Map<String, Object>> login(@RequestBody LoginReq req, HttpServletRequest request,
                                             HttpServletResponse response) {
        String ip = IpUtil.get(request);
        long t = System.currentTimeMillis();
        try {
            Map<String, Object> m = authService.login(req.getUsername(), req.getPassword(), ip);
            // 会话令牌写入 HttpOnly Cookie（JS 不可读，防 XSS 窃取；服务端存 Redis 可即时失效）
            Object tok = m.get("token");
            if (tok != null) {
                ResponseCookie ck = ResponseCookie.from(SessionService.COOKIE_NAME, String.valueOf(tok))
                        .httpOnly(true).secure(request.isSecure()).sameSite("Lax")
                        .path("/").maxAge(expireMinutes * 60).build();
                response.addHeader(HttpHeaders.SET_COOKIE, ck.toString());
            }
            auditService.record(req.getUsername(), "auth", "登录成功", "POST", ip, 1, null,
                    (int) (System.currentTimeMillis() - t));
            return Result.ok(m);
        } catch (BusinessException e) {
            auditService.record(req.getUsername(), "auth", "登录失败:" + e.getMessage(), "POST", ip, 0,
                    e.getMessage(), (int) (System.currentTimeMillis() - t));
            throw e;
        }
    }

    @PostMapping("/logout")
    public Result<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String token = null;
        if (request.getCookies() != null)
            for (jakarta.servlet.http.Cookie c : request.getCookies())
                if (SessionService.COOKIE_NAME.equals(c.getName())) token = c.getValue();
        if (token == null) {
            String auth = request.getHeader("Authorization");
            token = (auth != null && auth.startsWith("Bearer ")) ? auth.substring(7) : null;
        }
        authService.logout(token);
        ResponseCookie ck = ResponseCookie.from(SessionService.COOKIE_NAME, "")
                .httpOnly(true).secure(request.isSecure()).sameSite("Lax").path("/").maxAge(0).build();
        response.addHeader(HttpHeaders.SET_COOKIE, ck.toString());
        return Result.ok();
    }

    /** 当前登录用户信息 + 权限(前端据此构建菜单/按钮) */
    @GetMapping("/info")
    public Result<Map<String, Object>> info() {
        LoginUser u = UserContext.get();
        if (u == null) throw new BusinessException(401, "未登录");
        Map<String, Object> m = new HashMap<>();
        m.put("userId", u.getUserId());
        m.put("username", u.getUsername());
        m.put("admin", u.isAdmin());
        m.put("perms", u.getPerms());
        return Result.ok(m);
    }
}
