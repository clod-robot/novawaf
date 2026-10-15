package com.novawaf.admin.security;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.mapper.SysMenuMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class SessionService {
    public static final String TOKEN_PREFIX = "nova:token:";
    public static final String COOKIE_NAME = "nova_session";

    private final JwtUtil jwtUtil;
    private final SysMenuMapper menuMapper;
    private final StringRedisTemplate redis;
    @Value("${nova.jwt.expire-minutes}") private long expireMinutes;

    /** 登录成功: 写 Redis 白名单(可被登出即时失效) */
    public void save(String token, Long userId) {
        redis.opsForValue().set(TOKEN_PREFIX + token, String.valueOf(userId),
                expireMinutes, TimeUnit.MINUTES);
    }

    /** 登出: 删除即失效 */
    public void delete(String token) {
        redis.delete(TOKEN_PREFIX + token);
    }

    /** 解析并构建 LoginUser(同时校验 Redis 白名单 + 滑动续期) */
    public LoginUser resolve(HttpServletRequest request) {
        String token = null;
        // 1) 优先 HttpOnly Cookie（防 XSS 窃取，会话存 Redis 可即时失效）
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie c : request.getCookies()) {
                if (COOKIE_NAME.equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
                    token = c.getValue(); break;
                }
            }
        }
        // 2) 兼容 Bearer 头 / 3) EventSource 的 ?token=
        if (token == null) {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) token = auth.substring(7);
        }
        if (token == null) {
            String q = request.getParameter("token");
            if (q != null && !q.isBlank()) token = q;
        }
        if (token == null) {
            throw new BusinessException(401, "未登录");
        }
        Claims c;
        try {
            c = jwtUtil.parse(token);
        } catch (Exception e) {
            throw new BusinessException(401, "令牌无效或已过期");
        }
        String key = TOKEN_PREFIX + token;
        String uidStr = redis.opsForValue().get(key);
        if (uidStr == null) throw new BusinessException(401, "登录已失效,请重新登录");
        // 滑动续期
        redis.expire(key, expireMinutes, TimeUnit.MINUTES);

        Long userId = Long.valueOf(uidStr);
        String username = c.get("username", String.class);
        List<String> roles = menuMapper.selectRoleCodesByUserId(userId);
        boolean admin = roles.contains("admin");
        HashSet<String> perms = new HashSet<>(menuMapper.selectPermsByUserId(userId));
        LoginUser u = new LoginUser();
        u.setUserId(userId);
        u.setUsername(username);
        u.setAdmin(admin);
        u.setPerms(perms);
        u.setToken(token);
        return u;
    }
}
