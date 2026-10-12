package com.novawaf.admin.service;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.SysUser;
import com.novawaf.admin.mapper.SysMenuMapper;
import com.novawaf.admin.mapper.SysUserMapper;
import com.novawaf.admin.security.JwtUtil;
import com.novawaf.admin.security.LoginUser;
import com.novawaf.admin.security.SessionService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final SysUserMapper userMapper;
    private final SysMenuMapper menuMapper;
    private final JwtUtil jwtUtil;
    private final SessionService sessionService;
    private final StringRedisTemplate redis;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Value("${nova.security.ip-fail-max}") private int ipFailMax;
    @Value("${nova.security.ip-lock-minutes}") private long ipLockMin;
    @Value("${nova.security.acct-fail-max}") private int acctFailMax;
    @Value("${nova.security.acct-lock-minutes}") private long acctLockMin;

    public Map<String, Object> login(String username, String password, String ip) {
        if (username == null || username.isBlank() || password == null) {
            throw new BusinessException(400, "账号或密码不能为空");
        }
        // 防爆破: IP 锁
        if (isLocked("nova:fail:ip:" + ip)) throw new BusinessException(423, "登录失败过多,请稍后再试");
        if (isLocked("nova:fail:acct:" + username)) throw new BusinessException(423, "账号已临时锁定");

        SysUser u = userMapper.selectByUsername(username);
        boolean ok = u != null && u.getStatus() != null && u.getStatus() == 1
                && encoder.matches(password, u.getPassword());
        if (!ok) {
            bumpFail("nova:fail:ip:" + ip, ipFailMax, ipLockMin);
            bumpFail("nova:fail:acct:" + username, acctFailMax, acctLockMin);
            throw new BusinessException(401, "账号或密码错误");
        }
        // 成功: 清失败计数
        redis.delete("nova:fail:ip:" + ip);
        redis.delete("nova:fail:acct:" + username);

        String token = jwtUtil.create(u.getId(), u.getUsername());
        sessionService.save(token, u.getId());

        List<String> roles = menuMapper.selectRoleCodesByUserId(u.getId());
        boolean admin = roles.contains("admin");
        Map<String, Object> m = new HashMap<>();
        m.put("token", token);
        m.put("userId", u.getId());
        m.put("username", u.getUsername());
        m.put("nickname", u.getNickname());
        m.put("admin", admin);
        m.put("roles", roles);
        m.put("perms", new HashSet<>(menuMapper.selectPermsByUserId(u.getId())));
        return m;
    }

    public void logout(String token) {
        if (token != null) sessionService.delete(token);
    }

    private boolean isLocked(String key) {
        String v = redis.opsForValue().get(key);
        return v != null && "LOCK".equals(v);
    }

    private void bumpFail(String key, int max, long lockMin) {
        Long n = redis.opsForValue().increment(key);
        if (n != null && n == 1) redis.expire(key, lockMin * 2, TimeUnit.MINUTES); // 计数窗口
        if (n != null && n >= max) {
            redis.opsForValue().set(key, "LOCK", lockMin, TimeUnit.MINUTES);
        }
    }
}
