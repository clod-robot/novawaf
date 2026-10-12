package com.novawaf.admin.service;

import com.novawaf.admin.entity.SysUser;
import com.novawaf.admin.mapper.SysUserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/** 启动时确保 admin 账号存在且密码为配置值(哈希不符则重置) */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {
    private final SysUserMapper userMapper;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    @Value("${nova.admin.init-password}") private String initPassword;

    @Override
    public void run(String... args) {
        ensureUser("admin", "超级管理员", initPassword);
        ensureUser("auditor", "审计员", initPassword);
        log.info("DataInitializer done.");
    }

    private void ensureUser(String username, String nickname, String rawPwd) {
        SysUser u = userMapper.selectByUsername(username);
        String hash = encoder.encode(rawPwd);
        if (u == null) {
            SysUser n = new SysUser();
            n.setUsername(username); n.setPassword(hash); n.setNickname(nickname);
            n.setStatus(1); n.setEmail(""); n.setPhone("");
            userMapper.insert(n);
            log.warn("created user {} with init password (please change)", username);
        } else {
            // 仅当哈希与当前配置不匹配时重置(允许通过环境变量轮换密码)
            if (!encoder.matches(rawPwd, u.getPassword())) {
                userMapper.updatePassword(u.getId(), hash);
                log.warn("reset password for {}", username);
            }
        }
    }
}
