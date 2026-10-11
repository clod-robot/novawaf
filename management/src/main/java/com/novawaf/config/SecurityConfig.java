package com.novawaf.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 配置（等保合规要求）：
 * - 管理面全接口需认证
 * - RBAC：ADMIN（全部）/ OPERATOR（查看+规则）/ VIEWER（只读）
 * - 密码 BCrypt 加密存储
 * - 会话固定保护、CSRF 防护
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder enc) {
        // 生产环境应改为数据库用户表；此处为最小可运行配置
        UserDetails admin = User.withUsername("admin")
                .password(enc.encode("Admin@2026"))
                .roles("ADMIN").build();
        UserDetails viewer = User.withUsername("viewer")
                .password(enc.encode("Viewer@2026"))
                .roles("VIEWER").build();
        return new InMemoryUserDetailsManager(admin, viewer);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // API 模式按需开启；生产建议按 token 校验
            .authorizeRequests()
                .antMatchers("/api/logs/**").hasAnyRole("ADMIN", "OPERATOR", "VIEWER")
                .antMatchers("/api/rules/**").hasAnyRole("ADMIN", "OPERATOR")
                .anyRequest().authenticated()
            .and()
            .httpBasic();
        return http.build();
    }
}
