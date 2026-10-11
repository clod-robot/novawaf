package com.novawaf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * NovaWAF 管理控制台启动类
 * 职责：规则管理、日志查询、RBAC 权限、审计报表
 * 不处理任何用户流量，对数据面零性能影响。
 */
@SpringBootApplication
public class ManagementApplication {
    public static void main(String[] args) {
        SpringApplication.run(ManagementApplication.class, args);
    }
}
