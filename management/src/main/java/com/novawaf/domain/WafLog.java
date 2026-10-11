package com.novawaf.domain;

import lombok.Data;
import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * 攻击日志实体（由 C++ 引擎上报，管理面查询展示）
 */
@Data
@Entity
@Table(name = "waf_log", indexes = {
        @Index(name = "idx_log_time", columnList = "createdAt"),
        @Index(name = "idx_log_ip", columnList = "clientIp")
})
public class WafLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String clientIp;
    private String method;
    private String uri;
    private String category;     // SQLi/XSS/...
    private String ruleId;
    private String matched;      // 命中片段
    private Integer action;      // 0=pass 1=block
    private LocalDateTime createdAt = LocalDateTime.now();
}
