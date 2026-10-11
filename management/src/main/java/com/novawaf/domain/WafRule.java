package com.novawaf.domain;

import lombok.Data;
import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;

/**
 * 防护规则实体（下发给 C++ 检测引擎）
 */
@Data
@Entity
@Table(name = "waf_rule")
public class WafRule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(unique = true, nullable = false)
    private String ruleId;        // 如 SQLI-001

    @NotBlank
    private String category;      // SQLi/XSS/RCE/Traversal

    @NotBlank
    private String pattern;       // 匹配特征

    private String description;

    @Column(nullable = false)
    private Boolean enabled = true;

    private Integer severity = 5; // 1-10

    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime updatedAt = LocalDateTime.now();

    @PreUpdate
    public void preUpdate() { updatedAt = LocalDateTime.now(); }
}
