package com.novawaf.admin.entity;

import lombok.Data;

import java.util.Date;

/**
 * Agentic AI 引擎配置（单行 id=1）：大模型判定未知 API 威胁。
 * 保存后发布 Redis novawaf:ai:agentic 并递增版本号，引擎 5s 内热加载。
 */
@Data
public class AgenticConfig {
    private Long id;
    private Boolean enabled;
    /** true=判定为攻击直接拦截；false=仅告警 */
    private Boolean block;
    /** 判定阈值 0~1，证据分达到才调用大模型、判定分达到才拦截 */
    private Double threshold;
    /** 代理循环最大步数 */
    private Integer maxSteps;
    /** 每分钟大模型调用预算（成本护栏） */
    private Integer budgetPerMin;
    /** 指纹判定缓存 TTL（秒） */
    private Integer cacheTtlSec;
    /** 审计轨迹保留条数 */
    private Integer traceMax;

    /* ---- 大模型接入 ---- */
    private Boolean llmEnabled;
    private String llmEndpoint;
    /** 密钥：接口返回时脱敏，留空表示不修改 */
    private String llmApiKey;
    private String llmModel;
    private Integer llmTimeoutMs;
    private Integer llmMaxRetries;
    private Integer llmMaxTokens;

    private Date updateTime;

    /* ---- 展示用，不落库 ---- */
    private String llmApiKeyMask;
}
