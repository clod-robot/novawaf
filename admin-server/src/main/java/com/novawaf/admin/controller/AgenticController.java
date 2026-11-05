package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.AgenticConfig;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AgenticService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Agentic AI 引擎：基于大模型识别未知 API 威胁，提升变形绕过识别率。
 * 配置保存即发布；研判轨迹可审计、可清空。
 */
@RestController
@RequestMapping("/api/waf/agentic")
@RequiredArgsConstructor
public class AgenticController {

    private final AgenticService service;
    private final AuditService audit;

    @RequirePerms("waf:agentic:list")
    @GetMapping("/config")
    public Result<AgenticConfig> config() {
        return Result.ok(service.config());
    }

    @RequirePerms("waf:agentic:edit")
    @PutMapping("/config")
    public Result<AgenticConfig> save(@RequestBody AgenticConfig c) {
        AgenticConfig ret = service.saveConfig(c);
        audit.record(user(), "waf", "保存Agentic AI配置", "PUT", null, 1,
                "enabled=" + ret.getEnabled() + ",block=" + ret.getBlock()
                        + ",threshold=" + ret.getThreshold() + ",llm=" + ret.getLlmEnabled(), 0);
        return Result.ok(ret);
    }

    /** 研判轨迹（倒序） */
    @RequirePerms("waf:agentic:list")
    @GetMapping("/traces")
    public Result<Map<String, Object>> traces(@RequestParam(defaultValue = "200") int limit) {
        return Result.ok(service.traces(limit));
    }

    @RequirePerms("waf:agentic:edit")
    @DeleteMapping("/traces")
    public Result<Void> clearTraces() {
        service.clearTraces();
        audit.record(user(), "waf", "清空Agentic轨迹", "DELETE", null, 1, "", 0);
        return Result.ok();
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
