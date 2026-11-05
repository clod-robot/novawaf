package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.ApiGuardConfig;
import com.novawaf.admin.entity.ApiGuardRule;
import com.novawaf.admin.entity.ApiToken;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.ApiGuardService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * API 级别防护：请求频率限制、Token 合法性校验、敏感数据脱敏。
 * 保存即自动发布（Redis + 版本号），引擎 5s 内热生效。
 */
@RestController
@RequestMapping("/api/waf/api-guard")
@RequiredArgsConstructor
public class ApiGuardController {

    private final ApiGuardService service;
    private final AuditService audit;

    /* ---------------------------- 限流策略 ---------------------------- */

    @RequirePerms("waf:apiguard:list")
    @GetMapping("/list")
    public Result<List<ApiGuardRule>> list() {
        return Result.ok(service.rules());
    }

    @RequirePerms("waf:apiguard:edit")
    @PostMapping
    public Result<Void> add(@RequestBody ApiGuardRule r) {
        service.addRule(r);
        audit.record(user(), "waf", "新增API限流策略", "POST", null, 1,
                r.getMethod() + " " + r.getPath() + " qps=" + r.getQps(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @PutMapping
    public Result<Void> update(@RequestBody ApiGuardRule r) {
        service.updateRule(r);
        audit.record(user(), "waf", "修改API限流策略", "PUT", null, 1,
                "id=" + r.getId() + "," + r.getMethod() + " " + r.getPath(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @PutMapping("/{id}/enabled")
    public Result<Void> toggle(@PathVariable Long id,
                               @RequestBody(required = false) Map<String, Boolean> body) {
        service.toggleRule(id, body == null ? null : body.get("enabled"));
        audit.record(user(), "waf", "启停API限流策略", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        service.deleteRule(id);
        audit.record(user(), "waf", "删除API限流策略", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    /* ---------------------------- 全局配置 ---------------------------- */

    @RequirePerms("waf:apiguard:list")
    @GetMapping("/config")
    public Result<ApiGuardConfig> config() {
        return Result.ok(service.config());
    }

    @RequirePerms("waf:apiguard:edit")
    @PutMapping("/config")
    public Result<ApiGuardConfig> saveConfig(@RequestBody ApiGuardConfig c) {
        ApiGuardConfig ret = service.saveConfig(c);
        audit.record(user(), "waf", "保存API防护配置", "PUT", null, 1,
                "stage=" + ret.getStage() + ",tokenMode=" + ret.getTokenMode()
                        + ",dlp=" + ret.getDlpAction(), 0);
        return Result.ok(ret);
    }

    @RequirePerms("waf:apiguard:list")
    @GetMapping("/stats")
    public Result<Map<String, Object>> stats() {
        return Result.ok(service.stats());
    }

    /* ---------------------------- 令牌白名单 ---------------------------- */

    @RequirePerms("waf:apiguard:list")
    @GetMapping("/tokens")
    public Result<List<ApiToken>> tokens() {
        return Result.ok(service.tokens());
    }

    @RequirePerms("waf:apiguard:edit")
    @PostMapping("/tokens")
    public Result<Void> addToken(@RequestBody ApiToken t) {
        service.addToken(t);
        audit.record(user(), "waf", "新增API令牌", "POST", null, 1, "name=" + t.getName(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @PutMapping("/tokens")
    public Result<Void> updateToken(@RequestBody ApiToken t) {
        service.updateToken(t);
        audit.record(user(), "waf", "修改API令牌", "PUT", null, 1, "id=" + t.getId(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @PutMapping("/tokens/{id}/enabled")
    public Result<Void> toggleToken(@PathVariable Long id,
                                    @RequestBody(required = false) Map<String, Boolean> body) {
        service.toggleToken(id, body == null ? null : body.get("enabled"));
        audit.record(user(), "waf", "启停API令牌", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiguard:edit")
    @DeleteMapping("/tokens/{id}")
    public Result<Void> deleteToken(@PathVariable Long id) {
        service.deleteToken(id);
        audit.record(user(), "waf", "删除API令牌", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
