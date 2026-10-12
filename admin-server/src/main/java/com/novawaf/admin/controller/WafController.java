package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.WafRedisService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** WAF 业务数据: 日志/规则/统计/IOC (数据源为引擎 Redis) */
@RestController
@RequestMapping("/api/waf")
@RequiredArgsConstructor
public class WafController {
    private final WafRedisService waf;
    private final AuditService audit;

    // ---------- 日志 ----------
    @RequirePerms("waf:log:list")
    @GetMapping("/logs")
    public Result<Map<String, Object>> logs(@RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "20") int size,
                                            @RequestParam(required = false) String keyword) {
        if (size > 200) size = 200;            // 防一次拉太多
        return Result.ok(waf.logs(page, size, keyword));
    }

    @RequirePerms("waf:log:list")
    @GetMapping("/events")
    public Result<List<Object>> events(@RequestParam(defaultValue = "50") int limit) {
        if (limit > 500) limit = 500;
        return Result.ok(waf.events(limit));
    }

    // ---------- 统计(仪表盘) ----------
    @RequirePerms("dashboard")
    @GetMapping("/stats")
    public Result<Object> stats() {
        return Result.ok(waf.stats());
    }

    @RequirePerms("dashboard")
    @GetMapping("/dashboard")
    public Result<Map<String, Object>> dashboard() {
        return Result.ok(waf.dashboard());
    }

    // ---------- 防护应用 ----------
    @RequirePerms("waf:app:list")
    @GetMapping("/apps")
    public Result<List<Map<String, Object>>> apps() {
        return Result.ok(waf.apps());
    }

    @RequirePerms("waf:app:edit")
    @PostMapping("/apps")
    public Result<Void> addApp(@RequestBody Map<String, Object> req) {
        waf.addApp(req);
        audit.record(UserContext.get().getUsername(), "waf", "新增防护应用", "POST", null, 1, String.valueOf(req.get("host")), 0);
        return Result.ok();
    }

    @RequirePerms("waf:app:edit")
    @DeleteMapping("/apps/{id}")
    public Result<Void> deleteApp(@PathVariable String id) {
        waf.deleteApp(id);
        audit.record(UserContext.get().getUsername(), "waf", "删除防护应用", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:app:edit")
    @PutMapping("/apps/{id}")
    public Result<Void> updateApp(@PathVariable String id, @RequestBody Map<String, Object> req) {
        waf.updateApp(id, req);
        audit.record(UserContext.get().getUsername(), "waf", "修改防护应用", "PUT", null, 1, "id=" + id + ",host=" + req.get("host"), 0);
        return Result.ok();
    }

    @RequirePerms("waf:app:edit")
    @PostMapping("/apps/{id}/mode")
    public Result<Void> setAppMode(@PathVariable String id, @RequestBody Map<String, Object> req) {
        waf.setAppMode(id, String.valueOf(req.get("mode")));
        audit.record(UserContext.get().getUsername(), "waf", "切换运行模式", "POST", null, 1, "id=" + id + ",mode=" + req.get("mode"), 0);
        return Result.ok();
    }

    // ---------- 规则 ----------
    @RequirePerms("waf:rule:list")
    @GetMapping("/rules")
    public Result<Object> rules() { return Result.ok(waf.rules()); }

    @Data
    public static class RulesReq { private String json; }

    @RequirePerms("waf:rule:list")
    @PostMapping("/rules")
    public Result<Void> saveRules(@RequestBody RulesReq req) {
        waf.setRules(req.getJson());
        audit.record(UserContext.get().getUsername(), "waf", "更新规则集", "POST", null, 1, null, 0);
        return Result.ok();
    }

    @RequirePerms("waf:rule:list")
    @PostMapping("/rules/reload")
    public Result<Void> reload() {
        waf.bumpRulesVersion();
        return Result.ok();
    }

    // ---------- IOC ----------
    @RequirePerms("waf:ioc:list")
    @GetMapping("/ioc")
    public Result<Object> ioc() {
        return Result.ok(Map.of("ioc", waf.ioc() == null ? List.of() : waf.ioc(),
                "meta", waf.iocMeta() == null ? Map.of() : waf.iocMeta()));
    }
}
