package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.TamperService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** 网页防篡改: 基线页面/配置下发/基线清除/引擎统计 */
@RestController
@RequestMapping("/api/tamper")
@RequiredArgsConstructor
public class TamperController {
    private final TamperService tamper;
    private final AuditService audit;

    @RequirePerms("waf:tamper:list")
    @GetMapping("/pages")
    public Result<List<Object>> pages() {
        return Result.ok(tamper.pages());
    }

    @RequirePerms("waf:tamper:list")
    @GetMapping("/config")
    public Result<Map<String, Object>> config() {
        return Result.ok(tamper.config());
    }

    @RequirePerms("waf:tamper:list")
    @GetMapping("/stats")
    public Result<Object> stats() {
        return Result.ok(tamper.stats());
    }

    @RequirePerms("waf:tamper:edit")
    @PostMapping("/config")
    public Result<Map<String, Object>> saveConfig(@RequestBody Map<String, Object> req) {
        Map<String, Object> out = tamper.saveConfig(req);
        audit.record(UserContext.get().getUsername(), "waf", "更新防篡改配置", "POST", null, 1,
                "enabled=" + out.get("enabled") + ",ttl=" + out.get("ttl") + ",prefixes=" + out.get("prefixes"), 0);
        return Result.ok(out);
    }

    @Data
    public static class PurgeReq { private String id; }

    @RequirePerms("waf:tamper:edit")
    @PostMapping("/purge")
    public Result<Map<String, Object>> purge(@RequestBody PurgeReq req) {
        Map<String, Object> out = tamper.purge(req.getId());
        audit.record(UserContext.get().getUsername(), "waf", "清除防篡改基线", "POST", null, 1,
                "id=" + req.getId(), 0);
        return Result.ok(out);
    }
}
