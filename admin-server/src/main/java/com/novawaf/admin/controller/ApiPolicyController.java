package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.ApiPolicy;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.ApiPolicyService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * API 路径级防护策略：按 URL 前缀将 WAF 处置设为
 * block(拦截) / log(仅记录·观察期) / pass(跳过WAF检测)。保存即自动发布、引擎 3s 内热生效。
 */
@RestController
@RequestMapping("/api/waf/api-policy")
@RequiredArgsConstructor
public class ApiPolicyController {

    private final ApiPolicyService service;
    private final AuditService audit;

    @RequirePerms("waf:apipolicy:list")
    @GetMapping("/list")
    public Result<List<ApiPolicy>> list() {
        return Result.ok(service.list());
    }

    @RequirePerms("waf:apipolicy:edit")
    @PostMapping
    public Result<Void> add(@RequestBody ApiPolicy p) {
        service.add(p);
        audit.record(user(), "waf", "新增API防护策略", "POST", null, 1, "prefix=" + p.getPrefix(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apipolicy:edit")
    @PutMapping
    public Result<Void> update(@RequestBody ApiPolicy p) {
        service.update(p);
        audit.record(user(), "waf", "修改API防护策略", "PUT", null, 1, "id=" + p.getId() + ",prefix=" + p.getPrefix(), 0);
        return Result.ok();
    }

    /** 快速启停 */
    @RequirePerms("waf:apipolicy:edit")
    @PutMapping("/{id}/enabled")
    public Result<Void> toggle(@PathVariable Long id, @RequestBody(required = false) Map<String, Boolean> body) {
        service.toggle(id, body == null ? null : body.get("enabled"));
        audit.record(user(), "waf", "启停API防护策略", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:apipolicy:edit")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        service.delete(id);
        audit.record(user(), "waf", "删除API防护策略", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
