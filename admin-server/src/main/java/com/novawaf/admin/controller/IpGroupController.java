package com.novawaf.admin.controller;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.IpGroup;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.GeoPolicyService;
import com.novawaf.admin.service.IpGroupService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 通用设置-IP 组：自定义/威胁情报组管理 + GeoIP 地域访问策略。
 * 视图 waf:ipgroup:list、编辑 waf:ipgroup:edit 分离，写操作全程审计（等保要求）。
 */
@RestController
@RequestMapping("/api/waf/ipgroup")
@RequiredArgsConstructor
public class IpGroupController {

    private final IpGroupService service;
    private final GeoPolicyService geoService;
    private final AuditService audit;

    // ---------------- 组管理 ----------------

    @RequirePerms("waf:ipgroup:list")
    @GetMapping("/list")
    public Result<List<Map<String, Object>>> list() {
        return Result.ok(service.listGroups());
    }

    @RequirePerms("waf:ipgroup:edit")
    @PostMapping
    public Result<IpGroup> create(@RequestBody IpGroup body) {
        IpGroup g = service.create(body);
        audit.record(user(), "ip-group", "添加 IP 组", "POST", null, 1,
                "name=" + safe(body.getName()) + ",type=" + safe(body.getType()), 0);
        return Result.ok(g);
    }

    @RequirePerms("waf:ipgroup:edit")
    @PutMapping("/{id}")
    public Result<IpGroup> update(@PathVariable long id, @RequestBody IpGroup body) {
        IpGroup g = service.update(id, body);
        audit.record(user(), "ip-group", "修改 IP 组", "PUT", null, 1,
                "id=" + id + ",name=" + safe(body.getName()), 0);
        return Result.ok(g);
    }

    @RequirePerms("waf:ipgroup:edit")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable long id) {
        service.delete(id);
        audit.record(user(), "ip-group", "删除 IP 组", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    // ---------------- 条目管理 ----------------

    @RequirePerms("waf:ipgroup:list")
    @GetMapping("/{id}/entries")
    public Result<Map<String, Object>> entries(@PathVariable long id,
                                               @RequestParam(defaultValue = "1") int page,
                                               @RequestParam(defaultValue = "20") int size) {
        return Result.ok(service.pageEntries(id, page, size));
    }

    @RequirePerms("waf:ipgroup:edit")
    @PostMapping("/{id}/entries")
    public Result<Map<String, Object>> addEntry(@PathVariable long id, @RequestBody Map<String, String> body) {
        String value = body == null ? null : body.get("value");
        if (value == null || IpGroupService.normalizeEntry(value) == null) {
            throw new BusinessException("IP/CIDR 格式不合法");
        }
        service.addEntries(id, IpGroupService.normalizeEntry(value));
        audit.record(user(), "ip-group", "IP 组添加条目", "POST", null, 1, "id=" + id, 0);
        return Result.ok(Map.of("ok", true));
    }

    @RequirePerms("waf:ipgroup:edit")
    @PostMapping("/{id}/import")
    public Result<Map<String, Object>> importText(@PathVariable long id, @RequestBody Map<String, String> body) {
        String text = body == null ? null : body.get("text");
        long added = service.addEntries(id, text);
        audit.record(user(), "ip-group", "IP 组导入条目", "POST", null, 1,
                "id=" + id + ",added=" + added, 0);
        return Result.ok(Map.of("added", added, "total", service.entryCount(id)));
    }

    @RequirePerms("waf:ipgroup:edit")
    @DeleteMapping("/{id}/entries")
    public Result<Void> removeEntry(@PathVariable long id, @RequestBody Map<String, String> body) {
        service.removeEntry(id, body == null ? null : body.get("value"));
        audit.record(user(), "ip-group", "IP 组删除条目", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:ipgroup:edit")
    @PutMapping("/{id}/entries/clear")
    public Result<Void> clearEntries(@PathVariable long id) {
        service.clearEntries(id);
        audit.record(user(), "ip-group", "IP 组清空条目", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    // ---------------- 更新任务（异步） ----------------

    @RequirePerms("waf:ipgroup:edit")
    @PostMapping("/{id}/update")
    public Result<Map<String, Object>> startUpdate(@PathVariable long id) {
        Map<String, Object> t = service.startUpdate(id);
        audit.record(user(), "ip-group", "触发 IP 组更新", "POST", null, 1, "id=" + id, 0);
        return Result.ok(t);
    }

    @RequirePerms("waf:ipgroup:list")
    @GetMapping("/{id}/task")
    public Result<Map<String, Object>> task(@PathVariable long id) {
        return Result.ok(service.task(id));
    }

    // ---------------- GeoIP 地域策略 ----------------

    @RequirePerms("waf:ipgroup:list")
    @GetMapping("/geo/stats")
    public Result<Map<String, Object>> geoStats() {
        return Result.ok(geoService.countryStats());
    }

    @RequirePerms("waf:ipgroup:list")
    @GetMapping("/geo/policy")
    public Result<Map<String, Object>> geoPolicy() {
        return Result.ok(geoService.getPolicy());
    }

    @RequirePerms("waf:ipgroup:edit")
    @PutMapping("/geo/policy")
    public Result<Map<String, Object>> saveGeoPolicy(@RequestBody Map<String, Object> body) {
        String mode = body == null ? null : String.valueOf(body.getOrDefault("mode", ""));
        @SuppressWarnings("unchecked")
        List<String> countries = body == null ? List.of() : (List<String>) body.getOrDefault("countries", List.of());
        Map<String, Object> saved = geoService.savePolicy(mode, countries);
        audit.record(user(), "ip-group", "保存 GeoIP 地域策略", "PUT", null, 1,
                "mode=" + mode + ",countries=" + countries.size(), 0);
        return Result.ok(saved);
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }

    private static String safe(String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n,]", " ");
    }
}
