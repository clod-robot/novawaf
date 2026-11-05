package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.SystemOpsService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * 系统维护：引擎在线一键升级 / 零停机滚动重启 / 版本回退。
 * 全部高危操作仅限 system:ops:edit（默认仅 admin），操作全程审计（等保要求）。
 */
@RestController
@RequestMapping("/api/system/ops")
@RequiredArgsConstructor
public class SystemOpsController {

    private final SystemOpsService service;
    private final AuditService audit;

    /** 版本清单 + master/worker 运行状态 */
    @RequirePerms("system:ops:view")
    @GetMapping
    public Result<Map<String, Object>> overview() {
        return Result.ok(service.overview());
    }

    /** 上传引擎二进制并安装为新版本（不切换运行版本） */
    @RequirePerms("system:ops:edit")
    @PostMapping("/upload")
    public Result<Map<String, Object>> upload(@RequestParam("file") MultipartFile file) {
        long t0 = System.currentTimeMillis();
        Map<String, Object> r = service.install(file);
        audit.record(user(), "system", "上传引擎版本 " + r.get("version"), "POST", null, 1,
                "size=" + r.get("size"), (int) (System.currentTimeMillis() - t0));
        return Result.ok(r);
    }

    /** 一键升级：切换到指定已安装版本（零停机滚动，失败自动回切） */
    @RequirePerms("system:ops:edit")
    @PostMapping("/upgrade")
    public Result<Map<String, Object>> upgrade(@RequestBody Map<String, String> body) {
        long t0 = System.currentTimeMillis();
        String version = body == null ? null : body.get("version");
        Map<String, Object> r = service.upgrade(version);
        audit.record(user(), "system", "一键升级引擎到 " + version, "POST", null, 1,
                null, (int) (System.currentTimeMillis() - t0));
        return Result.ok(r);
    }

    /** 版本回退：切回上一版本（零停机滚动） */
    @RequirePerms("system:ops:edit")
    @PostMapping("/rollback")
    public Result<Map<String, Object>> rollback() {
        long t0 = System.currentTimeMillis();
        Map<String, Object> r = service.rollback();
        audit.record(user(), "system", "回退引擎到 " + r.get("version"), "POST", null, 1,
                null, (int) (System.currentTimeMillis() - t0));
        return Result.ok(r);
    }

    /** 零停机滚动重启（同版本更换 worker） */
    @RequirePerms("system:ops:edit")
    @PostMapping("/restart")
    public Result<Map<String, Object>> restart() {
        long t0 = System.currentTimeMillis();
        Map<String, Object> r = service.restart();
        audit.record(user(), "system", "滚动重启引擎", "POST", null, 1,
                null, (int) (System.currentTimeMillis() - t0));
        return Result.ok(r);
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
