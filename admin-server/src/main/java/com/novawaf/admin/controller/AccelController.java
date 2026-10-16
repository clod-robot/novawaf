package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AccelService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 硬件加速（CPU SIMD / GPU 微批 / 旁路批量分析）管理接口。
 * 数据面仅透传引擎 Redis 配置与状态，默认关闭。
 */
@RestController
@RequestMapping("/api/system/accel")
@RequiredArgsConstructor
public class AccelController {
    private final AccelService accel;
    private final AuditService audit;

    /** 查询加速配置 + 引擎实时设备/后端/统计 */
    @RequirePerms("system:accel:list")
    @GetMapping
    public Result<Map<String, Object>> view() {
        return Result.ok(accel.view());
    }

    /** 下发加速配置（总开关/首选后端/批量参数），INCR 版本号热生效 */
    @RequirePerms("system:accel:edit")
    @PutMapping
    public Result<String> update(@RequestBody Map<String, Object> req) {
        String msg = accel.update(req);
        String by = UserContext.get() == null ? "system" : UserContext.get().getUsername();
        String detail = "enabled=" + req.get("enabled")
                + ", backend=" + req.get("preferredBackend")
                + ", batchGateMinN=" + req.get("batchGateMinN")
                + ", batchMaxWaitUs=" + req.get("batchMaxWaitUs");
        audit.record(by, "system", "更新硬件加速配置", "PUT", null, 1, detail, 0);
        return Result.ok(msg);
    }

    /** 引擎 SIMD/后端健康自检（依据引擎上报状态，不执行系统命令） */
    @RequirePerms("system:accel:list")
    @PostMapping("/selftest")
    public Result<Map<String, Object>> selfTest() {
        return Result.ok(accel.selfTest());
    }
}
