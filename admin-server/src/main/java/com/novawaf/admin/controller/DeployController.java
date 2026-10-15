package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.DeployConfig;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.DeployService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 通用设置-部署方式：网络类型(NAT 探测结果) + HA 配置。
 * 视图权限与编辑/探测权限分离，操作全程审计（等保要求）。
 */
@RestController
@RequestMapping("/api/system/deploy")
@RequiredArgsConstructor
public class DeployController {

    private final DeployService service;
    private final AuditService audit;

    /** HA 配置 + 最近 NAT 探测结果 */
    @RequirePerms("system:deploy:view")
    @GetMapping
    public Result<Map<String, Object>> get() {
        return Result.ok(service.get());
    }

    /** 保存 HA 配置（MySQL + Redis 发布；不驱动 keepalived/VIP） */
    @RequirePerms("system:deploy:edit")
    @PutMapping
    public Result<Void> save(@RequestBody DeployConfig body) {
        service.saveHa(body);
        String vip = body.getVip() == null ? "" : body.getVip();
        audit.record(user(), "system", "保存部署方式-HA配置", "PUT", null, 1,
                "haMode=" + body.getHaMode() + ",vip=" + vip, 0);
        return Result.ok();
    }

    /** 后台一键触发 NAT 探测，结果写 Redis 并返回 */
    @RequirePerms("system:deploy:detect")
    @PostMapping("/nat/detect")
    public Result<Object> detectNat() {
        long t0 = System.currentTimeMillis();
        Object nat = service.detectNat();
        audit.record(user(), "system", "触发部署网络类型探测", "POST", null, 1,
                null, (int) (System.currentTimeMillis() - t0));
        return Result.ok(nat);
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
