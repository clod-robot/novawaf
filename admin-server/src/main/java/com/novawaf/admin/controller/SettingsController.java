package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.WafRedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 系统设置：全局防护模式（WAF 指纹三态）与检测规则版本管理。
 * 数据面透传引擎 Redis 配置，引擎热路径读取，2s 内生效，无需重启。
 */
@RestController
@RequestMapping("/api/settings")
@RequiredArgsConstructor
public class SettingsController {
    private final WafRedisService waf;
    private final AuditService audit;

    /** 查询全局防护模式：hidden(默认)/public/off */
    @RequirePerms("system:settings:list")
    @GetMapping("/waf-mode")
    public Result<Map<String, Object>> getWafMode() {
        return Result.ok(Map.of("mode", waf.getWafMode()));
    }

    /** 设置全局防护模式：
     *  hidden = 开启且隐藏指纹（推荐）：防护全开，响应特征与原生 nginx 一致，不暴露 WAF 品牌
     *  public = 开启且公开指纹：防护全开，拦截页与 Server/X-WAF 头公开 NovaWAF 品牌（可被 wafw00f 识别，起威慑作用）
     *  off    = 关闭防护：全站降级旁路观察，攻击仅记录不拦截不封禁（应急排障用） */
    @RequirePerms("system:settings:edit")
    @PutMapping("/waf-mode")
    public Result<String> setWafMode(@RequestBody Map<String, Object> req) {
        String mode = String.valueOf(req.get("mode"));
        waf.setWafMode(mode);
        String by = UserContext.get() == null ? "system" : UserContext.get().getUsername();
        audit.record(by, "system", "设置全局防护模式", "PUT", null, 1, "wafMode=" + mode, 0);
        return Result.ok("已切换到 " + mode + " 模式，引擎 2 秒内热生效");
    }

    /** 检测规则版本信息：版本号(单调递增)/规则条数/最近更新时间/规则集来源 */
    @RequirePerms("system:settings:list")
    @GetMapping("/rules-version")
    public Result<Map<String, Object>> rulesVersion() {
        return Result.ok(waf.rulesVersionInfo());
    }
}
