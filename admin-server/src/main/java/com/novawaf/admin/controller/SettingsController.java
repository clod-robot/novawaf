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

    /** 查询拟态防御配置与引擎当前人格预览 */
    @RequirePerms("system:settings:list")
    @GetMapping("/mimic")
    public Result<Map<String, Object>> getMimic() {
        return Result.ok(waf.getMimic());
    }

    /** 设置拟态防御：enabled 开关 + windowMin 轮换窗口(分钟,5-1440)。
     *  启用后拦截响应的 Server banner/状态码/页面模板/会话 cookie 名按时间窗确定性轮换，
     *  攻击者跨窗指纹探测结论全部失效；仅作用于"隐藏指纹"模式。引擎 2s 内热生效。 */
    @RequirePerms("system:settings:edit")
    @PutMapping("/mimic")
    public Result<String> setMimic(@RequestBody Map<String, Object> req) {
        boolean enabled = Boolean.TRUE.equals(req.get("enabled"))
                || "true".equals(String.valueOf(req.get("enabled")));
        int windowMin = 60;
        try { windowMin = Integer.parseInt(String.valueOf(req.get("windowMin"))); }
        catch (Exception ignore) {}
        waf.setMimic(enabled, windowMin);
        String by = UserContext.get() == null ? "system" : UserContext.get().getUsername();
        audit.record(by, "system", "设置拟态防御", "PUT", null, 1,
                "mimic=" + (enabled ? "on" : "off") + ",windowMin=" + windowMin, 0);
        return Result.ok(enabled ? "拟态防御已开启，引擎 2 秒内热生效" : "拟态防御已关闭");
    }

    /** 一键轮换盐：全部人格序列立即更换，正在进行的探测结论即刻作废 */
    @RequirePerms("system:settings:edit")
    @PostMapping("/mimic/rotate-salt")
    public Result<String> rotateMimicSalt() {
        String tail = waf.rotateMimicSalt();
        String by = UserContext.get() == null ? "system" : UserContext.get().getUsername();
        audit.record(by, "system", "轮换拟态盐", "POST", null, 1, "saltTail=" + tail, 0);
        return Result.ok("盐已轮换(尾号 " + tail + ")，全部人格序列已更换");
    }
}
