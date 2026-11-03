package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.AuditService;
import com.novawaf.admin.service.RateLimitService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 阈值管理：端点分级限流策略（read/write/upload/auth/static 五类独立配额）。
 * 数据面透传引擎 Redis 配置，引擎 3s 轮询版本号热生效，无需重启。
 * 上线顺序约定：stage 0 monitor-only（只记账不处置，采集 7 天分布）→ 1 auth →
 * 2 read/write/upload → 3 封禁阶梯（仅到 L2 URL+方法，不开 L4 全端口）。
 */
@RestController
@RequestMapping("/api/settings/ratelimit")
@RequiredArgsConstructor
public class RateLimitController {
    private final RateLimitService svc;
    private final AuditService audit;

    /** 查询当前策略 + 版本 + 引擎运行指标 + 各类别最新采集分布 */
    @RequirePerms("system:settings:list")
    @GetMapping
    public Result<Map<String, Object>> get() {
        return Result.ok(svc.get());
    }

    /** 保存策略：字段级合并，INCR 版本号触发引擎热加载 */
    @RequirePerms("system:settings:edit")
    @PutMapping
    public Result<String> update(@RequestBody Map<String, Object> req) {
        String msg = svc.update(req);
        String by = UserContext.get() == null ? "system" : UserContext.get().getUsername();
        audit.record(by, "system", "下发限流阈值策略", "PUT", null, 1,
                "stage=" + req.get("stage"), 0);
        return Result.ok(msg);
    }

    /** 某类别的分钟级分布历史（P50/P99/P99.9、3s 峰值、桶利用率趋势） */
    @RequirePerms("system:settings:list")
    @GetMapping("/dist/{cls}")
    public Result<List<Object>> distHistory(@PathVariable String cls,
                                            @RequestParam(defaultValue = "240") int limit) {
        return Result.ok(svc.distHistory(cls, limit));
    }
}
