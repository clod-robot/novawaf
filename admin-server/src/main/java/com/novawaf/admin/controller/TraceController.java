package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.service.TraceService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/** 攻击溯源分析: 攻击源 IP 排行 + 单 IP 攻击链时间线 */
@RestController
@RequestMapping("/api/trace")
@RequiredArgsConstructor
public class TraceController {
    private final TraceService trace;

    @RequirePerms("waf:trace:list")
    @GetMapping("/summary")
    public Result<Map<String, Object>> summary(@RequestParam(defaultValue = "50") int limit) {
        return Result.ok(trace.summary(limit));
    }

    @RequirePerms("waf:trace:list")
    @GetMapping("/ip/{ip}")
    public Result<Map<String, Object>> ipDetail(@PathVariable String ip,
                                                @RequestParam(required = false) Long from,
                                                @RequestParam(required = false) Long to) {
        return Result.ok(trace.ipDetail(ip, from, to));
    }
}
