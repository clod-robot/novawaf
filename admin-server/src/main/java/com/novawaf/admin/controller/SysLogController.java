package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.SysOperLog;
import com.novawaf.admin.mapper.SysOperLogMapper;
import com.novawaf.admin.security.RequirePerms;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/system/logs")
@RequiredArgsConstructor
public class SysLogController {
    private final SysOperLogMapper operLogMapper;

    @RequirePerms("sys:log:list")
    @GetMapping
    public Result<Map<String, Object>> page(@RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "20") int size,
                                            @RequestParam(required = false) String username) {
        if (size > 200) size = 200;
        List<SysOperLog> rows = operLogMapper.selectPage(username, (page - 1) * size, size);
        Map<String, Object> m = new HashMap<>();
        m.put("total", operLogMapper.count(username));
        m.put("rows", rows);
        return Result.ok(m);
    }
}
