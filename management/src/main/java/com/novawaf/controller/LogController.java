package com.novawaf.controller;

import com.novawaf.domain.WafLog;
import com.novawaf.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

/**
 * 攻击日志查询 API
 */
@RestController
@RequestMapping("/api/logs")
public class LogController {

    @Autowired
    private LogService logService;

    @GetMapping
    public Page<WafLog> list(@RequestParam(defaultValue = "0") int page,
                             @RequestParam(defaultValue = "50") int size,
                             @RequestParam(required = false) String category) {
        return logService.list(page, size, category);
    }
}
