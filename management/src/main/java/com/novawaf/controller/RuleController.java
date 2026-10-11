package com.novawaf.controller;

import com.novawaf.domain.WafRule;
import com.novawaf.service.RuleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

/**
 * 规则管理 REST API（管理面，需认证）
 */
@RestController
@RequestMapping("/api/rules")
public class RuleController {

    @Autowired
    private RuleService ruleService;

    @GetMapping
    public List<WafRule> list() {
        return ruleService.listAll();
    }

    @PostMapping
    public ResponseEntity<WafRule> create(@Valid @RequestBody WafRule rule) {
        return ResponseEntity.ok(ruleService.save(rule));
    }

    @PutMapping("/{id}")
    public ResponseEntity<WafRule> update(@PathVariable Long id, @Valid @RequestBody WafRule rule) {
        rule.setId(id);
        return ResponseEntity.ok(ruleService.save(rule));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        ruleService.delete(id);
        return ResponseEntity.ok().build();
    }

    /** 规则热加载：推送到 C++ 检测引擎 */
    @PostMapping("/reload")
    public ResponseEntity<String> reload() {
        boolean ok = ruleService.pushToEngine();
        return ok ? ResponseEntity.ok("reloaded") : ResponseEntity.status(503).body("engine unreachable");
    }
}
