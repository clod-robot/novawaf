package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.ApiPolicy;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.ApiPolicyService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * API 路径级防护策略：按 URL 前缀将 WAF 处置设为
 * block(拦截) / log(仅记录·观察期) / pass(跳过WAF检测)。保存即自动发布、引擎 3s 内热生效。
 */
@RestController
@RequestMapping("/api/waf/api-policy")
@RequiredArgsConstructor
public class ApiPolicyController {

    private final ApiPolicyService service;
    private final AuditService audit;

    @RequirePerms("waf:apipolicy:list")
    @GetMapping("/list")
    public Result<List<ApiPolicy>> list() {
        return Result.ok(service.list());
    }

    @RequirePerms("waf:apipolicy:edit")
    @PostMapping
    public Result<Void> add(@RequestBody ApiPolicy p) {
        service.add(p);
        audit.record(user(), "waf", "新增API防护策略", "POST", null, 1, "prefix=" + p.getPrefix(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apipolicy:edit")
    @PutMapping
    public Result<Void> update(@RequestBody ApiPolicy p) {
        service.update(p);
        audit.record(user(), "waf", "修改API防护策略", "PUT", null, 1, "id=" + p.getId() + ",prefix=" + p.getPrefix(), 0);
        return Result.ok();
    }

    /** 快速启停 */
    @RequirePerms("waf:apipolicy:edit")
    @PutMapping("/{id}/enabled")
    public Result<Void> toggle(@PathVariable Long id, @RequestBody(required = false) Map<String, Boolean> body) {
        service.toggle(id, body == null ? null : body.get("enabled"));
        audit.record(user(), "waf", "启停API防护策略", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:apipolicy:edit")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        service.delete(id);
        audit.record(user(), "waf", "删除API防护策略", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    /** 下载导入模板（CSV，UTF-8 BOM，Excel 可直接打开编辑） */
    @RequirePerms("waf:apipolicy:list")
    @GetMapping("/template")
    public ResponseEntity<byte[]> template() {
        String csv = "\uFEFF序号,请求格式,API接口,动作,所属应用,策略名称,备注\r\n"
                + "1,GET,/api/portal/*,拦截,,门户接口拦截,示例行可直接删除\r\n"
                + "2,POST,/api/auth/login,仅记录,,登录接口观察期,所属应用留空=全部应用；也可填应用名称(如 A)\r\n"
                + "3,ANY,/static/*,放行,,静态资源放行,\r\n";
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"api-policy-template.csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(csv.getBytes(StandardCharsets.UTF_8));
    }

    /** 批量导入（CSV）：序号,请求格式,API接口,动作,所属应用,策略名称,备注 */
    @RequirePerms("waf:apipolicy:edit")
    @PostMapping("/import")
    public Result<Map<String, Object>> importCsv(@RequestParam("file") MultipartFile file) throws Exception {
        String text = new String(file.getBytes(), StandardCharsets.UTF_8);
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        List<String[]> rows = parseCsv(text);
        if (rows.isEmpty()) return Result.ok(Map.of("success", 0, "failed", List.of()));

        Map<String, String> appIdByName = service.appIdByName();
        List<com.novawaf.admin.entity.ApiPolicy> items = new ArrayList<>();
        List<Map<String, Object>> failed = new ArrayList<>();
        int lineNo = 0;
        for (String[] r : rows) {
            lineNo++;
            String first = r.length > 0 ? r[0].trim() : "";
            // 跳过表头
            if (lineNo == 1 && (first.isEmpty() || first.contains("序号"))) continue;
            if (r.length < 4 || first.isEmpty()) continue; // 空行/序号缺失视为占位行
            String method = r[1].trim().toUpperCase();
            String prefix = r[2].trim();
            String action = normalizeAction(r[3].trim());
            String appRaw = r.length > 4 ? r[4].trim() : "";
            String name = r.length > 5 ? r[5].trim() : "";
            String remark = r.length > 6 ? r[6].trim() : "";

            com.novawaf.admin.entity.ApiPolicy p = new com.novawaf.admin.entity.ApiPolicy();
            p.setPrefix(prefix);
            p.setAction(action);
            p.setName(name.isEmpty() ? ("导入-" + prefix) : name);
            String appId = appRaw;
            if (!appRaw.isEmpty()) {
                String byName = appIdByName.get(appRaw);
                if (byName != null) appId = byName;
                else if (!appIdByName.containsValue(appRaw)) {
                    Map<String, Object> f = new java.util.HashMap<>();
                    f.put("line", lineNo);
                    f.put("prefix", prefix);
                    f.put("reason", "所属应用不存在：" + appRaw);
                    failed.add(f);
                    continue;
                }
            }
            p.setAppId(appId);
            // 请求格式当前不参与匹配（策略按路径前缀生效），随备注留档备查
            p.setRemark(method.isEmpty() || "ANY".equals(method)
                    ? remark : ("[" + method + "] " + remark).trim());
            p.setEnabled(true);
            items.add(p);
        }
        Map<String, Object> r = service.addBatch(items);
        r.put("failed", mergeFailed(failed, r.get("failed"), items));
        audit.record(user(), "waf", "批量导入API防护策略", "POST", null, 1,
                "导入成功=" + r.get("success"), 0);
        return Result.ok(r);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> mergeFailed(List<Map<String, Object>> pre,
                                                  Object fromService,
                                                  List<com.novawaf.admin.entity.ApiPolicy> items) {
        List<Map<String, Object>> all = new ArrayList<>(pre);
        if (fromService instanceof List) {
            for (Map<String, Object> f : (List<Map<String, Object>>) fromService) {
                Object idx = f.remove("index");
                if (idx instanceof Integer i && i >= 0 && i < items.size()) {
                    Map<String, Object> grown = new java.util.HashMap<>();
                    grown.put("line", idx);
                    grown.put("prefix", items.get((Integer) idx).getPrefix());
                    grown.put("reason", f.get("reason"));
                    all.add(grown);
                } else {
                    all.add(f);
                }
            }
        }
        return all;
    }

    private static String normalizeAction(String v) {
        if (v.isEmpty()) return "log";
        switch (v) {
            case "拦截": case "block": case "BLOCK": return "block";
            case "放行": case "pass": case "PASS": case "允许": return "pass";
            case "仅记录": case "log": case "LOG": case "记录": return "log";
            default: return v.toLowerCase();
        }
    }

    private static List<String[]> parseCsv(String text) {
        List<String[]> out = new ArrayList<>();
        for (String line : text.split("\r?\n")) {
            if (line.trim().isEmpty()) continue;
            List<String> cols = new ArrayList<>();
            StringBuilder sb = new StringBuilder();
            boolean q = false;
            for (char ch : line.toCharArray()) {
                if (ch == '"') { q = !q; continue; }
                if (ch == ',' && !q) { cols.add(sb.toString().trim()); sb.setLength(0); continue; }
                sb.append(ch);
            }
            cols.add(sb.toString().trim());
            out.add(cols.toArray(new String[0]));
        }
        return out;
    }

    private String user() {
        return UserContext.get() == null ? "system" : UserContext.get().getUsername();
    }
}
