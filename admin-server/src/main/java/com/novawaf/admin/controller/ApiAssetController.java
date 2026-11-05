package com.novawaf.admin.controller;

import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.ApiAsset;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import com.novawaf.admin.service.ApiAssetService;
import com.novawaf.admin.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API 资产自动发现与目录：
 * - 目录/概览：读取引擎快照，识别影子 API（未登记）与僵尸 API（登记后长期无流量）；
 * - 登记清单：MySQL 真值，保存即自动发布、引擎 5s 内热生效。
 */
@RestController
@RequestMapping("/api/waf/api-assets")
@RequiredArgsConstructor
public class ApiAssetController {

    private final ApiAssetService service;
    private final AuditService audit;

    /** 资产目录（分页 + 三态筛选） */
    @RequirePerms("waf:apiasset:list")
    @GetMapping("/list")
    public Result<Map<String, Object>> list(@RequestParam(required = false) String kind,
                                           @RequestParam(required = false) String appId,
                                           @RequestParam(required = false) String method,
                                           @RequestParam(required = false) String keyword,
                                           @RequestParam(defaultValue = "1") int page,
                                           @RequestParam(defaultValue = "20") int size) {
        return Result.ok(service.directory(kind, appId, method, keyword, page, size));
    }

    /** 概览统计：影子/僵尸/已登记/24h 新增 */
    @RequirePerms("waf:apiasset:list")
    @GetMapping("/stats")
    public Result<Map<String, Object>> stats() {
        return Result.ok(service.stats());
    }

    /** 已登记清单 */
    @RequirePerms("waf:apiasset:list")
    @GetMapping("/inventory")
    public Result<List<ApiAsset>> inventory() {
        return Result.ok(service.inventoryList());
    }

    @RequirePerms("waf:apiasset:edit")
    @PostMapping("/inventory")
    public Result<Void> add(@RequestBody ApiAsset a) {
        service.add(a);
        audit.record(user(), "waf", "登记API资产", "POST", null, 1,
                a.getMethod() + " " + a.getPath(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiasset:edit")
    @PutMapping("/inventory")
    public Result<Void> update(@RequestBody ApiAsset a) {
        service.update(a);
        audit.record(user(), "waf", "修改API资产登记", "PUT", null, 1,
                "id=" + a.getId() + "," + a.getMethod() + " " + a.getPath(), 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiasset:edit")
    @PutMapping("/inventory/{id}/enabled")
    public Result<Void> toggle(@PathVariable Long id,
                               @RequestBody(required = false) Map<String, Boolean> body) {
        service.toggle(id, body == null ? null : body.get("enabled"));
        audit.record(user(), "waf", "启停API资产登记", "PUT", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    @RequirePerms("waf:apiasset:edit")
    @DeleteMapping("/inventory/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        service.delete(id);
        audit.record(user(), "waf", "删除API资产登记", "DELETE", null, 1, "id=" + id, 0);
        return Result.ok();
    }

    /** 影子资产一键登记（支持批量），已存在自动跳过 */
    @RequirePerms("waf:apiasset:edit")
    @PostMapping("/inventory/promote")
    public Result<Map<String, Object>> promote(@RequestBody List<ApiAsset> items) {
        Map<String, Object> r = service.promote(items);
        audit.record(user(), "waf", "影子API一键登记", "POST", null, 1,
                "新增=" + r.get("added") + ",跳过=" + r.get("skipped"), 0);
        return Result.ok(r);
    }

    /** 下载登记模板（CSV，UTF-8 BOM） */
    @RequirePerms("waf:apiasset:list")
    @GetMapping("/inventory/template")
    public ResponseEntity<byte[]> template() {
        String csv = "\uFEFF序号,请求格式,接口,所属应用,资产名称,责任人,备注\r\n"
                + "1,GET,/api/user/{id},,用户详情,张三,路径已归一化，{id} 表示可变段\r\n"
                + "2,POST,/api/order/create,,创建订单,李四,所属应用留空=全部应用\r\n"
                + "3,ANY,/api/report/export,,报表导出,王五,ANY 发布时自动展开为全部方法\r\n";
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"api-asset-template.csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(csv.getBytes(StandardCharsets.UTF_8));
    }

    /** 批量导入登记（CSV）：序号,请求格式,接口,所属应用,资产名称,责任人,备注 */
    @RequirePerms("waf:apiasset:edit")
    @PostMapping("/inventory/import")
    public Result<Map<String, Object>> importCsv(@RequestParam("file") MultipartFile file) throws Exception {
        String text = new String(file.getBytes(), StandardCharsets.UTF_8);
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        List<String[]> rows = parseCsv(text);
        Map<String, String> appIdByName = appIdByName();
        List<ApiAsset> items = new ArrayList<>();
        List<Map<String, Object>> failed = new ArrayList<>();
        int lineNo = 0;
        for (String[] r : rows) {
            lineNo++;
            String first = r.length > 0 ? r[0].trim() : "";
            if (lineNo == 1 && (first.isEmpty() || first.contains("序号"))) continue;
            if (r.length < 3 || first.isEmpty()) continue;
            ApiAsset a = new ApiAsset();
            a.setMethod(r[1].trim().toUpperCase());
            a.setPath(r[2].trim());
            a.setName(r.length > 4 ? r[4].trim() : "");
            a.setOwner(r.length > 5 ? r[5].trim() : "");
            a.setRemark(r.length > 6 ? r[6].trim() : "");
            String appRaw = r.length > 3 ? r[3].trim() : "";
            if (!appRaw.isEmpty()) {
                String byName = appIdByName.get(appRaw);
                if (byName != null) {
                    a.setAppId(byName);
                } else if (appIdByName.containsValue(appRaw)) {
                    a.setAppId(appRaw);
                } else {
                    Map<String, Object> f = new HashMap<>();
                    f.put("line", lineNo);
                    f.put("path", a.getPath());
                    f.put("reason", "所属应用不存在：" + appRaw);
                    failed.add(f);
                    continue;
                }
            }
            a.setEnabled(true);
            items.add(a);
        }
        Map<String, Object> r = service.promote(items);
        r.put("failed", failed);
        audit.record(user(), "waf", "批量导入API资产登记", "POST", null, 1,
                "新增=" + r.get("added") + ",跳过=" + r.get("skipped") + ",失败=" + failed.size(), 0);
        return Result.ok(r);
    }

    private Map<String, String> appIdByName() {
        Map<String, String> m = new HashMap<>();
        for (Map.Entry<String, String> e : service.appNames().entrySet()) m.put(e.getValue(), e.getKey());
        return m;
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
