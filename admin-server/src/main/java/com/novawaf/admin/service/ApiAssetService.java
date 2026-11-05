package com.novawaf.admin.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.ApiAsset;
import com.novawaf.admin.mapper.ApiAssetMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * API 资产目录服务：
 * - 资产目录：读取引擎快照 Redis novawaf:api:assets（含 kind=registered/shadow/zombie 三态），
 *   管理端只做筛选/分页/展示，避免与引擎口径分叉；
 * - 资产登记：MySQL 为真值，整表发布 Redis novawaf:api:inventory + INCR 版本号，引擎 5s 内热加载；
 *   登记后即从影子列表消失，长期无流量则归入僵尸。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiAssetService {

    public static final String INVENTORY_KEY = "novawaf:api:inventory";
    public static final String INVENTORY_VERSION = "novawaf:api:inventory:version";
    /** 引擎每分钟写出的资产目录快照 */
    public static final String SNAPSHOT_KEY = "novawaf:api:assets";
    public static final String APPS_KEY = "novawaf:apps";

    /** 发布护栏：清单超过该数量拒绝发布，防止误导入撑爆引擎内存 */
    private static final int MAX_INVENTORY = 20000;
    private static final Set<String> METHODS =
            Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY");
    private static final List<String> EXPAND_METHODS =
            List.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS");
    /** 路径只允许安全字符（与引擎路径模板一致的字符集） */
    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9_\\-./{}:?%~]*$");

    private final ApiAssetMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /* ============================ 资产目录 ============================ */

    /** 资产目录（分页）：kind 为空/all 表示全部；keyword 匹配路径或资产名。 */
    @SuppressWarnings("unchecked")
    public Map<String, Object> directory(String kind, String appId, String method, String keyword,
                                         int page, int size) {
        Map<String, Object> snap = snapshot();
        Map<String, String> appNames = appNames();
        List<Map<String, Object>> assets = new ArrayList<>();
        Object raw = snap.get("assets");
        if (raw instanceof List) {
            for (Object o : (List<Object>) raw) {
                if (o instanceof Map) assets.add((Map<String, Object>) o);
            }
        }
        String k = kind == null ? "" : kind.trim().toLowerCase();
        String aid = appId == null ? "" : appId.trim();
        String mth = method == null ? "" : method.trim().toUpperCase();
        String kw = keyword == null ? "" : keyword.trim().toLowerCase();

        List<Map<String, Object>> filtered = new ArrayList<>(assets.size());
        for (Map<String, Object> a : assets) {
            String ak = str(a.get("kind"));
            if (!k.isEmpty() && !"all".equals(k) && !k.equals(ak)) continue;
            if (!aid.isEmpty() && !aid.equals(str(a.get("appId")))) continue;
            if (!mth.isEmpty() && !mth.equals(str(a.get("method")))) continue;
            if (!kw.isEmpty()) {
                String tpl = str(a.get("template")).toLowerCase();
                String nm = str(a.get("name")).toLowerCase();
                if (!tpl.contains(kw) && !nm.contains(kw)) continue;
            }
            Map<String, Object> row = new LinkedHashMap<>(a);
            String app = str(a.get("appId"));
            row.put("appName", app.isEmpty() ? "全部应用" : appNames.getOrDefault(app, "应用-" + app));
            filtered.add(row);
        }
        // 活跃度优先：影子在前，其次最近访问时间倒序，避免列表噪声
        filtered.sort(Comparator
                .comparingInt((Map<String, Object> m) -> kindRank(str(m.get("kind"))))
                .thenComparing(Comparator.comparingLong((Map<String, Object> m) -> num(m.get("lastSeen"))).reversed()));
        long total = filtered.size();
        int p = Math.max(1, page);
        int s = Math.min(1000, Math.max(1, size));
        int from = (p - 1) * s;
        List<Map<String, Object>> items = from >= filtered.size()
                ? List.of() : filtered.subList(from, Math.min(from + s, filtered.size()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", total);
        out.put("page", p);
        out.put("size", s);
        out.put("items", items);
        out.put("summary", summary(snap));
        return out;
    }

    private static int kindRank(String kind) {
        switch (kind) {
            case "shadow": return 0;
            case "zombie": return 1;
            case "registered": return 2;
            default: return 3;
        }
    }

    /** 概览统计（直接取引擎快照的聚合字段，保证与目录口径一致） */
    public Map<String, Object> summary(Map<String, Object> snap) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", num(snap.get("ts")));
        m.put("total", num(snap.get("total")));
        m.put("observed", num(snap.get("observed")));
        m.put("shadow", num(snap.get("shadow")));
        m.put("registered", num(snap.get("registered")));
        m.put("zombie", num(snap.get("zombie")));
        m.put("new24h", num(snap.get("new24h")));
        m.put("inventory", num(snap.get("inventory")));
        m.put("dropped", num(snap.get("dropped")));
        return m;
    }

    public Map<String, Object> stats() {
        return summary(snapshot());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> snapshot() {
        try {
            String raw = redis.opsForValue().get(SNAPSHOT_KEY);
            if (raw == null || raw.isBlank()) return Map.of();
            Map<String, Object> m = om.readValue(raw, new TypeReference<Map<String, Object>>() {});
            return m == null ? Map.of() : m;
        } catch (Exception e) {
            log.warn("读取 API 资产快照失败: {}", e.getMessage());
            return Map.of();
        }
    }

    /* ============================ 资产登记（清单） ============================ */

    public List<ApiAsset> inventoryList() {
        Map<String, String> names = appNames();
        List<ApiAsset> all = mapper.selectAll();
        for (ApiAsset a : all) {
            String aid = a.getAppId();
            a.setAppName(aid == null || aid.isBlank() ? "全部应用" : names.getOrDefault(aid, "应用-" + aid));
        }
        return all;
    }

    @Transactional
    public void add(ApiAsset a) {
        normalize(a, true);
        if (mapper.countByKey(a.getAppId(), a.getMethod(), a.getPath(), null) > 0) {
            throw new BusinessException("该应用下资产已登记：" + a.getMethod() + " " + a.getPath());
        }
        if (a.getEnabled() == null) a.setEnabled(true);
        mapper.insert(a);
        publish();
    }

    @Transactional
    public void update(ApiAsset a) {
        if (a.getId() == null || mapper.selectById(a.getId()) == null) {
            throw new BusinessException("资产不存在或已被删除");
        }
        normalize(a, true);
        if (mapper.countByKey(a.getAppId(), a.getMethod(), a.getPath(), a.getId()) > 0) {
            throw new BusinessException("该应用下资产已被其它记录占用：" + a.getMethod() + " " + a.getPath());
        }
        if (a.getEnabled() == null) a.setEnabled(true);
        mapper.update(a);
        publish();
    }

    @Transactional
    public void toggle(Long id, Boolean enabled) {
        if (id == null || mapper.selectById(id) == null) throw new BusinessException("资产不存在或已被删除");
        mapper.updateEnabled(id, Boolean.TRUE.equals(enabled));
        publish();
    }

    @Transactional
    public void delete(Long id) {
        if (id == null || mapper.selectById(id) == null) throw new BusinessException("资产不存在或已被删除");
        mapper.deleteById(id);
        publish();
    }

    /** 影子资产一键登记：已存在则跳过，返回新增/跳过数量。 */
    @Transactional
    public Map<String, Object> promote(List<ApiAsset> items) {
        int added = 0, skipped = 0;
        if (items != null) {
            for (ApiAsset a : items) {
                try {
                    normalize(a, false);
                    if (mapper.countByKey(a.getAppId(), a.getMethod(), a.getPath(), null) > 0) {
                        skipped++;
                        continue;
                    }
                    if (a.getEnabled() == null) a.setEnabled(true);
                    mapper.insert(a);
                    added++;
                } catch (Exception e) {
                    skipped++;
                }
            }
        }
        if (added > 0) publish();
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("added", added);
        r.put("skipped", skipped);
        return r;
    }

    /** 校验 + 归一：方法大写白名单，路径只允许安全字符且不含 * （清单是精确模板，通配属于限流策略）。 */
    private void normalize(ApiAsset a, boolean strict) {
        if (a == null) throw new BusinessException("参数不能为空");
        String name = a.getName() == null ? "" : a.getName().trim();
        String method = a.getMethod() == null ? "" : a.getMethod().trim().toUpperCase();
        String path = a.getPath() == null ? "" : a.getPath().trim();
        String appId = a.getAppId() == null ? "" : a.getAppId().trim();
        if (name.length() > 128) throw new BusinessException("资产名称不能超过 128 字符");
        if (method.isEmpty()) method = "ANY";
        if (!METHODS.contains(method)) {
            throw new BusinessException("请求方法只能是 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/ANY");
        }
        if (path.isEmpty() || path.length() > 255 || !SAFE_PATH.matcher(path).matches()) {
            throw new BusinessException("路径必须以 / 开头，仅允许字母数字及 / _ - . { } : ? % ~ ，长度不超过 255");
        }
        if (path.contains("..")) throw new BusinessException("路径不允许包含 .. 目录穿越片段");
        if (path.contains("*")) throw new BusinessException("资产清单为精确路径模板，不支持通配符 *（请到 API 策略中配置）");
        if (!appId.isEmpty() && (appId.length() > 32 || !appNames().containsKey(appId))) {
            if (strict) throw new BusinessException("所属应用不存在或非法：" + appId);
            else appId = "";
        }
        if (a.getOwner() != null && a.getOwner().length() > 64) throw new BusinessException("责任人不能超过 64 字符");
        if (a.getRemark() != null && a.getRemark().length() > 255) throw new BusinessException("备注不能超过 255 字符");
        a.setName(name);
        a.setMethod(method);
        a.setPath(path);
        a.setAppId(appId.isEmpty() ? null : appId);
    }

    /** 整表发布：{"items":[{appId,method,path}]}，ANY 展开为全部方法（引擎按精确方法匹配）。 */
    private void publish() {
        try {
            List<ApiAsset> rows = mapper.selectEnabled();
            ObjectNode root = om.createObjectNode();
            ArrayNode items = om.createArrayNode();
            int count = 0;
            for (ApiAsset a : rows) {
                List<String> methods = "ANY".equals(a.getMethod()) ? EXPAND_METHODS : List.of(a.getMethod());
                for (String mth : methods) {
                    ObjectNode it = om.createObjectNode();
                    it.put("appId", a.getAppId() == null ? "" : a.getAppId());
                    it.put("method", mth);
                    it.put("path", a.getPath());
                    items.add(it);
                    if (++count > MAX_INVENTORY) {
                        throw new BusinessException("已登记资产条目（含方法展开）超过上限 " + MAX_INVENTORY);
                    }
                }
            }
            root.set("items", items);
            redis.opsForValue().set(INVENTORY_KEY, om.writeValueAsString(root));
            Long ver = redis.opsForValue().increment(INVENTORY_VERSION);
            log.info("API 资产清单已发布: {} 条记录 / {} 个方法条目, version={}", rows.size(), count, ver);
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            throw new BusinessException(500, "资产清单已保存但发布到引擎失败：" + e.getMessage());
        }
    }

    /* ============================ 公共辅助 ============================ */

    /** 应用 id -> 名称（来自引擎应用注册表 novawaf:apps） */
    @SuppressWarnings("unchecked")
    public Map<String, String> appNames() {
        Map<String, String> m = new HashMap<>();
        try {
            String raw = redis.opsForValue().get(APPS_KEY);
            if (raw == null) return m;
            JsonNode arr = om.readTree(raw);
            if (arr.isArray()) {
                for (JsonNode n : arr) {
                    String id = n.path("id").asText("");
                    if (id.isEmpty()) continue;
                    String nm = n.path("name").asText("");
                    m.put(id, nm.isEmpty() ? "应用-" + id : nm);
                }
            }
        } catch (Exception ignore) { }
        return m;
    }

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    private static long num(Object o) {
        if (o instanceof Number) return ((Number) o).longValue();
        try { return Long.parseLong(str(o)); } catch (Exception e) { return 0L; }
    }
}
