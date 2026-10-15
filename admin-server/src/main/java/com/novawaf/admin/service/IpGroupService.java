package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.SafeExec;
import com.novawaf.admin.entity.IpGroup;
import com.novawaf.admin.mapper.IpGroupMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * IP 组服务。
 * 生效链路（保存/导入/更新即同步，引擎 3s 内热加载）：
 * - custom + block  → 条目并入 novawaf:blacklist（source=group:{id}，整组替换）
 * - custom + allow  → 条目并入 novawaf:whitelist（同上）
 * - threat          → 条目重建进 novawaf:ioc（类别 ipgroup:{id}，severity=high），cksum 写 novawaf:meta
 * 条目本体存 Redis SET novawaf:ipgroup:{id}；更新任务状态存 novawaf:ipgroup:task:{id}。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IpGroupService {

    public static final String GROUP_KEY_PREFIX = "novawaf:ipgroup:";
    public static final String TASK_KEY_PREFIX = "novawaf:ipgroup:task:";
    public static final String IOC_KEY = "novawaf:ioc";
    public static final String IOC_CATEGORY_PREFIX = "ipgroup:";
    // 与 IpListService 私有键一致（不改动其封装），引擎按此版本号热加载
    private static final String IPLIST_VERSION = "novawaf:iplist:version";
    private static final String META_KEY = "novawaf:meta";
    private static final int MAX_ENTRIES = 200_000;
    private static final int MAX_IMPORT_BYTES = 8 * 1024 * 1024;
    private static final int SADD_BATCH = 5000;
    private static final long TASK_STALE_MS = 15 * 60 * 1000L;
    private static final Pattern URL_RE = Pattern.compile("^https?://\\S+$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NAME_RE = Pattern.compile("^[\\w.\\-\\u4e00-\\u9fa5 ]{1,64}$");

    private final IpGroupMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    @Value("${nova.ipgroup.fetch-script:/opt/novawaf/scripts/fetch_ip_list.py}")
    private String fetchScript;
    @Value("${nova.ipgroup.threat-script:/opt/novawaf/scripts/collect_malicious_ips.py}")
    private String threatScript;
    @Value("${nova.ipgroup.fetch-timeout-ms:120000}")
    private long fetchTimeoutMs;
    @Value("${nova.ipgroup.threat-timeout-ms:300000}")
    private long threatTimeoutMs;

    /** 供重建 ioc 文本时传组条目（纯逻辑可单测）。 */
    public record GroupEntries(long id, String name, List<String> entries) {}

    // ---------------- 组 CRUD ----------------

    public List<Map<String, Object>> listGroups() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (IpGroup g : mapper.selectAll()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", g.getId());
            m.put("name", g.getName());
            m.put("type", g.getType());
            m.put("action", g.getAction());
            m.put("sourceUrl", g.getSourceUrl() == null ? "" : g.getSourceUrl());
            m.put("remark", g.getRemark() == null ? "" : g.getRemark());
            m.put("enabled", Boolean.TRUE.equals(g.getEnabled()));
            long cnt = entryCount(g.getId());
            m.put("entryCount", cnt);
            m.put("summary", summarize(g.getId(), cnt));
            m.put("updateTime", g.getUpdateTime() == null ? null : g.getUpdateTime().getTime());
            out.add(m);
        }
        return out;
    }

    @Transactional
    public IpGroup create(IpGroup req) {
        IpGroup g = normalize(req, null);
        if (mapper.selectByName(g.getName()) != null) {
            throw new BusinessException("同名 IP 组已存在，不允许重复");
        }
        mapper.insert(g);
        syncChannel(g);
        return mapper.selectById(g.getId());
    }

    @Transactional
    public IpGroup update(long id, IpGroup req) {
        IpGroup old = mustGet(id);
        IpGroup g = normalize(req, old);
        IpGroup dup = mapper.selectByName(g.getName());
        if (dup != null && !dup.getId().equals(id)) {
            throw new BusinessException("同名 IP 组已存在，不允许重复");
        }
        g.setId(id);
        mapper.update(g);
        syncChannel(mapper.selectById(id));
        return mapper.selectById(id);
    }

    @Transactional
    public void delete(long id) {
        mustGet(id);
        mapper.deleteById(id);
        // 从生效通道摘除本组条目
        removeFromIpList(id, false);
        removeFromIpList(id, true);
        syncIoc();
        redis.delete(GROUP_KEY_PREFIX + id);
        redis.delete(TASK_KEY_PREFIX + id);
    }

    private IpGroup mustGet(long id) {
        IpGroup g = mapper.selectById(id);
        if (g == null) throw new BusinessException("IP 组不存在");
        return g;
    }

    private IpGroup normalize(IpGroup req, IpGroup old) {
        if (req == null) throw new BusinessException("参数不能为空");
        String name = req.getName() == null ? "" : req.getName().trim();
        if (!NAME_RE.matcher(name).matches()) {
            throw new BusinessException("组名必填，仅允许中英文/数字及 _-. 空格，长度不超过 64");
        }
        String type = req.getType() == null ? "" : req.getType().trim().toLowerCase();
        if (!type.equals("custom") && !type.equals("threat")) {
            throw new BusinessException("组类型只能是 custom（自定义）或 threat（威胁情报）");
        }
        String action = req.getAction() == null ? "" : req.getAction().trim().toLowerCase();
        if (type.equals("threat")) {
            action = "block";  // 情报组固定拦截语义（引擎威胁情报通道）
        } else if (!action.equals("block") && !action.equals("allow")) {
            throw new BusinessException("自定义组动作只能是 block（拦截）或 allow（放行）");
        }
        String url = req.getSourceUrl() == null ? "" : req.getSourceUrl().trim();
        if (!url.isEmpty() && !URL_RE.matcher(url).matches()) {
            throw new BusinessException("源 URL 必须是 http/https 地址");
        }
        String remark = req.getRemark() == null ? "" : req.getRemark().trim();
        if (remark.length() > 255) throw new BusinessException("备注长度不能超过 255");
        Boolean enabled = req.getEnabled() == null ? (old == null ? Boolean.TRUE : old.getEnabled()) : req.getEnabled();

        IpGroup g = new IpGroup();
        g.setName(name);
        g.setType(type);
        g.setAction(action);
        g.setSourceUrl(url.isEmpty() ? null : url);
        g.setRemark(remark.isEmpty() ? null : remark);
        g.setEnabled(enabled);
        return g;
    }

    // ---------------- 条目管理 ----------------

    public long entryCount(long id) {
        Long n = redis.opsForSet().size(GROUP_KEY_PREFIX + id);
        return n == null ? 0 : n;
    }

    /** 条目分页（SSCAN 无序遍历，管理界面够用；total=SCARD）。 */
    public Map<String, Object> pageEntries(long id, int page, int size) {
        mustGet(id);
        if (page < 1) page = 1;
        if (size < 1 || size > 200) size = 20;
        int need = page * size;
        List<String> items = new ArrayList<>(size);
        Cursor<String> cursor = null;
        try {
            cursor = redis.opsForSet().scan(GROUP_KEY_PREFIX + id,
                    ScanOptions.scanOptions().count(2000).build());
            int i = 0;
            while (cursor.hasNext() && items.size() < size) {
                String v = cursor.next();
                if (i++ >= need - size) items.add(v);
            }
        } finally {
            if (cursor != null) cursor.close();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", entryCount(id));
        out.put("page", page);
        out.put("size", size);
        out.put("items", items);
        return out;
    }

    /** 批量添加条目（文本，每行一个 IP/CIDR，# 开头忽略），返回实际新增数。 */
    @Transactional
    public long addEntries(long id, String text) {
        mustGet(id);
        List<String> entries = parseEntries(text);
        if (entries.isEmpty()) throw new BusinessException("没有可识别的 IP/CIDR 条目");
        long cur = entryCount(id);
        Set<String> uniq = new LinkedHashSet<>(entries);
        long added = addEntriesInternal(id, new ArrayList<>(uniq), cur);
        resync(id);  // 导入即同步生效通道（引擎 3s/60s 内热加载）
        return added;
    }

    @Transactional
    public void removeEntry(long id, String value) {
        mustGet(id);
        redis.opsForSet().remove(GROUP_KEY_PREFIX + id, value == null ? "" : value.trim());
        resync(id);
    }

    @Transactional
    public void clearEntries(long id) {
        mustGet(id);
        redis.delete(GROUP_KEY_PREFIX + id);
        resync(id);
    }

    private long addEntriesInternal(long id, List<String> entries, long currentCount) {
        long cur = currentCount;
        long added = 0;
        List<String> batch = new ArrayList<>(SADD_BATCH);
        for (String e : entries) {
            batch.add(e);
            if (batch.size() >= SADD_BATCH) {
                Long n = redis.opsForSet().add(GROUP_KEY_PREFIX + id, batch.toArray(new String[0]));
                added += n == null ? 0 : n;
                cur += n == null ? 0 : n;
                if (cur > MAX_ENTRIES) throw new BusinessException("单组条目数不能超过 " + MAX_ENTRIES);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) {
            Long n = redis.opsForSet().add(GROUP_KEY_PREFIX + id, batch.toArray(new String[0]));
            added += n == null ? 0 : n;
        }
        return added;
    }

    /** 解析多行文本为合法条目列表（去重、去注释、校验 IP/CIDR）。纯逻辑可单测配套 normalizeEntry。 */
    private List<String> parseEntries(String text) {
        if (text == null) throw new BusinessException("内容不能为空");
        if (text.length() > MAX_IMPORT_BYTES) throw new BusinessException("内容超过 8MB 上限");
        Set<String> uniq = new LinkedHashSet<>();
        for (String line : text.split("\r?\n")) {
            String e = normalizeEntry(line);
            if (e != null) uniq.add(e);
        }
        return new ArrayList<>(uniq);
    }

    // ---------------- 生效链路 ----------------

    /** 组保存/条目变化后重新同步生效通道。 */
    private void resync(long id) {
        IpGroup g = mapper.selectById(id);
        if (g != null) syncChannel(g);
    }

    private void syncChannel(IpGroup g) {
        if ("threat".equals(g.getType())) {
            syncIoc();
        } else {
            syncCustomToIpList(g);
        }
    }

    /** 自定义组并入黑/白名单：整组替换 source=group:{id} 的条目。 */
    private void syncCustomToIpList(IpGroup g) {
        boolean white = "allow".equals(g.getAction());
        String key = white ? IpListService.WHITE : IpListService.BLACK;
        List<String> entries = new ArrayList<>(members(g.getId()));
        String merged;
        try {
            merged = mergeIpListJson(redis.opsForValue().get(key), g.getId(),
                    g.getName(), Boolean.TRUE.equals(g.getEnabled()), entries, white);
        } catch (Exception e) {
            throw new BusinessException(500, "合并黑白名单失败：" + e.getMessage());
        }
        redis.opsForValue().set(key, merged);
        redis.opsForValue().increment(IPLIST_VERSION);
    }

    /** 组禁用/删除时从黑/白名单摘除。 */
    private void removeFromIpList(long groupId, boolean whiteChannel) {
        String key = whiteChannel ? IpListService.WHITE : IpListService.BLACK;
        String cur = redis.opsForValue().get(key);
        if (cur == null || !cur.contains("group:" + groupId)) return;
        try {
            String merged = mergeIpListJson(cur, groupId, "", false, List.of(), whiteChannel);
            redis.opsForValue().set(key, merged);
            redis.opsForValue().increment(IPLIST_VERSION);
        } catch (Exception e) {
            log.error("从名单摘除组 {} 失败", groupId, e);
        }
    }

    /** 重建 novawaf:ioc：保留非 ipgroup 类别行，全部启用中的威胁组条目重建追加，写 cksum。 */
    private void syncIoc() {
        List<GroupEntries> groups = new ArrayList<>();
        for (IpGroup g : mapper.selectByType("threat")) {
            if (!Boolean.TRUE.equals(g.getEnabled())) continue;
            groups.add(new GroupEntries(g.getId(), g.getName(), new ArrayList<>(members(g.getId()))));
        }
        String cur = redis.opsForValue().get(IOC_KEY);
        String blob = rebuildIocText(cur, groups);
        redis.opsForValue().set(IOC_KEY, blob);
        String cs = sha256Hex16(blob.getBytes(StandardCharsets.UTF_8));
        redis.opsForHash().put(META_KEY, "ioc_cksum", cs);
        redis.opsForHash().put(META_KEY, "ioc_updated", String.valueOf(System.currentTimeMillis() / 1000));
        log.info("novawaf:ioc 已重建: {} 组, {} 字符, cksum={}", groups.size(), blob.length(), cs);
    }

    private Set<String> members(long id) {
        Set<String> s = redis.opsForSet().members(GROUP_KEY_PREFIX + id);
        return s == null ? Set.of() : s;
    }

    private String summarize(long id, long cnt) {
        if (cnt <= 0) return "暂无条目";
        List<String> sample = new ArrayList<>(redis.opsForSet().randomMembers(GROUP_KEY_PREFIX + id, (int) Math.min(3, cnt)));
        return String.join("、", sample) + " 等，共 " + cnt + " 个";
    }

    // ---------------- 手动更新（异步任务） ----------------

    /** 触发异步更新：threat 组跑情报收集器；配置了源 URL 的组拉取自定义源。 */
    public Map<String, Object> startUpdate(long id) {
        IpGroup g = mustGet(id);
        boolean hasUrl = g.getSourceUrl() != null && !g.getSourceUrl().isBlank();
        if (!hasUrl && !"threat".equals(g.getType())) {
            throw new BusinessException("请先为该组配置源 URL（或改用导入）");
        }
        Map<String, Object> cur = task(id);
        if ("running".equals(cur.get("status"))
                && System.currentTimeMillis() - toLong(cur.get("time")) < TASK_STALE_MS) {
            throw new BusinessException("已有更新任务在执行，请稍候");
        }
        writeTask(id, "running", 0, null);
        doUpdateAsync(id);
        return task(id);
    }

    @Async("bizExecutor")
    public void doUpdateAsync(long id) {
        try {
            IpGroup g = mapper.selectById(id);
            if (g == null) { writeTask(id, "error", 0, "组不存在"); return; }
            boolean hasUrl = g.getSourceUrl() != null && !g.getSourceUrl().isBlank();
            if (hasUrl) {
                if (fetchScript == null || fetchScript.isBlank()) {
                    throw new BusinessException("拉取脚本未配置(nova.ipgroup.fetch-script)");
                }
                if (!Files.isRegularFile(Path.of(fetchScript))) {
                    throw new BusinessException("拉取脚本未安装：" + fetchScript);
                }
                // 脚本校验条目后直接写 Redis SET（继承 admin 进程的 NOVA_REDIS_* 环境变量）
                String out = SafeExec.run(List.of("python3", fetchScript,
                        "--url", g.getSourceUrl(), "--write-redis-key", GROUP_KEY_PREFIX + id),
                        fetchTimeoutMs, 262144);
                JsonNode n = om.readTree(extractJson(out));
                if (n.hasNonNull("written") && n.get("written").asLong() == 0) {
                    log.warn("组 {} 自定义源拉取到 0 条有效条目", id);
                }
            } else {
                if (threatScript == null || threatScript.isBlank()) {
                    throw new BusinessException("情报收集脚本未配置(nova.ipgroup.threat-script)");
                }
                if (!Files.isRegularFile(Path.of(threatScript))) {
                    throw new BusinessException("情报收集脚本未安装：" + threatScript);
                }
                Path tmp = Files.createTempFile("novawaf-threat-", ".txt");
                try {
                    SafeExec.run(List.of("python3", threatScript, "-o", tmp.toString()),
                            threatTimeoutMs, 262144);
                    String text = Files.readString(tmp, StandardCharsets.UTF_8);
                    List<String> entries = parseEntries(text);
                    if (entries.isEmpty()) throw new BusinessException("收集器未产出有效条目");
                    addEntriesInternal(id, entries, entryCount(id));
                } finally {
                    try { Files.deleteIfExists(tmp); } catch (Exception ignore) {}
                }
            }
            // 重新走生效链路
            resync(id);
            writeTask(id, "done", entryCount(id), null);
            log.info("IP 组 {} 更新完成", id);
        } catch (Exception e) {
            log.error("IP 组 {} 更新失败", id, e);
            writeTask(id, "error", 0, e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    public Map<String, Object> task(long id) {
        String raw = redis.opsForValue().get(TASK_KEY_PREFIX + id);
        if (raw == null || raw.isBlank()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", "idle");
            return m;
        }
        try {
            return om.readValue(raw, Map.class);
        } catch (Exception e) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", "idle");
            return m;
        }
    }

    private void writeTask(long id, String status, long count, String err) {
        try {
            ObjectNode n = om.createObjectNode();
            n.put("status", status);
            n.put("entryCount", count);
            n.put("time", System.currentTimeMillis());
            if (err != null) n.put("error", err.length() > 300 ? err.substring(0, 300) : err);
            redis.opsForValue().set(TASK_KEY_PREFIX + id, om.writeValueAsString(n));
        } catch (Exception e) {
            log.error("写任务状态失败: 组 {}", id, e);
        }
    }

    // ---------------- 纯逻辑（供单测，无 Spring 依赖） ----------------

    /** 单行条目校验与归一：合法返回原文（trim 后），非法/注释/空行返回 null。 */
    public static String normalizeEntry(String line) {
        if (line == null) return null;
        String s = line.trim();
        if (s.isEmpty() || s.startsWith("#")) return null;
        // parseCidr 同时覆盖纯 IP 与 a.b.c.d/n 两种形态
        return GeoService.parseCidr(s) == null ? null : s;
    }

    /**
     * 在黑白名单 JSON 数组文本中整组替换 source=group:{id} 的条目。
     * groupEnabled=false 时仅剔除不追加。条目字段形状与 IpListService.add 一致。
     */
    public static String mergeIpListJson(String current, long groupId, String groupName,
                                         boolean groupEnabled, List<String> entries,
                                         boolean whiteChannel) throws Exception {
        ObjectMapper m = new ObjectMapper();
        ArrayNode arr;
        if (current == null || current.isBlank()) {
            arr = m.createArrayNode();
        } else {
            JsonNode root = m.readTree(current);
            arr = root.isArray() ? (ArrayNode) root : m.createArrayNode();
        }
        String src = "group:" + groupId;
        ArrayNode kept = m.createArrayNode();
        for (JsonNode e : arr) {
            if (src.equals(e.path("source").asText(""))) continue;
            kept.add(e);
        }
        if (groupEnabled && entries != null) {
            long now = System.currentTimeMillis();
            int i = 1;
            for (String v : entries) {
                ObjectNode e = m.createObjectNode();
                e.put("id", "g" + groupId + "-" + (i++));
                e.put("ip", v);
                e.put("type", whiteChannel ? "white" : "black");
                e.put("note", groupName == null ? "" : groupName);
                e.put("source", src);
                e.put("enabled", true);
                e.put("hits", 0);
                e.put("createdAt", now);
                e.put("createdBy", "ipgroup");
                kept.add(e);
            }
        }
        return m.writeValueAsString(kept);
    }

    /**
     * 重建 novawaf:ioc 文本：保留注释行与非 ipgroup:* 类别行（ti_feed 等外部供给共存），
     * 按组重建 ip,{value},high,ipgroup:{id},{组名} 行（CIDR 值用 cidr 类型），跨组去重。
     */
    public static String rebuildIocText(String current, List<GroupEntries> groups) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        if (current != null && !current.isBlank()) {
            for (String line : current.split("\n")) {
                String s = line.trim();
                if (s.isEmpty()) continue;
                if (s.startsWith("#")) { out.add(s); continue; }
                String[] f = s.split(",", 5);
                if (f.length >= 4 && f[3].startsWith(IOC_CATEGORY_PREFIX)) continue;  // 组行全部重建
                out.add(s);
            }
        }
        if (groups != null) {
            for (GroupEntries g : groups) {
                String cat = IOC_CATEGORY_PREFIX + g.id();
                String name = (g.name() == null ? "" : g.name()).replace(",", " ").replace("\n", " ");
                for (String v : g.entries()) {
                    if (v == null || v.isBlank()) continue;
                    String vv = v.trim();
                    String k = (vv.contains("/") ? "cidr:" : "ip:") + vv;
                    if (!seen.add(k)) continue;
                    out.add((vv.contains("/") ? "cidr," : "ip,") + vv + ",high," + cat + "," + name);
                }
            }
        }
        StringBuilder sb = new StringBuilder(out.size() * 40);
        for (String l : out) sb.append(l).append('\n');
        return sb.toString();
    }

    /** 与 ti_feed.py / 引擎 loadDataLines 对齐的 cksum：sha256 hex 前 16 位。 */
    public static String sha256Hex16(byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(32);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("sha-256 不可用", e);
        }
    }

    private static String extractJson(String out) {
        if (out == null) throw new BusinessException(500, "脚本无输出");
        String t = out.trim();
        int l = t.indexOf('{');
        int r = t.lastIndexOf('}');
        if (l < 0 || r <= l) throw new BusinessException(500, "脚本输出中未找到 JSON");
        return t.substring(l, r + 1);
    }

    private static long toLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; }
    }
}
