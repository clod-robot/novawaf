package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * IP 黑白名单管理：黑名单=直接拦截，白名单=直接放行（引擎消费 novawaf:blacklist / novawaf:whitelist）。
 * 存储为 JSON 数组字符串，写操作 bump novawaf:iplist:version 触发引擎热加载 + 前端 SSE 刷新。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IpListService {
    private final StringRedisTemplate redis;
    private final GeoService geo;
    private final ObjectMapper om = new ObjectMapper();

    public static final String BLACK = "novawaf:blacklist";
    public static final String WHITE = "novawaf:whitelist";
    private static final String VERSION = "novawaf:iplist:version";

    private String key(String type) { return "white".equals(type) ? WHITE : BLACK; }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list(String type, String q) {
        String raw = redis.opsForValue().get(key(type));
        List<Map<String, Object>> all;
        try { all = (raw == null || raw.isBlank()) ? new ArrayList<>() : om.readValue(raw, List.class); }
        catch (Exception e) { all = new ArrayList<>(); }
        // 实时富集 geo（数据真实，不缓存脏值）
        for (Map<String, Object> e : all) {
            String ip = String.valueOf(e.get("ip"));
            e.put("geo", geo.label(ip));
        }
        if (q != null && !q.isBlank()) {
            String kw = q.toLowerCase();
            all.removeIf(e -> !String.valueOf(e.get("ip")).toLowerCase().contains(kw)
                    && !String.valueOf(e.getOrDefault("note", "")).toLowerCase().contains(kw)
                    && !String.valueOf(e.getOrDefault("geo", "")).toLowerCase().contains(kw));
        }
        all.sort((a, b) -> Long.compare(toLong(b.get("createdAt")), toLong(a.get("createdAt"))));
        return all;
    }

    public Map<String, Object> add(String type, String ip, String note, String source, String by) {
        if (ip == null || ip.isBlank()) throw new IllegalArgumentException("IP 不能为空");
        String norm = ip.trim();
        // 校验是合法 IP 或 CIDR
        if (GeoService.parseCidr(norm) == null && GeoService.ipToUint(norm) == 0)
            throw new IllegalArgumentException("IP/CIDR 格式不合法: " + norm);
        List<Map<String, Object>> all = list(type, null);
        all.removeIf(e -> norm.equalsIgnoreCase(String.valueOf(e.get("ip"))));  // 去重覆盖
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("id", String.valueOf(all.size() + 1));
        e.put("ip", norm);
        e.put("type", "white".equals(type) ? "white" : "black");
        e.put("note", note == null ? "" : note);
        e.put("source", source == null ? "manual" : source);
        e.put("enabled", true);
        e.put("hits", 0);
        e.put("createdAt", System.currentTimeMillis());
        e.put("createdBy", by == null ? "system" : by);
        e.put("geo", geo.label(norm));
        all.add(e);
        persist(type, all);
        return e;
    }

    public void remove(String type, String ip) {
        List<Map<String, Object>> all = list(type, null);
        all.removeIf(e -> ip.equalsIgnoreCase(String.valueOf(e.get("ip"))));
        persist(type, all);
    }

    public void toggle(String type, String ip) {
        List<Map<String, Object>> all = list(type, null);
        for (Map<String, Object> e : all)
            if (ip.equalsIgnoreCase(String.valueOf(e.get("ip")))) e.put("enabled", !Boolean.TRUE.equals(e.get("enabled")));
        persist(type, all);
    }

    public void clear(String type) { persist(type, new ArrayList<>()); }

    /** 引擎热加载 + SSE 推送信号 */
    public void bumpVersion() { redis.opsForValue().increment(VERSION); }

    public long version() {
        String v = redis.opsForValue().get(VERSION);
        try { return v == null ? 0 : Long.parseLong(v); } catch (NumberFormatException e) { return 0; }
    }

    /** 实时事件命中某 IP 时累加计数（用于列表“命中次数”实时刷新） */
    public void recordHit(String ip) {
        if (ip == null || ip.isBlank()) return;
        for (String type : new String[]{"black", "white"}) {
            List<Map<String, Object>> all = list(type, null);
            boolean changed = false;
            for (Map<String, Object> e : all) {
                if (ip.equalsIgnoreCase(String.valueOf(e.get("ip")))) {
                    e.put("hits", toLong(e.get("hits")) + 1);
                    e.put("lastHit", System.currentTimeMillis());
                    changed = true;
                }
            }
            if (changed) persist(type, all, false);  // 命中计数不必 bump 版本
        }
    }

    @SuppressWarnings("unchecked")
    private void persist(String type, List<Map<String, Object>> all) { persist(type, all, true); }
    private void persist(String type, List<Map<String, Object>> all, boolean bump) {
        try {
            // 落库时去掉动态 geo 字段（保持存储干净，展示时实时算）
            List<Map<String, Object>> copy = new ArrayList<>();
            for (Map<String, Object> e : all) { Map<String,Object> m = new LinkedHashMap<>(e); m.remove("geo"); copy.add(m); }
            redis.opsForValue().set(key(type), om.writeValueAsString(copy));
            if (bump) bumpVersion();
        } catch (Exception ex) { log.error("persist iplist failed", ex); }
    }

    private static long toLong(Object o) { if (o instanceof Number n) return n.longValue(); try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; } }
}
