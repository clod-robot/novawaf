package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 网页防篡改管理（与引擎 TamperCache 对应的 Redis 通道）:
 *   novawaf:tamper:config  JSON 配置(enabled/ttl/maxBody/maxPages/prefixes)
 *   novawaf:tamper:cfgver  配置版本号(INCR, 引擎 5s 脏检查热加载)
 *   novawaf:tamper:index   JSON 数组 [{id,host,path,ts,size}]
 *   novawaf:tamper:page:<id>  base64 基线响应(引擎写)
 *   novawaf:tamper:purge   list, 元素=页面 id 或 "all"(引擎消费后重学)
 *   novawaf:tamper:stats   JSON 统计(引擎写)
 */
@Service
@RequiredArgsConstructor
public class TamperService {
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    static final String K_CONFIG = "novawaf:tamper:config";
    static final String K_CFGVER = "novawaf:tamper:cfgver";
    static final String K_INDEX = "novawaf:tamper:index";
    static final String K_PAGE_PREFIX = "novawaf:tamper:page:";
    static final String K_PURGE = "novawaf:tamper:purge";
    static final String K_STATS = "novawaf:tamper:stats";

    private static final long MAX_TTL = 86400;          // 1 天
    private static final long MAX_BODY = 4 * 1024 * 1024; // 4MB
    private static final long MAX_PAGES = 4096;

    // ---------------- 查询 ----------------

    /** 基线页面索引 */
    public List<Object> pages() {
        Object obj = parse(redis.opsForValue().get(K_INDEX));
        return obj instanceof List ? (List<Object>) obj : new ArrayList<>();
    }

    /** 当前生效配置(无下发时返回默认) */
    @SuppressWarnings("unchecked")
    public Map<String, Object> config() {
        Object obj = parse(redis.opsForValue().get(K_CONFIG));
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("enabled", false);
        cfg.put("ttl", 3600);
        cfg.put("maxBody", 256 * 1024);
        cfg.put("maxPages", 256);
        cfg.put("prefixes", new ArrayList<String>());
        if (obj instanceof Map) {
            cfg.putAll((Map<String, Object>) obj);
        }
        String ver = redis.opsForValue().get(K_CFGVER);
        cfg.put("cfgver", ver == null ? 0 : Long.parseLong(ver));
        return cfg;
    }

    public Object stats() {
        Object obj = parse(redis.opsForValue().get(K_STATS));
        return obj == null ? Map.of() : obj;
    }

    // ---------------- 配置下发 ----------------

    /** 校验并落盘配置, INCR cfgver 触发引擎 5s 内热加载 */
    public synchronized Map<String, Object> saveConfig(Map<String, Object> req) {
        Map<String, Object> cur = config();
        Map<String, Object> out = new LinkedHashMap<>();

        out.put("enabled", req.containsKey("enabled")
                ? Boolean.TRUE.equals(req.get("enabled"))
                : Boolean.TRUE.equals(cur.get("enabled")));

        out.put("ttl", clampLong(req.get("ttl"), toLong(cur.get("ttl")), 0, MAX_TTL, "ttl"));
        out.put("maxBody", clampLong(req.get("maxBody"), toLong(cur.get("maxBody")), 1024, MAX_BODY, "maxBody"));
        out.put("maxPages", clampLong(req.get("maxPages"), toLong(cur.get("maxPages")), 1, MAX_PAGES, "maxPages"));

        List<String> prefixes = new ArrayList<>();
        Object po = req.containsKey("prefixes") ? req.get("prefixes") : cur.get("prefixes");
        if (po instanceof List) {
            for (Object o : (List<Object>) po) {
                String p = String.valueOf(o).trim();
                if (p.isEmpty()) continue;
                if (prefixes.size() >= 64) throw new BusinessException(400, "前缀最多 64 条");
                if (p.length() > 128) throw new BusinessException(400, "前缀过长(>128): " + p);
                if (!p.startsWith("/")) throw new BusinessException(400, "前缀必须以 / 开头: " + p);
                if (p.contains("..") || p.matches(".*\\s.*"))
                    throw new BusinessException(400, "前缀含非法字符: " + p);
                prefixes.add(p);
            }
        } else if (po != null && !(po instanceof List)) {
            throw new BusinessException(400, "prefixes 必须是数组");
        }
        out.put("prefixes", prefixes);

        try {
            redis.opsForValue().set(K_CONFIG, om.writeValueAsString(out));
        } catch (BusinessException be) {
            throw be;
        } catch (Exception e) {
            throw new BusinessException(500, "写入防篡改配置失败: " + e.getMessage());
        }
        redis.opsForValue().increment(K_CFGVER);
        out.put("cfgver", toLong(redis.opsForValue().get(K_CFGVER)));
        return out;
    }

    // ---------------- 基线清除(重学) ----------------

    /**
     * purge: id="all" 清空全部基线; 否则按 16 位 hex 页面 id 清除。
     * 入队 novawaf:tamper:purge 供引擎消费重学; 指定 id 时同步删基线与索引(管理端立即生效)。
     */
    public synchronized Map<String, Object> purge(String id) {
        String target = id == null ? "" : id.trim();
        if (target.isEmpty()) throw new BusinessException(400, "id 不能为空(all 或页面 id)");
        if (!"all".equals(target)) {
            if (!target.matches("[0-9a-f]{16}"))
                throw new BusinessException(400, "页面 id 必须是 16 位小写 hex(见页面列表)");
        }
        redis.opsForList().rightPush(K_PURGE, target);

        long removed = -1; // -1 表示全部
        if (!"all".equals(target)) {
            redis.delete(K_PAGE_PREFIX + target);
            removed = removeFromIndex(target) ? 1 : 0;
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("purged", target);
        r.put("indexRemoved", removed);
        return r;
    }

    /** 从索引数组中剔除指定 id, 返回是否剔除过 */
    @SuppressWarnings("unchecked")
    private boolean removeFromIndex(String id) {
        Object obj = parse(redis.opsForValue().get(K_INDEX));
        if (!(obj instanceof List)) return false;
        boolean hit = false;
        List<Object> keep = new ArrayList<>();
        for (Object o : (List<Object>) obj) {
            if (o instanceof Map && id.equals(String.valueOf(((Map<String, Object>) o).get("id")))) {
                hit = true;
                continue;
            }
            keep.add(o);
        }
        if (hit) {
            try {
                redis.opsForValue().set(K_INDEX, om.writeValueAsString(keep));
            } catch (Exception e) {
                throw new BusinessException(500, "更新页面索引失败: " + e.getMessage());
            }
        }
        return hit;
    }

    // ---------------- 工具 ----------------

    private Object parse(String s) {
        if (s == null) return null;
        try { return om.readValue(s, Object.class); }
        catch (Exception e) { return s; }
    }

    private static long toLong(Object o) {
        if (o == null) return 0;
        if (o instanceof Number) return ((Number) o).longValue();
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; }
    }

    /** 数值边界校验: null 用 current; 越界直接报错(避免静默截断掩盖配置错误) */
    private static long clampLong(Object v, long current, long min, long max, String name) {
        if (v == null) return current;
        long n = toLong(v);
        if (n < min || n > max)
            throw new BusinessException(400, name + " 超出范围 [" + min + "," + max + "]: " + n);
        return n;
    }
}
