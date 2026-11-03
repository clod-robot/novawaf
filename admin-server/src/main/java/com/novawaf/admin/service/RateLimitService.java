package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 端点分级限流阈值管理：policy 读写（novawaf:ratelimit:policy + version 触发引擎热加载）、
 * 采集分布与运行指标查询（引擎每分钟上报 novawaf:ratelimit:dist:* / metrics）。
 * 五类端点配额独立：static 只记账不限速；auth 按用户名+IP 双维度（引擎侧实现）。
 * 上线阶段 stage：0 monitor-only → 1 auth enforce → 2 +read/write/upload → 3 +封禁阶梯(仅到 L2)。
 */
@Service
@RequiredArgsConstructor
public class RateLimitService {
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    public static final String K_POLICY = "novawaf:ratelimit:policy";
    public static final String K_VERSION = "novawaf:ratelimit:version";
    public static final String K_METRICS = "novawaf:ratelimit:metrics";
    public static final String K_DIST_PREFIX = "novawaf:ratelimit:dist:";
    public static final List<String> CLASSES = List.of("read", "write", "upload", "auth", "static");

    /** 默认策略：与引擎 EndpointRateGuard::defaultPolicy 保持一致（「中」档，stage=0） */
    public Map<String, Object> defaultPolicy() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("stage", 0);
        p.put("banStrikes", 3);
        p.put("banSec", 300);
        Map<String, Object> cls = new LinkedHashMap<>();
        cls.put("read",   Map.of("qps", 20,  "burst", 40, "minQps", 20,  "enabled", true));
        cls.put("write",  Map.of("qps", 5,   "burst", 10, "minQps", 5,   "enabled", true));
        cls.put("upload", Map.of("qps", 2,   "burst", 4,  "minQps", 2,   "enabled", true));
        cls.put("auth",   Map.of("qps", 0.1, "burst", 3,  "minQps", 0.1, "enabled", true));
        cls.put("static", Map.of("qps", 0,   "burst", 0,  "minQps", 0,   "enabled", true));
        p.put("classes", cls);
        p.put("authPaths", List.of("/api/auth/login", "/api/auth/captcha", "/api/auth/mfa"));
        p.put("uploadPaths", List.of("/api/upload", "/api/files"));
        return p;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> get() {
        Map<String, Object> out = new LinkedHashMap<>();
        Object policy = parse(redis.opsForValue().get(K_POLICY));
        out.put("policy", policy instanceof Map ? policy : defaultPolicy());
        String ver = redis.opsForValue().get(K_VERSION);
        out.put("version", ver == null ? "0" : ver);
        out.put("metrics", parse(redis.opsForValue().get(K_METRICS)));
        Map<String, Object> dist = new LinkedHashMap<>();
        for (String c : CLASSES) dist.put(c, parse(redis.opsForValue().get(K_DIST_PREFIX + c)));
        out.put("dist", dist);
        return out;
    }

    private Object parse(String s) {
        if (s == null) return null;
        try { return om.readValue(s, Object.class); } catch (Exception e) { return s; }
    }

    /** 校验并下发：字段级合并当前配置，INCR 版本号触发引擎 3s 内热加载 */
    @SuppressWarnings("unchecked")
    public synchronized String update(Map<String, Object> req) {
        if (req == null) throw new BusinessException(400, "配置不能为空");
        long stage = asLong(req.get("stage"), 0);
        if (stage < 0 || stage > 3) throw new BusinessException(400, "stage 取值 0-3");
        long banStrikes = asLong(req.get("banStrikes"), 3);
        if (banStrikes < 1 || banStrikes > 100) throw new BusinessException(400, "banStrikes 取值 1-100");
        long banSec = asLong(req.get("banSec"), 300);
        if (banSec < 10 || banSec > 86400) throw new BusinessException(400, "banSec 取值 10-86400");

        Object curObj = parse(redis.opsForValue().get(K_POLICY));
        Map<String, Object> cfg = new LinkedHashMap<>(
                curObj instanceof Map ? (Map<String, Object>) curObj : defaultPolicy());
        cfg.put("stage", stage);
        cfg.put("banStrikes", banStrikes);
        cfg.put("banSec", banSec);

        Object clsReq = req.get("classes");
        Map<String, Object> clsCur = cfg.get("classes") instanceof Map
                ? new LinkedHashMap<>((Map<String, Object>) cfg.get("classes")) : new LinkedHashMap<>();
        if (clsReq instanceof Map) {
            Map<String, Object> cr = (Map<String, Object>) clsReq;
            for (String c : CLASSES) {
                if (!(cr.get(c) instanceof Map)) continue;
                Map<String, Object> in = (Map<String, Object>) cr.get(c);
                Map<String, Object> merged = new LinkedHashMap<>(
                        clsCur.get(c) instanceof Map ? (Map<String, Object>) clsCur.get(c) : Map.of());
                double qps = asDouble(in.get("qps"), asDouble(merged.get("qps"), 0));
                long burst = asLong(in.get("burst"), asLong(merged.get("burst"), 0));
                double minQps = asDouble(in.get("minQps"), asDouble(merged.get("minQps"), 0));
                if (qps < 0 || qps > 100000) throw new BusinessException(400, c + ".qps 取值 0-100000");
                if (burst < 0 || burst > 1000000) throw new BusinessException(400, c + ".burst 取值 0-1000000");
                if (!"static".equals(c) && in.containsKey("enabled") && Boolean.TRUE.equals(in.get("enabled")) && qps <= 0)
                    throw new BusinessException(400, c + " 启用时 qps 必须 > 0");
                merged.put("qps", qps);
                merged.put("burst", burst);
                merged.put("minQps", minQps);
                merged.put("enabled", !in.containsKey("enabled") || Boolean.TRUE.equals(in.get("enabled")));
                clsCur.put(c, merged);
            }
            cfg.put("classes", clsCur);
        }
        if (req.get("authPaths") instanceof List) cfg.put("authPaths", strList(req.get("authPaths"), 64));
        if (req.get("uploadPaths") instanceof List) cfg.put("uploadPaths", strList(req.get("uploadPaths"), 64));
        cfg.put("updatedAt", System.currentTimeMillis() / 1000);

        try {
            redis.opsForValue().set(K_POLICY, om.writeValueAsString(cfg));
            redis.opsForValue().increment(K_VERSION);
        } catch (Exception e) {
            throw new BusinessException(500, "下发限流策略失败: " + e.getMessage());
        }
        String[] stageName = {"monitor-only 采集", "auth 限流", "read/write/upload 限流", "封禁阶梯(L2)"};
        return "策略已下发，当前阶段 " + stage + "（" + stageName[(int) stage] + "），引擎 3 秒内热生效";
    }

    /** 某类别的分钟级分布历史（默认最近 240 条 = 4 小时） */
    public List<Object> distHistory(String cls, int limit) {
        if (!CLASSES.contains(cls)) throw new BusinessException(400, "非法类别: " + cls);
        int n = Math.min(Math.max(limit, 1), 1440);
        List<String> raw = redis.opsForList().range(K_DIST_PREFIX + cls + ":hist", -n, -1);
        List<Object> out = new ArrayList<>();
        if (raw != null) for (String s : raw) out.add(parse(s));
        return out;
    }

    private static long asLong(Object v, long dft) {
        if (v == null) return dft;
        try { return Long.parseLong(String.valueOf(v)); } catch (Exception e) { return dft; }
    }
    private static double asDouble(Object v, double dft) {
        if (v == null) return dft;
        try { return Double.parseDouble(String.valueOf(v)); } catch (Exception e) { return dft; }
    }
    private static List<String> strList(Object v, int max) {
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            String s = String.valueOf(o).trim();
            if (s.startsWith("/") && s.length() <= 128 && !s.contains("*")) out.add(s);
            if (out.size() >= max) break;
        }
        return out;
    }
}
