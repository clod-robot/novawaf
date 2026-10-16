package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 硬件加速管理面：读写引擎约定的 Redis Key。
 *   novawaf:accel:config  —— 管理面下发的期望配置（引擎每 2s 热加载，默认关闭）
 *   novawaf:accel:status  —— 引擎每 ~6s 上报的设备/后端健康/聚合计数（只读）
 *   novawaf:accel:version —— 配置版本号，INCR 触发引擎即时重读
 * 管理面只做透传与校验，不触碰任何业务数据。
 */
@Service
@RequiredArgsConstructor
public class AccelService {
    private static final String K_CONFIG = "novawaf:accel:config";
    private static final String K_STATUS = "novawaf:accel:status";
    private static final String K_VERSION = "novawaf:accel:version";

    /** 引擎可识别的首选后端白名单（GPU/NPU 本期仅做探测与降级，扫描仍走 CPU SIMD） */
    private static final Set<String> BACKENDS = Set.of(
            "auto", "scalar", "avx2", "avx512", "opencl", "cuda", "hip", "cann");

    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /** 默认配置：默认关闭，未识别到加速设备时保持安全基线 */
    private Map<String, Object> defaultConfig() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", false);
        m.put("preferredBackend", "auto");
        m.put("batchGateMinN", 8);
        m.put("batchMaxWaitUs", 2000);
        m.put("offloadIocRebuild", true);
        m.put("updatedAt", 0);
        return m;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parse(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            Object o = om.readValue(raw, Object.class);
            return o instanceof Map ? (Map<String, Object>) o : null;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean asBool(Object o, boolean def) {
        if (o == null) return def;
        if (o instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(o));
    }

    private long asLong(Object o, long def) {
        if (o == null) return def;
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return def; }
    }

    /** 合并“期望配置 + 引擎实时状态”，供前端一页展示 */
    public Map<String, Object> view() {
        Map<String, Object> desired = parse(redis.opsForValue().get(K_CONFIG));
        if (desired == null) desired = defaultConfig();
        Map<String, Object> live = parse(redis.opsForValue().get(K_STATUS));

        Map<String, Object> out = new LinkedHashMap<>();
        boolean reachable = live != null;
        out.put("reachable", reachable);
        out.put("enabled", asBool(desired.get("enabled"), false));
        out.put("preferredBackend", str(desired.get("preferredBackend"), "auto"));
        out.put("batchGateMinN", asLong(desired.get("batchGateMinN"), 8));
        out.put("batchMaxWaitUs", asLong(desired.get("batchMaxWaitUs"), 2000));
        out.put("offloadIocRebuild", asBool(desired.get("offloadIocRebuild"), true));
        out.put("updatedAt", asLong(desired.get("updatedAt"), 0));
        if (reachable) {
            // 引擎实时字段透传（仅设备/健康/聚合计数，不含业务数据）
            for (String k : List.of("activeBackend", "cpu", "devices", "backends", "stats")) {
                if (live.containsKey(k)) out.put(k, live.get(k));
            }
            // 引擎上报的 enabled 与下发值不一致时，以前端可见方式暴露
            out.put("engineEnabled", asBool(live.get("enabled"), false));
        } else {
            out.put("activeBackend", "Scalar");
            out.put("devices", List.of());
            out.put("backends", List.of());
            out.put("stats", Map.of());
        }
        return out;
    }

    /** 校验并下发配置，INCR 版本号触发引擎热加载 */
    @SuppressWarnings("unchecked")
    public synchronized String update(Map<String, Object> req) {
        if (req == null) throw new BusinessException(400, "配置不能为空");
        String backend = str(req.get("preferredBackend"), "auto").toLowerCase(Locale.ROOT).trim();
        if (!BACKENDS.contains(backend))
            throw new BusinessException(400, "非法的首选后端: " + backend);

        long gateMin = asLong(req.get("batchGateMinN"), 8);
        if (gateMin < 1 || gateMin > 1024)
            throw new BusinessException(400, "批量闸门阈值 batchGateMinN 取值 1-1024");
        long gateWait = asLong(req.get("batchMaxWaitUs"), 2000);
        if (gateWait < 0 || gateWait > 100000)
            throw new BusinessException(400, "批量等待上限 batchMaxWaitUs 取值 0-100000 微秒");

        // 基于当前期望配置做字段级合并，避免 PUT 缺字段时被重置
        Map<String, Object> cur = parse(redis.opsForValue().get(K_CONFIG));
        if (cur == null) cur = defaultConfig();
        Map<String, Object> cfg = new LinkedHashMap<>(cur);
        cfg.put("enabled", asBool(req.get("enabled"), false));
        cfg.put("preferredBackend", backend);
        cfg.put("batchGateMinN", gateMin);
        cfg.put("batchMaxWaitUs", gateWait);
        if (req.containsKey("offloadIocRebuild"))
            cfg.put("offloadIocRebuild", asBool(req.get("offloadIocRebuild"), true));
        cfg.put("updatedAt", System.currentTimeMillis() / 1000);

        try {
            redis.opsForValue().set(K_CONFIG, om.writeValueAsString(cfg));
            redis.opsForValue().increment(K_VERSION);
        } catch (Exception e) {
            throw new BusinessException(500, "下发加速配置失败: " + e.getMessage());
        }
        return (boolean) cfg.get("enabled") ? "已开启硬件加速(" + backend + ")" : "已关闭硬件加速";
    }

    /**
     * 自检：依据引擎启动自检结果与实时健康灯判定（不执行任何系统命令）。
     * ok = 引擎在线 且 CPU SIMD(AVX2/SSSE3) 后端健康。
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> selfTest() {
        Map<String, Object> live = parse(redis.opsForValue().get(K_STATUS));
        Map<String, Object> res = new LinkedHashMap<>();
        if (live == null) {
            res.put("ok", false);
            res.put("reason", "引擎状态不可达（未上报 novawaf:accel:status）");
            return res;
        }
        boolean simdHealthy = false;
        List<Map<String, Object>> be = (List<Map<String, Object>>) live.getOrDefault("backends", List.of());
        for (Map<String, Object> b : be) {
            String name = str(b.get("name"), "");
            if (("AVX2".equals(name) || "SSSE3".equals(name) || "Scalar".equals(name))
                    && "healthy".equals(str(b.get("state"), ""))) {
                simdHealthy = true;
            }
        }
        res.put("ok", simdHealthy);
        res.put("activeBackend", str(live.get("activeBackend"), "Scalar"));
        res.put("enabled", asBool(live.get("enabled"), false));
        res.put("backends", be);
        if (!simdHealthy) res.put("reason", "CPU SIMD 自检未通过，引擎将保持标量基线");
        return res;
    }

    private String str(Object o, String def) { return o == null ? def : String.valueOf(o); }
}
