package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.GeoPolicy;
import com.novawaf.admin.mapper.GeoPolicyMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * GeoIP 地域访问策略：
 * - 国家分布统计：解析 novawaf:geoip 聚合 CC → CIDR 数（cksum 缓存）；
 * - 策略保存：MySQL 单行 upsert + 发布 novawaf:geo:policy + INCR novawaf:geo:policy:version，
 *   引擎 main.cpp 每 3s 检查版本热加载（GeoFilter whitelist=仅允许 / blacklist=封禁）。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeoPolicyService {

    public static final String POLICY_KEY = "novawaf:geo:policy";
    public static final String POLICY_VERSION = "novawaf:geo:policy:version";
    private static final int MAX_COUNTRIES = 64;
    private static final Pattern CC_RE = Pattern.compile("^[A-Z]{2}$");

    private final GeoPolicyMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    private record StatsSnap(int hash, List<Map<String, Object>> countries, long totalRanges) {}
    private final AtomicReference<StatsSnap> statsRef =
            new AtomicReference<>(new StatsSnap(-1, List.of(), 0));

    public Map<String, Object> getPolicy() {
        GeoPolicy p = mapper.selectSingleton();
        Map<String, Object> m = new LinkedHashMap<>();
        if (p == null) {
            m.put("mode", "off");
            m.put("countries", List.of());
            return m;
        }
        String mode = Boolean.TRUE.equals(p.getEnabled()) ? p.getMode() : "off";
        m.put("mode", mode);
        m.put("storedMode", p.getMode());
        m.put("countries", parseCountries(p.getCountries()));
        m.put("updateTime", p.getUpdateTime() == null ? null : p.getUpdateTime().getTime());
        return m;
    }

    /** mode: off=关闭 / whitelist=仅允许选中国家 / blacklist=封禁选中国家。 */
    @Transactional
    public Map<String, Object> savePolicy(String mode, List<String> countries) {
        String m = mode == null ? "" : mode.trim().toLowerCase();
        if (!m.equals("off") && !m.equals("whitelist") && !m.equals("blacklist")) {
            throw new BusinessException("策略模式只能是 off / whitelist / blacklist");
        }
        List<String> ccs = normalizeCountries(countries);
        boolean enabled = !m.equals("off");

        GeoPolicy row = new GeoPolicy();
        row.setId(1L);
        row.setEnabled(enabled);
        row.setMode(m.equals("off") ? lastStoredModeOrDefault() : m);
        row.setCountries(toJson(ccs));

        if (mapper.selectSingleton() == null) mapper.insertSingleton(row);
        else mapper.updateSingleton(row);

        publish(row.getMode(), enabled, ccs);
        return getPolicy();
    }

    /** 发布到 Redis：引擎读取 {"enabled":bool,"mode":...,"countries":[...]}，版本号触发 3s 内热加载。 */
    private void publish(String mode, boolean enabled, List<String> ccs) {
        try {
            ObjectNode n = om.createObjectNode();
            n.put("enabled", enabled);
            n.put("mode", mode);
            ArrayNode arr = om.createArrayNode();
            for (String cc : ccs) arr.add(cc);
            n.set("countries", arr);
            redis.opsForValue().set(POLICY_KEY, om.writeValueAsString(n));
            redis.opsForValue().increment(POLICY_VERSION);
            log.info("Geo 地域策略已发布: enabled={}, mode={}, countries={}", enabled, mode, ccs.size());
        } catch (Exception e) {
            throw new BusinessException(500, "策略已保存但发布到 Redis 失败：" + e.getMessage());
        }
    }

    private String lastStoredModeOrDefault() {
        GeoPolicy old = mapper.selectSingleton();
        String m = old == null || old.getMode() == null ? "whitelist" : old.getMode();
        return m.equals("whitelist") ? "whitelist" : "blacklist";
    }

    /** 国家码归一：大写两位、去重保序、上限 64。 */
    public static List<String> normalizeCountries(List<String> countries) {
        if (countries == null || countries.isEmpty()) return List.of();
        Set<String> uniq = new LinkedHashSet<>();
        for (String c : countries) {
            if (c == null) continue;
            String cc = c.trim().toUpperCase();
            if (cc.isEmpty()) continue;
            if (!CC_RE.matcher(cc).matches()) throw new BusinessException("国家码必须是两位大写字母：" + c);
            uniq.add(cc);
            if (uniq.size() > MAX_COUNTRIES) throw new BusinessException("选中国家不能超过 " + MAX_COUNTRIES);
        }
        return new ArrayList<>(uniq);
    }

    private String toJson(List<String> ccs) {
        try {
            ArrayNode arr = om.createArrayNode();
            for (String cc : ccs) arr.add(cc);
            return om.writeValueAsString(arr);
        } catch (Exception e) {
            throw new BusinessException(500, "国家列表序列化失败");
        }
    }

    private List<String> parseCountries(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            JsonNode n = om.readTree(json);
            List<String> out = new ArrayList<>();
            if (n.isArray()) for (JsonNode x : n) if (x.isTextual()) out.add(x.asText());
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** GeoIP 国家分布：[{cc,name,count}...] 按网段数降序；数据未变时走缓存。 */
    public Map<String, Object> countryStats() {
        String raw;
        try {
            raw = redis.opsForValue().get("novawaf:geoip");
        } catch (Exception e) {
            raw = null;
        }
        int hash = raw == null ? 0 : raw.hashCode();
        StatsSnap snap = statsRef.get();
        if (hash != snap.hash()) snap = rebuild(raw, hash);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("totalRanges", snap.totalRanges());
        out.put("countries", snap.countries());
        return out;
    }

    private synchronized StatsSnap rebuild(String raw, int hash) {
        StatsSnap snap = statsRef.get();
        if (hash == snap.hash()) return snap;  // 并发下已被其它线程重建
        Map<String, Long> byCc = new LinkedHashMap<>();
        long total = 0;
        if (raw != null) {
            for (String line : raw.split("\n")) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) continue;
                String[] f = s.split(",");
                if (f.length < 2) continue;
                String cc = f[1].trim().toUpperCase();
                if (!CC_RE.matcher(cc).matches()) continue;
                byCc.merge(cc, 1L, Long::sum);
                total++;
            }
        }
        List<Map<String, Object>> countries = new ArrayList<>(byCc.size());
        for (Map.Entry<String, Long> e : byCc.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("cc", e.getKey());
            String zh = GeoService.ccZh(e.getKey());
            m.put("name", zh != null ? zh : e.getKey());
            m.put("count", e.getValue());
            countries.add(m);
        }
        countries.sort(Comparator.comparingLong((Map<String, Object> m) -> toLong(m.get("count"))).reversed());
        StatsSnap next = new StatsSnap(hash, countries, total);
        statsRef.set(next);
        log.info("GeoPolicy 国家统计重建: {} 个国家, {} 个网段", countries.size(), total);
        return next;
    }

    private static long toLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; }
    }
}
