package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

/**
 * 攻击溯源分析:
 *   - summary: 攻击源 IP 排行——count 读引擎按天分桶的真实计数(novawaf:trace:cnt:YYYYMMDD,
 *     HINCRBY 持久累计, 不封顶/不被洪水挤占/引擎重启不丢), 画像(categories/时间/动作)从
 *     novawaf:events 近期明细窗口提取作补充; 跨天自然开新桶(每日重置), 桶保留 48h。
 *   - ipDetail: 单 IP 攻击链时间线 + 类型分布 + 行为画像(明细窗口样本) + 真实累计数。
 * 攻击链阶段(kill chain 简化): recon(侦察) → exploit(渗透) → intrusion(入侵) → impact(破坏)
 * 风险分 = 频率分(真实count) + severity 加权(样本) + 类别多样性 3/类, 上限 100。
 */
@Service
@RequiredArgsConstructor
public class TraceService {
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    static final String K_EVENTS = "novawaf:events";
    static final String K_TRACE_CNT = "novawaf:trace:cnt:";
    static final String K_EV_IP = "novawaf:ev:";   // 引擎按 IP 保留的攻击明细分桶
    static final String K_TRACE_CAT = "novawaf:trace:cat:";
    private static final ZoneId ZONE = ZoneId.of("Asia/Shanghai"); // 与引擎 localtime 桶一致
    private static final int MAX_SCAN = 1000;    // 与引擎 eventsCap 对齐
    private static final int MAX_TIMELINE = 200; // 单 IP 时间线上限(防大响应)

    // ---------------- 攻击源 IP 排行 ----------------

    public Map<String, Object> summary(int limit) {
        if (limit <= 0) limit = 50;
        if (limit > 200) limit = 200;
        // 1) 分桶真实计数(今天+昨天合并)
        Map<String, Long> realByIp = new HashMap<>();
        Map<String, Long> realByCat = new HashMap<>();
        readBuckets(realByIp, realByCat);
        // 2) 明细窗口样本(画像补充)
        Map<String, Agg> byIp = aggregate(readEvents());
        // 3) 合并输出: 真实计数为主, 样本画像为辅
        Set<String> ips = new LinkedHashSet<>(realByIp.keySet());
        ips.addAll(byIp.keySet());
        List<Agg> rows = new ArrayList<>();
        for (String ip : ips) {
            Agg a = byIp.getOrDefault(ip, new Agg(ip));
            long real = realByIp.getOrDefault(ip, 0L);
            a.realCount = Math.max(a.count, real); // 样本数与桶计数取大(桶可能滞后一个 flush 周期)
            rows.add(a);
        }
        rows.sort((a, b) -> {
            int c = Long.compare(b.realCount, a.realCount);
            return c != 0 ? c : Integer.compare(b.riskScore(), a.riskScore());
        });
        List<Map<String, Object>> out = new ArrayList<>();
        for (Agg a : rows) {
            if (out.size() >= limit) break;
            Map<String, Object> m = a.toSummary();
            m.put("count", a.realCount);            // 展示真实累计
            m.put("riskScore", a.riskScore(a.realCount));
            m.put("level", a.level(a.realCount));
            out.add(m);
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("date", LocalDate.now(ZONE).toString());
        resp.put("scope", "今日累计(跨天自动重置, 分桶保留48h); 类型画像来自近期明细样本");
        resp.put("rows", out);
        return resp;
    }

    // ---------------- 单 IP 攻击链详情 ----------------

    public Map<String, Object> ipDetail(String ip) {
        if (ip == null || !ip.matches("[0-9a-fA-F.:]{2,45}"))
            throw new BusinessException(400, "非法 IP 格式");
        // 优先读引擎按 IP 分桶保留的明细（novawaf:ev:{ip}，每 IP 最近 200 条、TTL 24h），
        // 避免全局环形缓冲被高频流量冲刷后低频 IP 明细完全缺失
        List<Map<String, Object>> mine = readIpBucket(ip);
        if (mine.isEmpty()) {
            List<Map<String, Object>> events = readEvents();
            for (Map<String, Object> e : events) {
                if (ip.equals(str(e.get("ip")))) mine.add(e);
            }
        }
        Map<String, Long> realByIp = new HashMap<>();
        Map<String, Long> realByCat = new HashMap<>();
        readBuckets(realByIp, realByCat);
        long real = realByIp.getOrDefault(ip, 0L);
        if (mine.isEmpty() && real == 0)
            throw new BusinessException(404, "未观察到该 IP 的攻击事件: " + ip);
        // 时间线按 ts 升序
        mine.sort(Comparator.comparingLong(e -> toLong(e.get("ts"))));

        Agg agg = new Agg(ip);
        Map<String, Long> rules = new LinkedHashMap<>();
        for (Map<String, Object> e : mine) {
            agg.add(e);
            String rid = str(e.get("ruleId"));
            if (!rid.isEmpty()) rules.merge(rid, 1L, Long::sum);
        }
        long shown = Math.max(agg.count, real);

        // 阶段迁移流(时间线上各阶段首次出现顺序)
        List<String> stageFlow = new ArrayList<>();
        for (Map<String, Object> e : mine) {
            String s = stageOf(str(e.get("category")));
            if (!stageFlow.contains(s)) stageFlow.add(s);
        }

        List<Map<String, Object>> timeline = new ArrayList<>();
        int from = Math.max(0, mine.size() - MAX_TIMELINE);
        for (int i = from; i < mine.size(); i++) {
            Map<String, Object> e = mine.get(i);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ts", toLong(e.get("ts")));
            row.put("action", str(e.get("action")));
            row.put("category", str(e.get("category")));
            row.put("ruleId", str(e.get("ruleId")));
            row.put("matched", str(e.get("matched")));
            row.put("severity", str(e.get("severity")));
            row.put("stage", stageOf(str(e.get("category"))));
            timeline.add(row);
        }

        Map<String, Object> out = agg.toSummary();
        out.put("count", shown);
        out.put("realCount", real);
        out.put("sampleCount", agg.count);
        out.put("riskScore", agg.riskScore(shown));
        out.put("level", agg.level(shown));
        out.put("topRules", topN(rules, 5));
        out.put("stageFlow", stageFlow);
        out.put("timeline", timeline);
        out.put("timelineTotal", mine.size());
        return out;
    }

    // ---------------- 分桶真实计数(今天+昨天) ----------------

    private void readBuckets(Map<String, Long> byIp, Map<String, Long> byCat) {
        LocalDate today = LocalDate.now(ZONE);
        for (LocalDate d : new LocalDate[]{today, today.minusDays(1)}) {
            String day = d.toString().replace("-", "");
            Map<Object, Object> cnt = redis.opsForHash().entries(K_TRACE_CNT + day);
            for (Map.Entry<Object, Object> en : cnt.entrySet())
                byIp.merge(String.valueOf(en.getKey()), toLong(en.getValue()), Long::sum);
            Map<Object, Object> cat = redis.opsForHash().entries(K_TRACE_CAT + day);
            for (Map.Entry<Object, Object> en : cat.entrySet())
                byCat.merge(String.valueOf(en.getKey()), toLong(en.getValue()), Long::sum);
        }
    }

    // ---------------- 聚合内核 ----------------

    // 读取引擎按 IP 分桶保留的攻击明细（novawaf:ev:{ip}）
    private List<Map<String, Object>> readIpBucket(String ip) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> raw = redis.opsForList().range(K_EV_IP + ip, 0, -1);
        if (raw == null) return out;
        for (String s : raw) {
            try {
                Object o = om.readValue(s, Object.class);
                if (o instanceof Map) out.add((Map<String, Object>) o);
            } catch (Exception ignore) { /* 跳过坏行 */ }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> readEvents() {
        List<String> raw = redis.opsForList().range(K_EVENTS, 0, -1);
        List<Map<String, Object>> out = new ArrayList<>();
        if (raw == null) return out;
        int n = 0;
        for (String s : raw) {
            if (++n > MAX_SCAN) break;
            try {
                Object o = om.readValue(s, Object.class);
                if (o instanceof Map) out.add((Map<String, Object>) o);
            } catch (Exception ignore) { /* 跳过坏行 */ }
        }
        return out;
    }

    private Map<String, Agg> aggregate(List<Map<String, Object>> events) {
        Map<String, Agg> byIp = new HashMap<>();
        for (Map<String, Object> e : events) {
            String ip = str(e.get("ip"));
            if (ip.isEmpty()) continue;
            byIp.computeIfAbsent(ip, Agg::new).add(e);
        }
        return byIp;
    }

    /** 单 IP 聚合器 */
    static final class Agg {
        final String ip;
        long count = 0;
        long realCount = 0;   // 分桶真实累计(与窗口无关)
        long firstSeen = Long.MAX_VALUE;
        long lastSeen = 0;
        long weighted = 0;
        final Set<String> categories = new LinkedHashSet<>();
        final Set<String> stages = new LinkedHashSet<>();
        final Map<String, Long> actions = new LinkedHashMap<>();

        Agg(String ip) { this.ip = ip; }

        void add(Map<String, Object> e) {
            ++count;
            long ts = toLong(e.get("ts"));
            if (ts > 0) {
                firstSeen = Math.min(firstSeen, ts);
                lastSeen = Math.max(lastSeen, ts);
            }
            String cat = str(e.get("category"));
            if (!cat.isEmpty()) {
                categories.add(cat);
                stages.add(stageOf(cat));
            }
            weighted += severityWeight(str(e.get("severity")));
            String act = str(e.get("action"));
            if (!act.isEmpty()) actions.merge(act, 1L, Long::sum);
        }

        int riskScore() { return riskScore(count); }

        int riskScore(long effectiveCount) {
            long score = weighted + 3L * categories.size();
            if (effectiveCount >= 100) score += 20;
            else if (effectiveCount >= 50) score += 10;
            else if (effectiveCount >= 20) score += 5;
            return (int) Math.min(100, score);
        }

        String level() { return level(count); }

        String level(long effectiveCount) {
            int s = riskScore(effectiveCount);
            return s >= 70 ? "严重" : s >= 40 ? "高危" : s >= 20 ? "中危" : "低危";
        }

        /** 攻击链阶段按 kill-chain 顺序输出 */
        List<String> chain() {
            List<String> order = List.of("recon", "exploit", "intrusion", "impact", "other");
            List<String> out = new ArrayList<>();
            for (String s : order) if (stages.contains(s)) out.add(s);
            return out;
        }

        List<String> tags() {
            Map<String, String> dict = Map.ofEntries(
                    Map.entry("Scanner", "扫描探测"), Map.entry("InfoLeak", "信息探测"),
                    Map.entry("SQLi", "SQL注入"), Map.entry("XSS", "跨站脚本"),
                    Map.entry("RCE", "远程代码执行"), Map.entry("Deserialization", "反序列化"),
                    Map.entry("AuthBypass", "认证绕过"), Map.entry("Traversal", "路径穿越"),
                    Map.entry("XXE", "XML外部实体"), Map.entry("SSRF", "服务端请求伪造"),
                    Map.entry("Tamper", "网页篡改"), Map.entry("CC", "CC攻击"),
                    Map.entry("Bot", "恶意机器人"), Map.entry("Geo", "地域封禁"),
                    Map.entry("Custom", "自定义规则命中"), Map.entry("Upload", "恶意上传"));
            List<String> out = new ArrayList<>();
            for (String c : categories) out.add(dict.getOrDefault(c, c));
            return out;
        }

        Map<String, Object> toSummary() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", ip);
            m.put("count", count);
            m.put("firstSeen", firstSeen == Long.MAX_VALUE ? 0 : firstSeen);
            m.put("lastSeen", lastSeen);
            m.put("categories", new ArrayList<>(categories));
            m.put("actions", actions);
            m.put("riskScore", riskScore());
            m.put("level", level());
            m.put("chain", chain());
            m.put("tags", tags());
            return m;
        }
    }

    /** 攻击类别 → 攻击链阶段 */
    static String stageOf(String category) {
        switch (category == null ? "" : category) {
            case "Scanner": case "InfoLeak": case "Bot": case "Geo":
                return "recon";
            case "SQLi": case "XSS": case "Traversal": case "XXE":
            case "SSRF": case "AuthBypass": case "Custom":
                return "exploit";
            case "RCE": case "Deserialization": case "Upload": case "Webshell":
                return "intrusion";
            case "Tamper": case "CC": case "DoS":
                return "impact";
            default:
                return "other";
        }
    }

    static int severityWeight(String sev) {
        switch (sev == null ? "" : sev) {
            case "critical": return 10;
            case "high": return 5;
            case "medium": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    private static List<Map<String, Object>> topN(Map<String, Long> m, int n) {
        List<Map.Entry<String, Long>> es = new ArrayList<>(m.entrySet());
        es.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, Long> e : es) {
            if (out.size() >= n) break;
            out.add(Map.of("ruleId", e.getKey(), "count", e.getValue()));
        }
        return out;
    }

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    private static long toLong(Object o) {
        if (o == null) return 0;
        if (o instanceof Number) return ((Number) o).longValue();
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; }
    }
}
