package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/** 读取引擎写入 Redis 的 WAF 数据(与 C++ 控制台同一套 Key) */
@Service
@RequiredArgsConstructor
public class WafRedisService {
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /** 解析 JSON 字符串为对象(失败返回原始结构) */
    @SuppressWarnings("unchecked")
    private Object parse(String s) {
        if (s == null) return null;
        try { return om.readValue(s, Object.class); }
        catch (Exception e) { return s; }
    }

    public Object getJson(String key) { return parse(redis.opsForValue().get(key)); }

    /** novawaf:logs —— 全量日志 JSON 数组, 支持分页切片(按倒序) */
    @SuppressWarnings("unchecked")
    public Map<String, Object> logs(int page, int size, String keyword) {
        Object obj = getJson("novawaf:logs");
        List<Object> all = (obj instanceof List) ? (List<Object>) obj : new ArrayList<>();
        Collections.reverse(all); // 最新在前
        List<Object> filtered = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            String kw = keyword.toLowerCase();
            for (Object o : all) {
                if (String.valueOf(o).toLowerCase().contains(kw)) filtered.add(o);
            }
        } else {
            filtered.addAll(all);
        }
        long total = filtered.size();
        int from = Math.min((page - 1) * size, filtered.size());
        int to = Math.min(from + size, filtered.size());
        Map<String, Object> m = new HashMap<>();
        m.put("total", total);
        m.put("rows", filtered.subList(from, to));
        return m;
    }

    public Object rules() { return getJson("novawaf:rules"); }

    /** 防护应用列表(novawaf:apps)，叠加每应用今日统计与引擎能力标签 */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> apps() {
        List<Map<String, Object>> out = new ArrayList<>();
        Object obj = getJson("novawaf:apps");
        if (!(obj instanceof List)) return out;
        long todayStartMin = ((long) (System.currentTimeMillis() / 1000) / 86400) * 86400 / 60; // 今日 0 点的分钟桶
        // 引擎已具备的防护能力（全局生效），按真实能力标注
        List<String> features = List.of("攻击防护", "CC防护", "BOT防护", "身份认证");
        for (Object o : (List<Object>) obj) {
            if (!(o instanceof Map)) continue;
            Map<String, Object> a = (Map<String, Object>) o;
            Object idO = a.get("id");
            String id = idO == null ? "" : String.valueOf(idO);
            long todayReq = 0, todayBlk = 0, qps = 0;
            // 今日请求/拦截：累加 novawaf:traffic:{id} 今日各分钟桶
            try {
                List<String> buckets = redis.opsForList().range("novawaf:traffic:" + id, 0, -1);
                if (buckets != null) for (String s : buckets) {
                    Object bo = parse(s);
                    if (!(bo instanceof Map)) continue;
                    Map<String, Object> b = (Map<String, Object>) bo;
                    if (toLong(b.get("t")) < todayStartMin) continue;
                    todayReq += toLong(b.get("req"));
                    todayBlk += toLong(b.get("blk"));
                }
            } catch (Exception ignore) {}
            // 实时 QPS：取 novawaf:traffic:stat:{id}
            try {
                Object so = getJson("novawaf:traffic:stat:" + id);
                if (so instanceof Map) qps = toLong(((Map<String, Object>) so).get("qps"));
            } catch (Exception ignore) {}
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("name", a.get("name"));
            m.put("host", a.get("host"));
            m.put("upstreamHost", a.get("upstreamHost"));
            m.put("upstreamPort", a.get("upstreamPort"));
            m.put("statsEnabled", Boolean.TRUE.equals(a.get("statsEnabled")));
            String mv = str(a.get("mode"));
            m.put("mode", "observe".equals(mv) ? "观察" : "maintenance".equals(mv) ? "维护" : "防护");
            m.put("todayReq", todayReq);
            m.put("todayBlock", todayBlk);
            m.put("qps", qps);
            m.put("features", features);
            out.add(m);
        }
        return out;
    }

    /** 新增防护应用：校验后写回 novawaf:apps 并递增版本号触发引擎热加载 */
    @SuppressWarnings("unchecked")
    public synchronized void addApp(Map<String, Object> req) {
        List<Object> list = readApps();
        String host = str(req.get("host")).trim();
        String upHost = str(req.get("upstreamHost")).trim();
        long port = toLong(req.get("upstreamPort"));
        String name = str(req.get("name")).trim();
        if (host.isEmpty()) throw new BusinessException(400, "域名不能为空");
        if (upHost.isEmpty()) throw new BusinessException(400, "上游地址不能为空");
        if (port < 1 || port > 65535) throw new BusinessException(400, "上游端口非法(1-65535)");
        // host/上游必须是纯主机名或 IP，禁止协议头、路径、端口，否则会匹配不到应用或造成回环
        if (host.contains("://") || host.contains("/") || host.contains(":") || host.matches(".*\\s.*"))
            throw new BusinessException(400, "防护域名只能是主机名/IP(如 nac 或 192.168.100.2)，不能带 http://、路径或端口");
        if (upHost.contains("://") || upHost.contains("/") || upHost.matches(".*\\s.*"))
            throw new BusinessException(400, "上游地址只能是主机名/IP，不能带协议、路径或端口(端口单独填)");
        // 防回环：上游不能指向本机对外入口端口(如 443/80 经 nginx 又回到 WAF)
        if (port == 443 || port == 80)
            throw new BusinessException(400, "上游端口不能是 80/443(会与 nginx 入口形成回环)");
        for (Object o : list) {
            if (o instanceof Map && host.equalsIgnoreCase(str(((Map<String, Object>) o).get("host"))))
                throw new BusinessException(409, "域名已存在: " + host);
        }
        int maxId = 0;
        for (Object o : list) if (o instanceof Map) maxId = Math.max(maxId, (int) toLong(((Map<String, Object>) o).get("id")));
        Map<String, Object> app = new LinkedHashMap<>();
        app.put("id", maxId + 1);
        app.put("name", name.isEmpty() ? host : name);
        app.put("host", host);
        app.put("upstreamHost", upHost);
        app.put("upstreamPort", (int) port);
        app.put("statsEnabled", Boolean.TRUE.equals(req.get("statsEnabled")));
        app.put("mode", normMode(req.get("mode")));
        app.put("default", false);
        list.add(app);
        persistApps(list);
    }

    /** 归一化运行模式：protect(防护)/observe(观察)/maintenance(维护) */
    private String normMode(Object o) {
        String v = str(o);
        return ("observe".equals(v) || "maintenance".equals(v)) ? v : "protect";
    }

    /** 设置应用运行模式 */
    @SuppressWarnings("unchecked")
    public synchronized void setAppMode(String id, String mode) {
        String m = normMode(mode);
        List<Object> list = readApps();
        boolean found = false;
        for (Object o : list) {
            if (o instanceof Map && id.equals(str(((Map<String, Object>) o).get("id")))) {
                ((Map<String, Object>) o).put("mode", m);
                found = true;
                break;
            }
        }
        if (!found) throw new BusinessException(404, "应用不存在: id=" + id);
        persistApps(list);
    }

    /** 修改防护应用 */
    @SuppressWarnings("unchecked")
    public synchronized void updateApp(String id, Map<String, Object> req) {
        List<Object> list = readApps();
        String host = str(req.get("host")).trim();
        String upHost = str(req.get("upstreamHost")).trim();
        long port = toLong(req.get("upstreamPort"));
        String name = str(req.get("name")).trim();
        if (host.isEmpty()) throw new BusinessException(400, "域名不能为空");
        if (upHost.isEmpty()) throw new BusinessException(400, "上游地址不能为空");
        if (port < 1 || port > 65535) throw new BusinessException(400, "上游端口非法(1-65535)");
        if (host.contains("://") || host.contains("/") || host.contains(":") || host.matches(".*\\s.*"))
            throw new BusinessException(400, "防护域名只能是主机名/IP(如 nac 或 192.168.100.2)，不能带 http://、路径或端口");
        if (upHost.contains("://") || upHost.contains("/") || upHost.matches(".*\\s.*"))
            throw new BusinessException(400, "上游地址只能是主机名/IP，不能带协议、路径或端口(端口单独填)");
        if (port == 443 || port == 80)
            throw new BusinessException(400, "上游端口不能是 80/443(会与 nginx 入口形成回环)");
        boolean found = false;
        for (Object o : list) {
            if (!(o instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> a = (Map<String, Object>) o;
            if (!id.equals(str(a.get("id")))) continue;
            // 域名变更时校验不与其它应用重复
            if (!host.equalsIgnoreCase(str(a.get("host")))) {
                for (Object o2 : list) {
                    if (o2 instanceof Map && o2 != o
                            && host.equalsIgnoreCase(str(((Map<String, Object>) o2).get("host"))))
                        throw new BusinessException(409, "域名已存在: " + host);
                }
            }
            a.put("name", name.isEmpty() ? host : name);
            a.put("host", host);
            a.put("upstreamHost", upHost);
            a.put("upstreamPort", (int) port);
            if (req.containsKey("statsEnabled")) a.put("statsEnabled", Boolean.TRUE.equals(req.get("statsEnabled")));
            if (req.containsKey("mode")) a.put("mode", normMode(req.get("mode")));
            found = true;
            break;
        }
        if (!found) throw new BusinessException(404, "应用不存在: id=" + id);
        persistApps(list);
    }

    /** 删除防护应用 */
    @SuppressWarnings("unchecked")
    public synchronized void deleteApp(String id) {
        List<Object> list = readApps();
        list.removeIf(o -> o instanceof Map && id.equals(str(((Map<String, Object>) o).get("id"))));
        persistApps(list);
    }

    @SuppressWarnings("unchecked")
    private List<Object> readApps() {
        List<Object> list = new ArrayList<>();
        Object cur = getJson("novawaf:apps");
        if (cur instanceof List) list.addAll((List<Object>) cur);
        return list;
    }

    private void persistApps(List<Object> list) {
        try {
            redis.opsForValue().set("novawaf:apps", om.writeValueAsString(list));
            redis.opsForValue().increment("novawaf:apps:version");   // 触发引擎热加载
        } catch (Exception e) {
            throw new BusinessException(500, "写入应用配置失败: " + e.getMessage());
        }
    }

    public Object stats() { return getJson("novawaf:stats"); }

    /** novawaf:ioc 是 CSV 文本, 解析为表格行 */
    public List<Map<String, String>> ioc() {
        String raw = redis.opsForValue().get("novawaf:ioc");
        List<Map<String, String>> rows = new ArrayList<>();
        if (raw == null) return rows;
        for (String line : raw.split("\\R")) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split(",", -1);
            if (f.length < 2) continue;
            Map<String, String> m = new LinkedHashMap<>();
            m.put("type", f[0]);
            m.put("value", f.length > 1 ? f[1] : "");
            m.put("severity", f.length > 2 ? f[2] : "");
            m.put("source", f.length > 3 ? f[3] : "");
            m.put("note", f.length > 4 ? f[4] : "");
            rows.add(m);
        }
        return rows;
    }

    /** novawaf:meta 是 hash, 必须用 hash 读(否则 WRONGTYPE) */
    public Map<String, String> iocMeta() {
        Map<Object, Object> raw = redis.opsForHash().entries("novawaf:meta");
        Map<String, String> m = new LinkedHashMap<>();
        if (raw != null) raw.forEach((k, v) -> m.put(String.valueOf(k), String.valueOf(v)));
        return m;
    }

    /** 最近 N 条事件(novawaf:events 是 Redis List) */
    public List<Object> events(int limit) {
        List<String> raw = redis.opsForList().range("novawaf:events", -limit, -1);
        List<Object> out = new ArrayList<>();
        if (raw != null) {
            Collections.reverse(raw);
            for (String s : raw) out.add(parse(s));
        }
        return out;
    }

    /** 仪表盘聚合: 真实对接流量统计 + 攻击事件 */
    @SuppressWarnings("unchecked")
    public Map<String, Object> dashboard() {
        Map<String, Object> out = new LinkedHashMap<>();
        // 1) 流量统计(聚合所有 novawaf:traffic:stat:* )
        long req = 0, pv = 0, blk = 0, a4 = 0, a5 = 0, qps = 0;
        Set<String> sess = new HashSet<>(), ips = new HashSet<>(), atk = new HashSet<>();
        try {
            Set<String> keys = redis.keys("novawaf:traffic:stat:*");
            if (keys != null) for (String k : keys) {
                Object o = getJson(k);
                if (!(o instanceof Map)) continue;
                Map<String, Object> m = (Map<String, Object>) o;
                Object curO = m.get("cur");
                if (curO instanceof Map) {
                    Map<String, Object> cur = (Map<String, Object>) curO;
                    req += toLong(cur.get("req")); pv += toLong(cur.get("pv"));
                    blk += toLong(cur.get("blk")); a4 += toLong(cur.get("a4")); a5 += toLong(cur.get("a5"));
                    qps = Math.max(qps, toLong(m.get("qps")));
                    addAll(sess, cur.get("sess")); addAll(ips, cur.get("ip")); addAll(atk, cur.get("atk"));
                }
            }
        } catch (Exception ignore) {}
        Map<String, Object> traffic = new LinkedHashMap<>();
        traffic.put("req", req); traffic.put("pv", pv); traffic.put("uv", sess.size());
        traffic.put("ip", ips.size()); traffic.put("blk", blk); traffic.put("a4", a4);
        traffic.put("a5", a5); traffic.put("atk", atk.size()); traffic.put("qps", qps);
        out.put("traffic", traffic);

        // 2) 全局统计
        Object stats = getJson("novawaf:stats");
        out.put("stats", stats == null ? Map.of() : stats);

        // 3) 基于 events 的聚合(趋势/类型/规则/动作/TopIP)
        List<Object> evs = events(500);
        Map<String, Long> byCat = new HashMap<>(), byRule = new HashMap<>(), byAction = new HashMap<>();
        Map<String, Long> ipCnt = new HashMap<>();
        TreeMap<Long, Long> trend = new TreeMap<>();
        for (Object e : evs) {
            if (!(e instanceof Map)) continue;
            Map<String, Object> ev = (Map<String, Object>) e;
            inc(byCat, str(ev.get("category")));
            inc(byRule, str(ev.get("ruleId")));
            inc(byAction, str(ev.get("action")));
            inc(ipCnt, str(ev.get("ip")));
            long ts = toLong(ev.get("ts"));
            if (ts > 0) inc(trend, (ts / 60) * 60); // 按分钟桶
        }
        out.put("byCategory", byCat);
        out.put("byRule", byRule);
        out.put("byAction", byAction);
        out.put("topIps", topN(ipCnt, 10));
        // 趋势转数组
        List<Map<String, Object>> trendArr = new ArrayList<>();
        trend.forEach((k, v) -> {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("t", k); p.put("count", v); trendArr.add(p);
        });
        out.put("trend", trendArr);
        out.put("events", evs.size() > 30 ? evs.subList(0, 30) : evs);

        // 4) 访问明细聚合(状态/国家/客户端/系统/受访域名/来源域名/受访页面)
        out.putAll(accessAgg(3000));
        return out;
    }

    /** 聚合 novawaf:access 访问日志流 */
    @SuppressWarnings("unchecked")
    private Map<String, Object> accessAgg(int limit) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Long> byStatus = new HashMap<>(), byCountry = new HashMap<>();
        Map<String, Long> byBrowser = new HashMap<>(), byOs = new HashMap<>();
        Map<String, Long> byHost = new HashMap<>(), byReferer = new HashMap<>();
        Map<String, Long> pageCnt = new HashMap<>();
        long total = 0;
        try {
            List<String> raw = redis.opsForList().range("novawaf:access", -limit, -1);
            if (raw != null) for (String s : raw) {
                Object o = parse(s);
                if (!(o instanceof Map)) continue;
                Map<String, Object> r = (Map<String, Object>) o;
                total++;
                String st = str(r.get("st"));
                inc(byStatus, st.isEmpty() ? "0" : st);
                String cty = str(r.get("cty"));
                inc(byCountry, cty.isEmpty() ? "未知" : cty);
                String ua = str(r.get("ua"));
                inc(byBrowser, browserOf(ua));
                inc(byOs, osOf(ua));
                String host = str(r.get("host"));
                inc(byHost, host.isEmpty() ? "-" : host);
                inc(byReferer, refererDomainOf(str(r.get("ref"))));
                inc(pageCnt, str(r.get("p")));
            }
        } catch (Exception ignore) {}
        out.put("accessTotal", total);
        out.put("byStatus", topN(byStatus, 15));
        out.put("byCountry", topN(byCountry, 15));
        out.put("byBrowser", topN(byBrowser, 10));
        out.put("byOs", topN(byOs, 10));
        out.put("byHost", topN(byHost, 15));
        out.put("byReferer", topN(byReferer, 15));
        out.put("topPages", topN(pageCnt, 15));
        return out;
    }

    private String browserOf(String ua) {
        if (ua == null || ua.isBlank()) return "未知";
        String u = ua.toLowerCase();
        if (u.contains("edg/")) return "Edge";
        if (u.contains("chrome/")) return "Chrome";
        if (u.contains("firefox/")) return "Firefox";
        if (u.contains("safari/")) return "Safari";
        if (u.contains("sqlmap")) return "sqlmap";
        if (u.contains("curl")) return "curl";
        if (u.contains("python")) return "Python";
        if (u.contains("go-http")) return "Go-http";
        return "其他";
    }
    private String osOf(String ua) {
        if (ua == null || ua.isBlank()) return "未知";
        String u = ua.toLowerCase();
        if (u.contains("windows")) return "Windows";
        if (u.contains("android")) return "Android";
        if (u.contains("iphone") || u.contains("ipad")) return "iOS";
        if (u.contains("mac os") || u.contains("macintosh")) return "macOS";
        if (u.contains("linux")) return "Linux";
        return "其他";
    }
    private String refererDomainOf(String ref) {
        if (ref == null || ref.isBlank()) return "直接访问";
        try {
            String s = ref;
            int p = s.indexOf("://");
            if (p >= 0) s = s.substring(p + 3);
            int slash = s.indexOf('/');
            if (slash >= 0) s = s.substring(0, slash);
            int q = s.indexOf('?');
            if (q >= 0) s = s.substring(0, q);
            return s.isEmpty() ? "直接访问" : s;
        } catch (Exception e) { return "直接访问"; }
    }

    private long toLong(Object o) { if (o == null) return 0; try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; } }
    private String str(Object o) { return o == null ? "" : String.valueOf(o); }
    private void inc(Map<String, Long> m, String k) { if (k == null || k.isEmpty()) return; m.merge(k, 1L, Long::sum); }
    private void inc(Map<Long, Long> m, Long k) { m.merge(k, 1L, Long::sum); }
    @SuppressWarnings("unchecked")
    private void addAll(Set<String> set, Object o) { if (o instanceof List) for (Object x : (List<Object>) o) set.add(String.valueOf(x)); }
    private List<Map<String, Object>> topN(Map<String, Long> m, int n) {
        return m.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(n)
                .map(e -> { Map<String, Object> p = new LinkedHashMap<>(); p.put("name", e.getKey()); p.put("value", e.getValue()); return p; })
                .toList();
    }

    /** bump 规则版本号触发引擎热加载 */
    public void bumpRulesVersion() {
        redis.opsForValue().increment("novawaf:rules:version");
    }

    public void setRules(String json) {
        redis.opsForValue().set("novawaf:rules", json);
        bumpRulesVersion();
    }
}
