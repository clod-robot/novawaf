package com.novawaf.admin.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 离线 GeoIP 解析：与引擎共用 Redis 键 novawaf:geoip（CIDR,CC[,名称] 文本）。
 * 解析 IP → {cc, name}，copy-on-write 热更新，查找用二分。纯离线不调用外部 API（合规）。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeoService {
    private final StringRedisTemplate redis;

    private record Range(long start, long end, String cc, String name) {}
    private static final class Snapshot { final List<Range> ranges; final long cksum; Snapshot(List<Range> r, long c){ranges=r;cksum=c;} }
    private final AtomicReference<Snapshot> snap = new AtomicReference<>(new Snapshot(List.of(), -1));

    /** ISO CC → 中文国名（离线映射，保证无库时也能显示可读标签） */
    private static final Map<String, String> CC_ZH = Map.ofEntries(
            Map.entry("CN", "中国"), Map.entry("US", "美国"), Map.entry("GB", "英国"), Map.entry("JP", "日本"),
            Map.entry("KR", "韩国"), Map.entry("RU", "俄罗斯"), Map.entry("IN", "印度"), Map.entry("DE", "德国"),
            Map.entry("FR", "法国"), Map.entry("AU", "澳大利亚"), Map.entry("CA", "加拿大"), Map.entry("BR", "巴西"),
            Map.entry("SG", "新加坡"), Map.entry("HK", "中国香港"), Map.entry("TW", "中国台湾"), Map.entry("VN", "越南"),
            Map.entry("TH", "泰国"), Map.entry("ID", "印度尼西亚"), Map.entry("MY", "马来西亚"), Map.entry("PH", "菲律宾"),
            Map.entry("IT", "意大利"), Map.entry("ES", "西班牙"), Map.entry("NL", "荷兰"), Map.entry("UA", "乌克兰"),
            Map.entry("PL", "波兰"), Map.entry("TR", "土耳其"), Map.entry("IR", "伊朗"), Map.entry("KP", "朝鲜"),
            Map.entry("MX", "墨西哥"), Map.entry("AR", "阿根廷"), Map.entry("ZA", "南非"), Map.entry("EG", "埃及"));

    private static boolean isPrivate(String ip) {
        long u = ipToUint(ip); if (u == 0) return false;
        long a = (u >> 24) & 0xFF;
        if (a == 0 || a == 10 || a == 127) return true;
        if (a == 192 && ((u >> 16) & 0xFF) == 168) return true;
        if (a == 172) { long b = (u >> 16) & 0xFF; if (b >= 16 && b <= 31) return true; }
        if (a == 169 && ((u >> 16) & 0xFF) == 254) return true;
        if (a == 100) { long b = (u >> 16) & 0xFF; if (b >= 64 && b <= 127) return true; }
        return a >= 224;
    }

    /** 解析 IP 归属：返回 {cc, name}；内网返回 {cc:"内网", name:"内网"}，未知返回空 map */
    public Map<String, String> resolve(String ip) {
        Map<String, String> m = new HashMap<>();
        if (ip == null || ip.isBlank()) return m;
        if (isPrivate(ip)) { m.put("cc", "内网"); m.put("name", "内网"); return m; }
        long u = ipToUint(ip);
        if (u == 0) return m;
        ensureLoaded();
        List<Range> rs = snap.get().ranges;
        // 二分：最大的 start <= u
        int lo = 0, hi = rs.size();
        while (lo < hi) { int mid = (lo + hi) >>> 1; if (rs.get(mid).start <= u) lo = mid + 1; else hi = mid; }
        if (lo > 0) { Range r = rs.get(lo - 1); if (u >= r.start && u <= r.end) { m.put("cc", r.cc); m.put("name", r.name); } }
        return m;
    }

    /** 供列表展示的标签：库给出省·市等细粒度(含·或中文)则用原名，否则用中文国名 */
    public String label(String ip) {
        Map<String, String> g = resolve(ip);
        if (g.isEmpty()) return "未知";
        String name = g.get("name");
        String cc = g.get("cc");
        if ("内网".equals(cc)) return "内网";
        boolean fine = name != null && (name.contains("·") || name.chars().anyMatch(c -> c > 0x4E00 && c < 0x9FFF));
        if (fine) return name;
        String zh = CC_ZH.get(cc);
        return zh != null ? zh : (name != null && !name.isBlank() ? name : cc);
    }

    /** 加载 novawaf:geoip（仅当 cksum 变化时重建） */
    private synchronized void ensureLoaded() {
        String raw;
        try { raw = redis.opsForValue().get("novawaf:geoip"); } catch (Exception e) { return; }
        if (raw == null) return;
        long ck = raw.hashCode();
        if (ck == snap.get().cksum) return;
        List<Range> list = new ArrayList<>();
        for (String line : raw.split("\n")) {
            String s = line.trim();
            if (s.isEmpty() || s.startsWith("#")) continue;
            String[] f = s.split(",");
            if (f.length < 2) continue;
            String cidr = f[0].trim();
            String cc = f[1].trim().toUpperCase();
            if (cc.isEmpty()) continue;
            long[] se = parseCidr(cidr);
            if (se == null) continue;
            String name = f.length >= 3 ? f[2].trim() : CC_ZH.getOrDefault(cc, cc);
            list.add(new Range(se[0], se[1], cc, name));
        }
        list.sort(Comparator.comparingLong(r -> r.start));
        snap.set(new Snapshot(list, ck));
        log.info("GeoService loaded {} CIDR ranges", list.size());
    }

    static long ipToUint(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return 0;
        try {
            long a = Long.parseLong(p[0]), b = Long.parseLong(p[1]), c = Long.parseLong(p[2]), d = Long.parseLong(p[3]);
            if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return 0;
            return (a << 24) | (b << 16) | (c << 8) | d;
        } catch (NumberFormatException e) { return 0; }
    }

    static long[] parseCidr(String s) {
        int slash = s.indexOf('/');
        if (slash < 0) { long ip = ipToUint(s); return ip == 0 ? null : new long[]{ip, ip}; }
        long net = ipToUint(s.substring(0, slash));
        int bits;
        try { bits = Integer.parseInt(s.substring(slash + 1)); } catch (NumberFormatException e) { return null; }
        if (net == 0 || bits < 0 || bits > 32) return null;
        long mask = (bits == 0) ? 0 : (0xFFFFFFFFL << (32 - bits));
        long start = net & mask;
        long end = (bits == 32) ? start : (start | (~mask & 0xFFFFFFFFL));
        return new long[]{start, end};
    }
}
