package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Syslog 外发：将攻击告警日志与运行状态日志按 RFC3164 发送到外部 Syslog 服务器，供安全审计/SIEM 归集。
 * 配置存于 Redis(novawaf:syslog)，后台线程增量推送 novawaf:events 新增事件，并周期性发送运行心跳。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SyslogService {
    public static final String CFG_KEY = "novawaf:syslog";
    private final StringRedisTemplate redis;
    private final WafRedisService waf;
    private final ObjectMapper om = new ObjectMapper();

    private ScheduledExecutorService pool;
    private long lastEventIdx = -1;
    private volatile long forwarded = 0;
    private volatile long failed = 0;
    private volatile String lastError = "";

    // RFC3164 Facility: USER=1, LOCAL0~7=16~23, AUTH=4, AUTHPRIV=10, DAEMON=3
    private static final Map<String, Integer> FAC = Map.ofEntries(
            Map.entry("user", 1), Map.entry("daemon", 3), Map.entry("auth", 4), Map.entry("authpriv", 10),
            Map.entry("local0", 16), Map.entry("local1", 17), Map.entry("local2", 18), Map.entry("local3", 19),
            Map.entry("local4", 20), Map.entry("local5", 21), Map.entry("local6", 22), Map.entry("local7", 23));
    // Severity: EMERG0 ALERT1 CRIT2 ERR3 WARN4 NOTICE5 INFO6 DEBUG7
    private static final Map<String, Integer> SEV = Map.of(
            "emerg", 0, "alert", 1, "crit", 2, "err", 3,
            "warning", 4, "notice", 5, "info", 6, "debug", 7);

    @Data
    public static class Cfg {
        private boolean enabled = false;
        private String host = "127.0.0.1";
        private int port = 514;
        private String protocol = "udp";      // udp | tcp
        private String facility = "local0";
        private String tag = "novawaf";
        private String minLevel = "info";     // 低于此严重级不发
        private boolean forwardAlerts = true; // 转发攻击告警
        private boolean forwardRuntime = true;// 转发运行心跳
    }

    @PostConstruct
    public void start() {
        Long len = redis.opsForList().size("novawaf:events");
        lastEventIdx = len == null ? 0 : len;
        pool = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "syslog-forwarder");
            t.setDaemon(true);
            return t;
        });
        pool.scheduleWithFixedDelay(this::tick, 5, 2, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void stop() { if (pool != null) pool.shutdownNow(); }

    public Cfg loadCfg() {
        try {
            String s = redis.opsForValue().get(CFG_KEY);
            if (s != null && !s.isBlank()) return om.readValue(s, Cfg.class);
        } catch (Exception ignore) {}
        return new Cfg();
    }

    public void saveCfg(Cfg c) {
        try {
            redis.opsForValue().set(CFG_KEY, om.writeValueAsString(c));
        } catch (Exception e) {
            throw new RuntimeException("保存 syslog 配置失败: " + e.getMessage());
        }
    }

    public Map<String, Object> status() {
        Cfg c = loadCfg();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("config", c);
        m.put("forwarded", forwarded);
        m.put("failed", failed);
        m.put("lastError", lastError);
        return m;
    }

    /** 发送一条测试消息（同步，便于前端验证连通性） */
    public Map<String, Object> test(Cfg c) {
        Cfg use = (c == null) ? loadCfg() : c;
        String msg = use.getTag() + " syslog test message @ " + new Date();
        boolean ok = send(use, "notice", msg);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", ok);
        r.put("target", use.getHost() + ":" + use.getPort() + "/" + use.getProtocol());
        r.put("message", msg);
        if (!ok) r.put("error", lastError);
        return r;
    }

    private void tick() {
        Cfg c = loadCfg();
        if (!c.isEnabled()) return;
        try {
            if (c.isForwardAlerts()) forwardNewEvents(c);
            if (c.isForwardRuntime()) {
                // 每 30s 发一次运行心跳（请求/拦截/QPS 汇总），满足“运行日志外发”
                long now = System.currentTimeMillis() / 1000;
                String k = "novawaf:syslog:hbeat";
                String last = redis.opsForValue().get(k);
                long lastHb = last == null ? 0 : Long.parseLong(last);
                if (now - lastHb >= 30) {
                    redis.opsForValue().set(k, String.valueOf(now));
                    send(c, "info", runtimeHeartbeat());
                }
            }
        } catch (Exception e) {
            log.debug("syslog tick error: {}", e.toString());
        }
    }

    @SuppressWarnings("unchecked")
    private void forwardNewEvents(Cfg c) {
        Long len = redis.opsForList().size("novawaf:events");
        long cur = len == null ? 0 : len;
        if (cur < lastEventIdx) lastEventIdx = cur;
        if (cur <= lastEventIdx) return;
        List<String> newOnes = redis.opsForList().range("novawaf:events", lastEventIdx, cur - 1);
        lastEventIdx = cur;
        if (newOnes == null) return;
        for (String s : newOnes) {
            String sev = "warning"; String text = s;
            try {
                Object o = om.readValue(s, Object.class);
                if (o instanceof Map) {
                    Map<String, Object> m = (Map<String, Object>) o;
                    String action = String.valueOf(m.getOrDefault("action", ""));
                    sev = "block".equalsIgnoreCase(action) ? "alert" : "warning";
                    text = String.format("WAF_ALERT action=%s category=%s rule=%s ip=%s matched=%s path=%s",
                            action, m.get("category"), m.get("ruleId"), m.get("ip"),
                            abbrev(String.valueOf(m.get("matched"))), m.get("path"));
                }
            } catch (Exception ignore) {}
            if (belowMin(sev, c.getMinLevel())) continue;
            send(c, sev, text);
        }
    }

    private String runtimeHeartbeat() {
        try {
            Map<String, Object> d = waf.dashboard();
            Object t = d.get("traffic");
            if (t instanceof Map) {
                Map<String, Object> tr = (Map<String, Object>) t;
                return String.format("WAF_RUNTIME req=%s pv=%s block=%s qps=%s attack_ip=%s",
                        tr.get("req"), tr.get("pv"), tr.get("blk"), tr.get("qps"), tr.get("atk"));
            }
        } catch (Exception ignore) {}
        return "WAF_RUNTIME heartbeat";
    }

    private boolean belowMin(String sev, String min) {
        int s = SEV.getOrDefault(sev, 6), m = SEV.getOrDefault(min, 6);
        return s > m; // severity 数值越大越不严重
    }
    private String abbrev(String s) { if (s == null) return ""; return s.length() > 120 ? s.substring(0, 120) + "…" : s; }

    /** RFC3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG */
    synchronized boolean send(Cfg c, String severity, String message) {
        int facility = FAC.getOrDefault(c.getFacility().toLowerCase(), 16);
        int sev = SEV.getOrDefault(severity.toLowerCase(), 6);
        int pri = facility * 8 + sev;
        String ts = new SimpleDateFormat("MMM dd HH:mm:ss", Locale.US).format(new Date());
        String host;
        try { host = InetAddress.getLocalHost().getHostName(); } catch (Exception e) { host = "novawaf"; }
        String payload = "<" + pri + ">" + ts + " " + host + " " + c.getTag() + ": " + message;
        byte[] data = payload.getBytes(StandardCharsets.UTF_8);
        try {
            if ("tcp".equalsIgnoreCase(c.getProtocol())) {
                try (Socket sock = new Socket()) {
                    sock.connect(new InetSocketAddress(c.getHost(), c.getPort()), 1500);
                    sock.setSoTimeout(1500);
                    OutputStream os = sock.getOutputStream();
                    os.write(data); os.write('\n'); os.flush();
                }
            } else {
                try (DatagramSocket ds = new DatagramSocket()) {
                    ds.send(new DatagramPacket(data, data.length, InetAddress.getByName(c.getHost()), c.getPort()));
                }
            }
            forwarded++;
            return true;
        } catch (Exception e) {
            failed++;
            lastError = e.getMessage();
            return false;
        }
    }
}
