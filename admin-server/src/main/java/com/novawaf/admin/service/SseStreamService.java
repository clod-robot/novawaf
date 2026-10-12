package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 实时推送服务：把引擎写入 Redis 的攻击事件与仪表盘快照通过 SSE 推给浏览器。
 * 单线程轮询 Redis，广播给所有连接的 SseEmitter，避免每客户端独立查库。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SseStreamService {
    private final StringRedisTemplate redis;
    private final WafRedisService waf;
    private final IpListService iplist;
    private final GeoService geo;
    private final ObjectMapper om = new ObjectMapper();

    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private ScheduledExecutorService pool;
    private long lastEventIdx = -1;   // 已推送的 novawaf:events 最大下标(0-based 总长度游标)
    private long lastSnapshot = 0;
    private long lastIpVersion = -1;  // 名单版本游标，变化则推送 iplist 事件

    private static final long TIMEOUT = 0L; // 不超时，靠连接断开清理

    @PostConstruct
    public void start() {
        // 初始化游标：启动时已存在的事件不再补发，只推之后新增的
        Long len = redis.opsForList().size("novawaf:events");
        lastEventIdx = len == null ? 0 : len;
        pool = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "sse-broadcaster");
            t.setDaemon(true);
            return t;
        });
        pool.scheduleWithFixedDelay(this::broadcast, 1, 1, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void stop() {
        if (pool != null) pool.shutdownNow();
        for (SseEmitter e : emitters) try { e.complete(); } catch (Exception ignore) {}
    }

    public SseEmitter subscribe() {
        SseEmitter em = new SseEmitter(TIMEOUT);
        em.onCompletion(() -> emitters.remove(em));
        em.onTimeout(() -> emitters.remove(em));
        em.onError(t -> emitters.remove(em));
        emitters.add(em);
        // 连接建立即推一份当前快照，前端无需先轮询
        try {
            em.send(SseEmitter.event().name("snapshot").data(waf.dashboard()));
        } catch (Exception e) {
            emitters.remove(em);
        }
        return em;
    }

    private void broadcast() {
        if (emitters.isEmpty()) return;
        try {
            // 1) 新增攻击事件（增量）
            Long len = redis.opsForList().size("novawaf:events");
            long cur = len == null ? 0 : len;
            if (cur > lastEventIdx) {
                long from = lastEventIdx;          // LRANGE 含两端，from 为已推最后一条的下一条之前的位置
                List<String> newOnes = redis.opsForList().range("novawaf:events", from, cur - 1);
                if (newOnes != null) {
                    for (String s : newOnes) {
                        Object ev;
                        try {
                            ev = om.readValue(s, Object.class);
                            // 富集 geo（联动地理），并累加名单命中计数
                            if (ev instanceof Map<?, ?> m && m.get("ip") != null) {
                                @SuppressWarnings("unchecked") Map<String, Object> mm = (Map<String, Object>) m;
                                String ip = String.valueOf(mm.get("ip"));
                                mm.put("country", geo.label(ip));
                                iplist.recordHit(ip);
                            }
                        } catch (Exception ex) { ev = s; }
                        sendAll("event", ev);
                    }
                }
                lastEventIdx = cur;
            } else if (cur < lastEventIdx) {
                lastEventIdx = cur; // 列表被裁剪/清空，重置游标
            }
            // 2) 黑白名单版本变化 → 推送 iplist（前端实时刷新）
            long ipv = iplist.version();
            if (lastIpVersion < 0) lastIpVersion = ipv;
            else if (ipv != lastIpVersion) { lastIpVersion = ipv; sendAll("iplist", Map.of("version", ipv)); }
            // 3) 仪表盘快照（每 3 秒）
            long now = System.currentTimeMillis();
            if (now - lastSnapshot >= 3000) {
                lastSnapshot = now;
                sendAll("snapshot", waf.dashboard());
            }
        } catch (Exception e) {
            log.debug("sse broadcast error: {}", e.toString());
        }
    }

    private void sendAll(String name, Object data) {
        for (SseEmitter em : emitters) {
            try {
                em.send(SseEmitter.event().name(name).data(data));
            } catch (Exception e) {
                emitters.remove(em);
                try { em.complete(); } catch (Exception ignore) {}
            }
        }
    }

    public Map<String, Object> status() {
        return Map.of("clients", emitters.size(), "eventCursor", lastEventIdx);
    }
}
