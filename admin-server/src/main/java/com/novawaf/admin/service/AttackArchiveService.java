package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.mapper.WafAttackEventMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 攻击事件归档: 引擎把每条攻击事件同时写入 Redis 归档消费队列(novawaf:ev:archive, 容量 50000),
 * 本服务每 10s 批量消费落 MySQL waf_attack_event 表, 实现任意 IP、任意时段的完整溯源回看。
 * 可靠性: 读(LRANGE) → 批量插入(INSERT IGNORE, dedup 唯一键去重) → 确认后删(LTRIM);
 * 中途崩溃最多重复消费, dedup 去重保证幂等。
 * 保留期: 默认 30 天(环境变量 NOVA_ARCHIVE_KEEP_DAYS 可调), 每日 03:30 清理。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AttackArchiveService {
    private final StringRedisTemplate redis;
    private final JdbcTemplate jdbc;
    private final WafAttackEventMapper mapper;
    private final ObjectMapper om = new ObjectMapper();

    static final String K_ARCHIVE = "novawaf:ev:archive";
    private static final int BATCH = 500;        // 每批消费条数
    private static final int MAX_PER_RUN = 5000; // 单次任务最多追平条数(防雪崩)

    /** 启动后自动建表(IF NOT EXISTS 幂等) */
    @EventListener(ApplicationReadyEvent.class)
    public void initTable() {
        jdbc.execute("CREATE TABLE IF NOT EXISTS waf_attack_event ("
                + "id BIGINT AUTO_INCREMENT PRIMARY KEY,"
                + "ts BIGINT NOT NULL COMMENT '攻击时间 epoch 秒',"
                + "ip VARCHAR(45) NOT NULL,"
                + "action VARCHAR(16),"
                + "category VARCHAR(32),"
                + "rule_id VARCHAR(64),"
                + "matched VARCHAR(512),"
                + "severity VARCHAR(16),"
                + "dedup CHAR(32) NOT NULL COMMENT '去重哈希 md5(ip|ts|rule|matched)',"
                + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "UNIQUE KEY uk_dedup (dedup),"
                + "KEY idx_ip_ts (ip, ts),"
                + "KEY idx_ts (ts)"
                + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        log.info("[archive] waf_attack_event 表就绪");
    }

    /** 每 10s 消费归档队列 */
    @Scheduled(fixedRate = 10000, initialDelay = 15000)
    public void consume() {
        int total = 0;
        try {
            while (total < MAX_PER_RUN) {
                List<String> raw = redis.opsForList().range(K_ARCHIVE, 0, BATCH - 1);
                if (raw == null || raw.isEmpty()) break;
                List<Map<String, Object>> rows = new ArrayList<>(raw.size());
                for (String s : raw) {
                    try {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> e = om.readValue(s, Map.class);
                        String ip = str(e.get("ip"));
                        long ts = toLong(e.get("ts"));
                        if (ip.isEmpty() || ts <= 0) continue;
                        e.put("dedup", md5(ip + "|" + ts + "|" + str(e.get("ruleId")) + "|" + str(e.get("matched"))));
                        if (str(e.get("matched")).length() > 512) e.put("matched", str(e.get("matched")).substring(0, 512));
                        rows.add(e);
                    } catch (Exception ignore) { /* 坏行跳过, 仍会被 LTRIM 清掉 */ }
                }
                if (!rows.isEmpty()) mapper.insertBatch(rows);
                // 确认写入后再从队列删除已消费部分(非原子但幂等: dedup 唯一键兜底)
                redis.opsForList().trim(K_ARCHIVE, raw.size(), -1);
                total += raw.size();
                if (raw.size() < BATCH) break;
            }
            if (total > 0) log.debug("[archive] 本批归档 {} 条", total);
        } catch (Exception e) {
            log.warn("[archive] 归档消费失败(下周期重试): {}", e.getMessage());
        }
    }

    /** 每日 03:30 清理保留期外数据 */
    @Scheduled(cron = "0 30 3 * * ?")
    public void purge() {
        int keepDays = Integer.parseInt(System.getenv().getOrDefault("NOVA_ARCHIVE_KEEP_DAYS", "30"));
        long before = System.currentTimeMillis() / 1000 - keepDays * 86400L;
        int n = mapper.deleteBefore(before);
        if (n > 0) log.info("[archive] 清理 {} 天前归档 {} 条", keepDays, n);
    }

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }
    private static long toLong(Object o) {
        if (o instanceof Number) return ((Number) o).longValue();
        try { return Long.parseLong(str(o)); } catch (Exception e) { return 0; }
    }
    private static String md5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(32);
            for (byte x : b) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) { return s.length() > 32 ? s.substring(0, 32) : s; }
    }
}
