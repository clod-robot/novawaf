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
    private static final int MAX_PER_RUN = 20000; // 单次任务最多追平条数(防雪崩；高速攻击下 10s 需消化近万条)

    /** 启动后自动建表(IF NOT EXISTS 幂等) + 存量表补齐新增列 */
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
                + "uri VARCHAR(512) DEFAULT '' COMMENT '请求 path(含 query), 按 API 维度统计',"
                + "host VARCHAR(255) DEFAULT '' COMMENT '请求 Host 头, 按应用/域名维度区分',"
                + "dedup CHAR(32) NOT NULL COMMENT '去重哈希 md5(ip|ts|rule|matched|uri|host)',"
                + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "UNIQUE KEY uk_dedup (dedup),"
                + "KEY idx_ip_ts (ip, ts),"
                + "KEY idx_ts (ts),"
                + "KEY idx_uri (uri(191)),"
                + "KEY idx_host (host(191))"
                + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // 存量表升级: 逐列检查补齐(MySQL 无 ADD COLUMN IF NOT EXISTS, 用 information_schema 判定)
        ensureColumn("uri", "VARCHAR(512) DEFAULT '' COMMENT '请求 path(含 query), 按 API 维度统计'");
        ensureColumn("host", "VARCHAR(255) DEFAULT '' COMMENT '请求 Host 头, 按应用/域名维度区分'");
        // API 维度统计(GROUP BY host,uri + ts 时间窗)专用索引，数据量上亿后避免全表扫描
        ensureIndex("idx_host_ts", "KEY idx_host_ts (host(191), ts)");
        ensureIndex("idx_ts_host_uri", "KEY idx_ts_host_uri (ts, host(191), uri(191))");
        ensureApiStatTable();
        log.info("[archive] waf_attack_event 表就绪");
    }

    /**
     * API 维度统计物化表(分钟桶)。明细表日增千万级，直接 GROUP BY host,uri 需数十秒；
     * 预聚合后页面查询只扫分钟桶(每桶几十行)，任意时段都是毫秒级。
     */
    private void ensureApiStatTable() {
        try {
            jdbc.execute("CREATE TABLE IF NOT EXISTS waf_api_stat ("
                    + "minute INT NOT NULL COMMENT '分钟桶 epoch/60',"
                    + "host VARCHAR(255) NOT NULL DEFAULT '',"
                    + "uri VARCHAR(512) NOT NULL DEFAULT '',"
                    + "total BIGINT NOT NULL DEFAULT 0,"
                    + "blocked BIGINT NOT NULL DEFAULT 0,"
                    + "challenged BIGINT NOT NULL DEFAULT 0,"
                    + "attackers INT NOT NULL DEFAULT 0 COMMENT '该分钟独立攻击源数',"
                    + "PRIMARY KEY (minute, host(100), uri(191)),"
                    + "KEY idx_minute (minute)"
                    + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            log.info("[archive] waf_api_stat 表就绪");
        } catch (Exception e) {
            log.warn("[archive] waf_api_stat 建表失败: {}", e.getMessage());
        }
    }

    /** 单段(秒区间)预聚合：按分钟桶 + host + uri 写入物化表，重复执行幂等覆盖 */
    private synchronized void rollRange(long fromS, long toS) {
        jdbc.update("INSERT INTO waf_api_stat(minute,host,uri,total,blocked,challenged,attackers) "
                + "SELECT ts DIV 60, host, uri, COUNT(*), SUM(action='block'), SUM(action='challenge'), COUNT(DISTINCT ip) "
                + "FROM waf_attack_event WHERE ts>=? AND ts<? AND uri<>'' "
                + "GROUP BY ts DIV 60, host, uri "
                + "ON DUPLICATE KEY UPDATE total=VALUES(total), blocked=VALUES(blocked), "
                + "challenged=VALUES(challenged), attackers=VALUES(attackers)", fromS, toS);
    }

    private volatile boolean statBackfilling = true;

    /** 启动后后台回填最近 48 小时(按小时分段)，不阻塞启动；完成后切到每分钟增量聚合 */
    @EventListener(ApplicationReadyEvent.class)
    public void backfillApiStat() {
        Thread t = new Thread(() -> {
            long now = System.currentTimeMillis() / 1000;
            long from = now - 48 * 3600;
            try {
                Long minTs = jdbc.queryForObject("SELECT MIN(ts) FROM waf_attack_event", Long.class);
                if (minTs != null && minTs > from) from = minTs;
            } catch (Exception ignore) {}
            from = (from / 3600) * 3600;
            for (long s = from; s < now; s += 3600) {
                try { rollRange(s, Math.min(s + 3600, now)); } catch (Exception ignore) {}
            }
            statBackfilling = false;
            log.info("[archive] waf_api_stat 回填完成(自 {} 起)", from);
        }, "api-stat-backfill");
        t.setDaemon(true);
        t.start();
    }

    /** 每分钟增量聚合最近 2 个已完成分钟(归档有 10s 批量滞后 + 迟到事件) */
    @Scheduled(fixedRate = 60000, initialDelay = 60000)
    public void rollupApiStat() {
        if (statBackfilling) return;
        try {
            long curMin = System.currentTimeMillis() / 1000 / 60;
            for (long m = curMin - 2; m <= curMin - 1; m++) rollRange(m * 60, m * 60 + 60);
        } catch (Exception e) {
            log.warn("[archive] API 分钟聚合失败(下周期重试): {}", e.getMessage());
        }
    }

    /** 幂等补索引 */
    private void ensureIndex(String name, String ddl) {
        try {
            Integer n = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.STATISTICS "
                            + "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_attack_event' AND INDEX_NAME=?",
                    Integer.class, name);
            if (n != null && n == 0) {
                jdbc.execute("ALTER TABLE waf_attack_event ADD " + ddl);
                log.info("[archive] waf_attack_event 补索引: {}", name);
            }
        } catch (Exception e) {
            log.warn("[archive] 补索引 {} 失败(不影响主流程): {}", name, e.getMessage());
        }
    }

    private void ensureColumn(String col, String ddl) {
        try {
            Integer n = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.COLUMNS "
                            + "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_attack_event' AND COLUMN_NAME=?",
                    Integer.class, col);
            if (n != null && n == 0) {
                jdbc.execute("ALTER TABLE waf_attack_event ADD COLUMN " + col + " " + ddl);
                log.info("[archive] waf_attack_event 补列: {}", col);
            }
        } catch (Exception e) {
            log.warn("[archive] 补列 {} 失败(不影响主流程): {}", col, e.getMessage());
        }
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
                        String uri = str(e.get("uri"));
                        String host = str(e.get("host"));
                        if (uri.length() > 512) { e.put("uri", uri.substring(0, 512)); uri = uri.substring(0, 512); }
                        if (host.length() > 255) { e.put("host", host.substring(0, 255)); host = host.substring(0, 255); }
                        e.put("dedup", md5(ip + "|" + ts + "|" + str(e.get("ruleId")) + "|" + str(e.get("matched")) + "|" + uri + "|" + host));
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
