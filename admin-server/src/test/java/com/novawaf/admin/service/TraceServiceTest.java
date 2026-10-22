package com.novawaf.admin.service;

import com.novawaf.admin.common.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** TraceService 溯源聚合单测: IP 维度聚合 / 分桶真实计数 / 风险分 / 攻击链阶段 / 单 IP 时间线 */
@ExtendWith(MockitoExtension.class)
class TraceServiceTest {

    private static final ZoneId ZONE = ZoneId.of("Asia/Shanghai"); // 与 TraceService 一致

    @Mock private StringRedisTemplate redis;
    @Mock private ListOperations<String, String> listOps;
    @Mock private HashOperations<String, Object, Object> hashOps;
    @Mock private com.novawaf.admin.mapper.WafAttackEventMapper archiveMapper;

    private TraceService service;

    @BeforeEach
    void setUp() {
        service = new TraceService(redis, archiveMapper);
        lenient().when(redis.opsForList()).thenReturn(listOps);
        lenient().when(redis.opsForHash()).thenReturn(hashOps);
        // 默认分桶为空(绝大多数用例只测窗口样本逻辑)
        lenient().when(hashOps.entries(anyString())).thenReturn(Collections.emptyMap());
    }

    private static String ev(long ts, String ip, String action, String cat, String rule, String sev) {
        return "{\"ts\":" + ts + ",\"ip\":\"" + ip + "\",\"action\":\"" + action
                + "\",\"category\":\"" + cat + "\",\"ruleId\":\"" + rule
                + "\",\"matched\":\"m\",\"severity\":\"" + sev + "\"}";
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rowsOf(Map<String, Object> resp) {
        return (List<Map<String, Object>>) resp.get("rows");
    }

    // 与 TraceService.readBuckets 完全一致的桶键格式(Asia/Shanghai, 无横线)
    private static String cntKey(LocalDate d) {
        return TraceService.K_TRACE_CNT + d.toString().replace("-", "");
    }

    // ---------------- summary 聚合 ----------------

    @Test
    void summaryAggregatesPerIp() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                ev(1000, "1.2.3.4", "block", "SQLi", "1", "critical"),
                ev(1010, "1.2.3.4", "block", "XSS", "3", "high"),
                ev(1020, "5.6.7.8", "log", "Scanner", "8", "medium")));

        List<Map<String, Object>> rows = rowsOf(service.summary(50));
        assertEquals(2, rows.size());
        // 1.2.3.4 风险分(10+5+3*2类=21) > 5.6.7.8(2+3=5) → 排第一
        Map<String, Object> top = rows.get(0);
        assertEquals("1.2.3.4", top.get("ip"));
        assertEquals(2L, top.get("count"));
        assertEquals(1000L, top.get("firstSeen"));
        assertEquals(1010L, top.get("lastSeen"));
        assertEquals(List.of("SQLi", "XSS"), top.get("categories"));
        assertEquals(21, top.get("riskScore"));
        assertEquals("中危", top.get("level"));
    }

    @Test
    void summaryKillChainStagesOrdered() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                ev(100, "9.9.9.9", "block", "Tamper", "TAMPER-01", "high"),   // impact
                ev(90, "9.9.9.9", "log", "Scanner", "8", "low"),             // recon
                ev(95, "9.9.9.9", "block", "RCE", "5", "critical")));        // intrusion
        Map<String, Object> row = rowsOf(service.summary(10)).get(0);
        // 按 kill-chain 顺序输出而非出现顺序
        assertEquals(List.of("recon", "intrusion", "impact"), row.get("chain"));
        assertTrue(((List<String>) row.get("tags")).contains("网页篡改"));
        assertTrue(((List<String>) row.get("tags")).contains("扫描探测"));
    }

    @Test
    void summaryRespectsLimitAndSkipsBadLines() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                "not-json",
                ev(1, "1.1.1.1", "block", "SQLi", "1", "high"),
                ev(2, "2.2.2.2", "block", "SQLi", "1", "high"),
                ev(3, "3.3.3.3", "block", "SQLi", "1", "high")));
        List<Map<String, Object>> rows = rowsOf(service.summary(2));
        assertEquals(2, rows.size()); // limit 生效 + 坏行跳过
    }

    @Test
    void summaryEmptyWhenNoEvents() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(null);
        assertTrue(rowsOf(service.summary(50)).isEmpty());
    }

    // ---------------- 分桶真实计数 ----------------

    @Test
    void realBucketCountOverridesWindowCap() {
        // 洪水 IP: 窗口里只剩 5 条样本(被挤出/封禁后重新开始), 但分桶真实计数 5000
        List<String> evs = List.of(
                ev(2000, "9.9.9.9", "block", "SQLi", "1", "critical"),
                ev(2001, "9.9.9.9", "block", "XSS", "3", "critical"),
                ev(2002, "9.9.9.9", "block", "RCE", "5", "critical"),
                ev(2003, "9.9.9.9", "block", "Traversal", "7", "critical"),
                ev(2004, "9.9.9.9", "block", "InfoLeak", "9", "critical"));
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(evs);
        Map<Object, Object> today = new java.util.HashMap<>();
        today.put("9.9.9.9", "5000");
        LocalDate now = LocalDate.now(ZONE);
        when(hashOps.entries(cntKey(now))).thenReturn(today);
        when(hashOps.entries(cntKey(now.minusDays(1)))).thenReturn(Collections.emptyMap());
        Map<String, Object> resp = service.summary(50);
        Map<String, Object> top = rowsOf(resp).get(0);
        assertEquals("9.9.9.9", top.get("ip"));
        assertEquals(5000L, top.get("count"));        // 真实累计, 不封顶 1000
        // 风险分 = 5*10(严重度) + 5*3(类别多样性) + 20(频率加成) = 85 → 严重
        assertEquals(85, top.get("riskScore"));
        assertEquals("严重", top.get("level"));
        assertEquals("今日累计(跨天自动重置, 分桶保留48h); 类型画像来自近期明细样本",
                resp.get("scope"));
    }

    @Test
    void bucketOnlyIpStillVisible() {
        // 100.4 场景: 窗口被洪水 IP 独占, 明细里没有它; 但分桶计数里有 → 仍然显示
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                ev(1, "6.6.6.6", "block", "CC", "cc", "high"),
                ev(2, "6.6.6.6", "block", "CC", "cc", "high"),
                ev(3, "6.6.6.6", "block", "CC", "cc", "high")));
        Map<Object, Object> today = new java.util.HashMap<>();
        today.put("6.6.6.6", "300");
        today.put("7.7.7.7", "42");   // 窗口外的 IP
        LocalDate now = LocalDate.now(ZONE);
        when(hashOps.entries(cntKey(now))).thenReturn(today);
        when(hashOps.entries(cntKey(now.minusDays(1)))).thenReturn(Collections.emptyMap());
        List<Map<String, Object>> rows = rowsOf(service.summary(50));
        assertEquals(2, rows.size());
        Map<String, Object> seven = rows.stream()
                .filter(r -> "7.7.7.7".equals(r.get("ip"))).findFirst().orElseThrow();
        assertEquals(42L, seven.get("count"));
        assertTrue(((List<String>) seven.get("categories")).isEmpty()); // 无样本画像
        assertEquals(0L, seven.get("firstSeen"));
    }

    @Test
    void bucketsMergeTodayAndYesterday() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(null);
        LocalDate now = LocalDate.now(ZONE);
        when(hashOps.entries(cntKey(now))).thenReturn(Map.of("1.1.1.1", (Object) "100"));
        when(hashOps.entries(cntKey(now.minusDays(1)))).thenReturn(Map.of("1.1.1.1", (Object) "250"));
        List<Map<String, Object>> rows = rowsOf(service.summary(50));
        assertEquals(1, rows.size());
        assertEquals(350L, rows.get(0).get("count")); // 今天+昨天合并
    }

    // ---------------- ipDetail ----------------

    @Test
    void ipDetailBuildsTimelineAndStageFlow() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                ev(300, "1.2.3.4", "block", "RCE", "5", "critical"),
                ev(100, "1.2.3.4", "log", "Scanner", "8", "low"),
                ev(200, "1.2.3.4", "block", "SQLi", "1", "high"),
                ev(150, "8.8.8.8", "block", "XSS", "3", "high"))); // 其他 IP 应被过滤

        Map<String, Object> d = service.ipDetail("1.2.3.4");
        assertEquals(3L, d.get("count"));
        assertEquals(100L, d.get("firstSeen"));
        assertEquals(300L, d.get("lastSeen"));
        // 阶段迁移流: 时间序首次出现 recon → exploit → intrusion
        assertEquals(List.of("recon", "exploit", "intrusion"), d.get("stageFlow"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> tl = (List<Map<String, Object>>) d.get("timeline");
        assertEquals(3, tl.size());
        assertEquals(100L, tl.get(0).get("ts")); // 升序
        assertEquals("Scanner", tl.get(0).get("category"));
        assertEquals("recon", tl.get(0).get("stage"));
        assertEquals(300L, tl.get(2).get("ts"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rules = (List<Map<String, Object>>) d.get("topRules");
        assertEquals(3, rules.size()); // 3 条不同规则各 1 次
    }

    @Test
    void ipDetailNotFound() {
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(List.of(
                ev(1, "1.1.1.1", "block", "SQLi", "1", "high")));
        BusinessException e = assertThrows(BusinessException.class, () -> service.ipDetail("2.2.2.2"));
        assertTrue(e.getMessage().contains("未观察到"));
    }

    @Test
    void ipDetailRejectsIllegalIp() {
        assertThrows(BusinessException.class, () -> service.ipDetail("'; DROP--"));
        assertThrows(BusinessException.class, () -> service.ipDetail(""));
        assertThrows(BusinessException.class, () -> service.ipDetail("1.1.1.1; rm -rf /"));
    }

    // ---------------- 阶段/权重映射 ----------------

    @Test
    void stageMapping() {
        assertEquals("recon", TraceService.stageOf("Scanner"));
        assertEquals("recon", TraceService.stageOf("InfoLeak"));
        assertEquals("exploit", TraceService.stageOf("SQLi"));
        assertEquals("exploit", TraceService.stageOf("AuthBypass"));
        assertEquals("intrusion", TraceService.stageOf("RCE"));
        assertEquals("intrusion", TraceService.stageOf("Deserialization"));
        assertEquals("impact", TraceService.stageOf("Tamper"));
        assertEquals("impact", TraceService.stageOf("CC"));
        assertEquals("other", TraceService.stageOf("未知类型"));
    }

    @Test
    void severityWeights() {
        assertEquals(10, TraceService.severityWeight("critical"));
        assertEquals(5, TraceService.severityWeight("high"));
        assertEquals(2, TraceService.severityWeight("medium"));
        assertEquals(1, TraceService.severityWeight("low"));
        assertEquals(0, TraceService.severityWeight(""));
    }

    @Test
    void riskScoreCappedAt100() {
        // 构造 30 条 critical 事件: 30*10 + 3*1 + 20(频率) = 333 → cap 100
        List<String> evs = new java.util.ArrayList<>();
        for (int i = 0; i < 30; i++) evs.add(ev(1000 + i, "6.6.6.6", "block", "RCE", "5", "critical"));
        when(listOps.range(TraceService.K_EVENTS, 0, -1)).thenReturn(evs);
        Map<String, Object> row = rowsOf(service.summary(10)).get(0);
        assertEquals(100, row.get("riskScore"));
        assertEquals("严重", row.get("level"));
    }
}
