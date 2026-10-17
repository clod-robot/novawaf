package com.novawaf.admin.service;

import com.novawaf.admin.common.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** TamperService 单测: 配置下发校验 / purge 通道 / 页面索引解析(Mockito, 无 Spring 容器) */
@ExtendWith(MockitoExtension.class)
class TamperServiceTest {

    @Mock private StringRedisTemplate redis;
    @Mock private ValueOperations<String, String> valueOps;
    @Mock private ListOperations<String, String> listOps;

    private TamperService service;

    @BeforeEach
    void setUp() {
        service = new TamperService(redis);
        lenient().when(redis.opsForValue()).thenReturn(valueOps);
        lenient().when(redis.opsForList()).thenReturn(listOps);
    }

    // ---------------- config 查询 ----------------

    @Test
    void configReturnsDefaultsWhenEmpty() {
        when(valueOps.get(TamperService.K_CONFIG)).thenReturn(null);
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn(null);
        Map<String, Object> cfg = service.config();
        assertEquals(false, cfg.get("enabled"));
        assertEquals(3600, cfg.get("ttl"));
        assertEquals(256 * 1024, cfg.get("maxBody"));
        assertEquals(0L, cfg.get("cfgver"));
    }

    @Test
    void configMergesStoredJson() {
        when(valueOps.get(TamperService.K_CONFIG))
                .thenReturn("{\"enabled\":true,\"ttl\":60,\"maxBody\":4096,\"maxPages\":8,\"prefixes\":[\"/news\"]}");
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn("7");
        Map<String, Object> cfg = service.config();
        assertEquals(true, cfg.get("enabled"));
        assertEquals(60, cfg.get("ttl"));
        assertEquals(7L, cfg.get("cfgver"));
    }

    // ---------------- saveConfig 校验 ----------------

    @Test
    void saveConfigWritesJsonAndBumpsVersion() {
        when(valueOps.get(TamperService.K_CONFIG)).thenReturn(null);
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn(null, "3");
        Map<String, Object> out = service.saveConfig(Map.of(
                "enabled", true, "ttl", 120, "prefixes", List.of("/", "/news")));

        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(valueOps).set(eq(TamperService.K_CONFIG), json.capture());
        assertTrue(json.getValue().contains("\"enabled\":true"));
        assertTrue(json.getValue().contains("\"ttl\":120"));
        assertTrue(json.getValue().contains("\"/news\""));
        verify(valueOps).increment(TamperService.K_CFGVER); // 引擎 5s 内热加载
        assertEquals(3L, out.get("cfgver"));
    }

    @Test
    void saveConfigRejectsTtlOutOfRange() {
        when(valueOps.get(TamperService.K_CONFIG)).thenReturn(null);
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn(null);
        BusinessException e = assertThrows(BusinessException.class,
                () -> service.saveConfig(Map.of("ttl", 99999)));
        assertTrue(e.getMessage().contains("ttl"));
        verify(valueOps, never()).set(eq(TamperService.K_CONFIG), anyString());
    }

    @Test
    void saveConfigRejectsBadPrefix() {
        when(valueOps.get(TamperService.K_CONFIG)).thenReturn(null);
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn(null);
        assertThrows(BusinessException.class,
                () -> service.saveConfig(Map.of("prefixes", List.of("news"))));      // 缺 /
        assertThrows(BusinessException.class,
                () -> service.saveConfig(Map.of("prefixes", List.of("/a/../b"))));   // 含 ..
        verify(valueOps, never()).set(eq(TamperService.K_CONFIG), anyString());
    }

    @Test
    void saveConfigKeepsCurrentWhenFieldAbsent() {
        when(valueOps.get(TamperService.K_CONFIG))
                .thenReturn("{\"enabled\":true,\"ttl\":60,\"maxBody\":4096,\"maxPages\":8,\"prefixes\":[\"/n\"]}");
        when(valueOps.get(TamperService.K_CFGVER)).thenReturn(null, "1");
        Map<String, Object> out = service.saveConfig(Map.of("ttl", 90)); // 只改 ttl
        assertEquals(true, out.get("enabled"));
        assertEquals(90L, out.get("ttl"));
        assertEquals(4096L, out.get("maxBody"));
    }

    // ---------------- purge ----------------

    @Test
    void purgeAllOnlyEnqueues() {
        Map<String, Object> r = service.purge("all");
        verify(listOps).rightPush(TamperService.K_PURGE, "all");
        verify(redis, never()).delete(anyString()); // 全量重学交给引擎, 管理端不逐页删
        assertEquals(-1L, r.get("indexRemoved"));
    }

    @Test
    void purgeByIdDeletesPageAndIndexEntry() {
        when(valueOps.get(TamperService.K_INDEX)).thenReturn(
                "[{\"id\":\"0123456789abcdef\",\"host\":\"h\",\"path\":\"/a\",\"ts\":1,\"size\":10},"
              + "{\"id\":\"fedcba9876543210\",\"host\":\"h\",\"path\":\"/b\",\"ts\":2,\"size\":20}]");
        Map<String, Object> r = service.purge("0123456789abcdef");
        verify(listOps).rightPush(TamperService.K_PURGE, "0123456789abcdef");
        verify(redis).delete(TamperService.K_PAGE_PREFIX + "0123456789abcdef");
        ArgumentCaptor<String> idx = ArgumentCaptor.forClass(String.class);
        verify(valueOps).set(eq(TamperService.K_INDEX), idx.capture());
        assertFalse(idx.getValue().contains("0123456789abcdef"));
        assertTrue(idx.getValue().contains("fedcba9876543210"));
        assertEquals(1L, r.get("indexRemoved"));
    }

    @Test
    void purgeRejectsInvalidId() {
        assertThrows(BusinessException.class, () -> service.purge(""));
        assertThrows(BusinessException.class, () -> service.purge("not-hex"));
        assertThrows(BusinessException.class, () -> service.purge("0123456789ABCDEF")); // 必须小写
        assertThrows(BusinessException.class, () -> service.purge("'; DROP--"));        // 注入尝试
        verify(listOps, never()).rightPush(anyString(), anyString());
    }

    // ---------------- pages / stats ----------------

    @Test
    void pagesParsesIndex() {
        when(valueOps.get(TamperService.K_INDEX))
                .thenReturn("[{\"id\":\"a\",\"host\":\"h\",\"path\":\"/\",\"ts\":1,\"size\":2}]");
        assertEquals(1, service.pages().size());
    }

    @Test
    void pagesEmptyWhenMissing() {
        when(valueOps.get(TamperService.K_INDEX)).thenReturn(null);
        assertTrue(service.pages().isEmpty());
    }
}
