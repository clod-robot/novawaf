package com.novawaf.admin.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GeoService 纯函数单元测试：IP/CIDR 解析与归属匹配（黑白名单 GeoIP 联动核心逻辑）。
 * 不依赖 Spring / Redis，纯静态方法，覆盖正常、边界与非法输入。
 */
class GeoServiceTest {

    @Test
    void ipToUint_basic() {
        assertEquals(0x01020304L, GeoService.ipToUint("1.2.3.4"));
        assertEquals(0xFFFFFFFFL, GeoService.ipToUint("255.255.255.255"));
        assertEquals(0L, GeoService.ipToUint("0.0.0.0"));
    }

    @Test
    void ipToUint_invalid() {
        assertEquals(0, GeoService.ipToUint(null));
        assertEquals(0, GeoService.ipToUint(""));
        assertEquals(0, GeoService.ipToUint("1.2.3"));        // 段数不足
        assertEquals(0, GeoService.ipToUint("1.2.3.4.5"));    // 段数过多
        assertEquals(0, GeoService.ipToUint("256.1.1.1"));    // 越界
        assertEquals(0, GeoService.ipToUint("1.2.3.x"));      // 非数字
        assertEquals(0, GeoService.ipToUint("1.2.3.4/24"));   // 带掩码应交给 parseCidr
    }

    @Test
    void uintToIp_roundtrip() {
        for (String ip : new String[]{"0.0.0.0", "1.2.3.4", "10.0.0.1", "192.168.1.1", "255.255.255.255"}) {
            assertEquals(ip, GeoService.uintToIp(GeoService.ipToUint(ip)));
        }
    }

    @Test
    void parseCidr_singleIp() {
        long[] se = GeoService.parseCidr("8.8.8.8");
        assertNotNull(se);
        assertEquals(GeoService.ipToUint("8.8.8.8"), se[0]);
        assertEquals(se[0], se[1]);
    }

    @Test
    void parseCidr_range() {
        long[] se = GeoService.parseCidr("8.8.8.0/24");
        assertNotNull(se);
        assertEquals(GeoService.ipToUint("8.8.8.0"), se[0]);
        assertEquals(GeoService.ipToUint("8.8.8.255"), se[1]);

        long[] all = GeoService.parseCidr("0.0.0.0/0");
        assertNotNull(all);
        assertEquals(0L, all[0]);
        assertEquals(0xFFFFFFFFL, all[1]);

        long[] host = GeoService.parseCidr("1.2.3.4/32");
        assertNotNull(host);
        assertEquals(host[0], host[1]);
    }

    @Test
    void parseCidr_invalid() {
        assertNull(GeoService.parseCidr("1.2.3.4/33"));  // 掩码越界
        assertNull(GeoService.parseCidr("999.0.0.0/8"));  // 地址非法
        assertNull(GeoService.parseCidr("bad"));
    }

    @Test
    void inRange_exactIp() {
        assertTrue(GeoService.inRange("8.8.8.8", "8.8.8.8"));
        assertFalse(GeoService.inRange("8.8.8.8", "8.8.8.9"));
    }

    @Test
    void inRange_cidr() {
        assertTrue(GeoService.inRange("8.8.8.0/24", "8.8.8.8"));
        assertTrue(GeoService.inRange("8.8.8.0/24", "8.8.8.0"));
        assertTrue(GeoService.inRange("8.8.8.0/24", "8.8.8.255"));
        assertFalse(GeoService.inRange("8.8.8.0/24", "8.8.9.0"));
        assertFalse(GeoService.inRange("8.8.8.0/24", "8.8.7.255"));
        // /0 匹配所有合法 IP
        assertTrue(GeoService.inRange("0.0.0.0/0", "1.2.3.4"));
        // /32 退化为精确匹配
        assertTrue(GeoService.inRange("1.2.3.4/32", "1.2.3.4"));
        assertFalse(GeoService.inRange("1.2.3.4/32", "1.2.3.5"));
    }

    @Test
    void inRange_invalidInputs() {
        assertFalse(GeoService.inRange(null, "1.2.3.4"));
        assertFalse(GeoService.inRange("8.8.8.0/24", null));
        assertFalse(GeoService.inRange("8.8.8.0/24", "not-an-ip"));
        assertFalse(GeoService.inRange("1.2.3.4/33", "1.2.3.4"));
    }

    @Test
    void inRange_withWhitespace() {
        assertTrue(GeoService.inRange("  8.8.8.0/24  ", " 8.8.8.8 "));
    }
}
