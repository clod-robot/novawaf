package com.novawaf.admin.service;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.IpGroup;
import com.novawaf.admin.mapper.IpGroupMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IpGroupService 集成行为单测（Mockito mock mapper/redis，无 Spring 容器）：
 * 同名唯一校验（create/update）与 addEntries 导入后触发生效通道同步。
 */
@ExtendWith(MockitoExtension.class)
class IpGroupServiceBehaviorTest {

    @Mock
    private IpGroupMapper mapper;
    @Mock
    private StringRedisTemplate redis;
    @Mock
    private ValueOperations<String, String> valueOps;
    @Mock
    private SetOperations<String, String> setOps;

    private IpGroupService service;

    @BeforeEach
    void setUp() {
        service = new IpGroupService(mapper, redis);
        lenient().when(redis.opsForValue()).thenReturn(valueOps);
        lenient().when(redis.opsForSet()).thenReturn(setOps);
    }

    private static IpGroup group(Long id, String name, String type, String action) {
        IpGroup g = new IpGroup();
        g.setId(id);
        g.setName(name);
        g.setType(type);
        g.setAction(action);
        g.setEnabled(true);
        return g;
    }

    // ---------------- 同名唯一校验 ----------------

    @Test
    void createRejectsDuplicatedName() {
        IpGroup req = group(null, "办公网", "custom", "block");
        when(mapper.selectByName("办公网")).thenReturn(group(1L, "办公网", "custom", "block"));

        BusinessException e = assertThrows(BusinessException.class, () -> service.create(req));
        assertTrue(e.getMessage().contains("同名"));
        verify(mapper, never()).insert(any());
    }

    @Test
    void createAllowsUniqueName() {
        IpGroup req = group(null, "办公网", "custom", "block");
        when(mapper.selectByName("办公网")).thenReturn(null);
        // 模拟 MyBatis useGeneratedKeys 回填自增 id
        doAnswer(inv -> { ((IpGroup) inv.getArgument(0)).setId(7L); return 1; })
                .when(mapper).insert(any(IpGroup.class));
        when(mapper.selectById(any())).thenReturn(group(7L, "办公网", "custom", "block"));
        when(setOps.members(anyString())).thenReturn(java.util.Set.of());

        service.create(req);
        verify(mapper).insert(any(IpGroup.class));
    }

    @Test
    void updateRejectsOtherGroupWithSameName() {
        IpGroup req = group(null, "新名字", "custom", "block");
        when(mapper.selectById(1L)).thenReturn(group(1L, "旧名字", "custom", "block"));
        when(mapper.selectByName("新名字")).thenReturn(group(2L, "新名字", "custom", "block"));

        BusinessException e = assertThrows(BusinessException.class, () -> service.update(1L, req));
        assertTrue(e.getMessage().contains("同名"));
        verify(mapper, never()).update(any());
    }

    @Test
    void updateAllowsSameNameOnItself() {
        IpGroup req = group(null, "办公网", "custom", "block");
        IpGroup self = group(1L, "办公网", "custom", "block");
        when(mapper.selectById(1L)).thenReturn(self);
        when(mapper.selectByName("办公网")).thenReturn(self);
        when(setOps.members(anyString())).thenReturn(java.util.Set.of());

        service.update(1L, req);
        verify(mapper).update(any(IpGroup.class));
    }

    // ---------------- addEntries 导入触发生效通道同步 ----------------

    @Test
    void addEntriesTriggersChannelResyncForBlockGroup() {
        IpGroup g = group(3L, "威胁组", "custom", "block");
        when(mapper.selectById(3L)).thenReturn(g);
        when(setOps.size(anyString())).thenReturn(0L);
        when(setOps.add(anyString(), any(String[].class))).thenReturn(2L);
        when(setOps.members(anyString())).thenReturn(java.util.Set.of("1.1.1.1", "2.2.2.2"));
        when(valueOps.get(IpListService.BLACK)).thenReturn(null);

        long added = service.addEntries(3L, "1.1.1.1\n2.2.2.2\n");
        assertEquals(2, added);
        // resync 副作用：黑名单被重写 + 版本号递增（引擎 3s 热加载）
        verify(valueOps).set(eq(IpListService.BLACK), contains("group:3"));
        verify(valueOps).increment("novawaf:iplist:version");
    }

    @Test
    void addEntriesRejectsEmptyContent() {
        when(mapper.selectById(3L)).thenReturn(group(3L, "g", "custom", "block"));
        assertThrows(BusinessException.class, () -> service.addEntries(3L, "# 只有注释\n\n"));
        verify(valueOps, never()).set(anyString(), anyString());
    }
}
