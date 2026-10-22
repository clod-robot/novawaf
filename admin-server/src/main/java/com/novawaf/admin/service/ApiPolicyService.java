package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.ApiPolicy;
import com.novawaf.admin.mapper.ApiPolicyMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * API 路径防护策略服务：MySQL 为真值，保存后自动整表发布到 Redis 并递增版本号，
 * 引擎在 3s 内热加载（保存即发布）。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiPolicyService {

    /** 引擎读取的策略数据与版本键（与 C++ PathPolicy 约定一致）。 */
    public static final String REDIS_KEY = "novawaf:pathpolicy";
    public static final String VERSION_KEY = "novawaf:pathpolicy:version";
    /** 引擎按策略累计的命中/拦截/放行次数：HASH 字段 {id}|hit / {id}|blk / {id}|pass */
    public static final String STAT_KEY = "novawaf:pathpolicy:stat";

    private static final Set<String> ACTIONS = Set.of("block", "log", "pass");
    // 仅允许路径安全字符：字母数字与 / _ - . { } : ? % ~ *；杜绝空白、引号、<>、分号、反斜杠、控制字符等。
    private static final Pattern SAFE_PREFIX = Pattern.compile("^/[A-Za-z0-9_\\-./{}:?%~*]*$");

    private final ApiPolicyMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /** 列表：补齐所属应用名称 + 引擎累计的访问/拦截/放行次数（展示用，不落库） */
    public List<ApiPolicy> list() {
        List<ApiPolicy> all = mapper.selectAll();
        Map<String, String> appNames = appNames();
        Map<Object, Object> stats = Map.of();
        try { stats = redis.opsForHash().entries(STAT_KEY); } catch (Exception ignore) { }
        for (ApiPolicy p : all) {
            String aid = p.getAppId();
            p.setAppName(aid == null || aid.isBlank() ? "全部应用" : appNames.getOrDefault(aid, "应用-" + aid));
            p.setHitCount(toLong(stats.get(p.getId() + "|hit")));
            p.setBlockCount(toLong(stats.get(p.getId() + "|blk")));
            p.setPassCount(toLong(stats.get(p.getId() + "|pass")));
        }
        return all;
    }

    /** 应用 id -> 名称（来自引擎应用注册表 novawaf:apps） */
    @SuppressWarnings("unchecked")
    private Map<String, String> appNames() {
        Map<String, String> m = new HashMap<>();
        try {
            Object obj = om.readValue(String.valueOf(redis.opsForValue().get("novawaf:apps")), Object.class);
            if (obj instanceof List) {
                for (Object o : (List<Object>) obj) {
                    if (!(o instanceof Map)) continue;
                    Map<String, Object> a = (Map<String, Object>) o;
                    String id = str(a.get("id"));
                    if (!id.isEmpty()) m.put(id, str(a.get("name")).isEmpty() ? "应用-" + id : str(a.get("name")));
                }
            }
        } catch (Exception ignore) { }
        return m;
    }

    private static long toLong(Object o) {
        if (o instanceof Number) return ((Number) o).longValue();
        try { return Long.parseLong(str(o)); } catch (Exception e) { return 0L; }
    }

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    @Transactional
    public void add(ApiPolicy p) {
        validate(p);
        if (mapper.countByPrefix(p.getPrefix(), p.getAppId(), null) > 0) {
            throw new BusinessException("该应用下路径策略已存在：" + scopeText(p) + p.getPrefix());
        }
        if (p.getEnabled() == null) p.setEnabled(true);
        mapper.insert(p);
        publish();
    }

    @Transactional
    public void update(ApiPolicy p) {
        if (p.getId() == null || mapper.selectById(p.getId()) == null) {
            throw new BusinessException("策略不存在或已被删除");
        }
        validate(p);
        if (mapper.countByPrefix(p.getPrefix(), p.getAppId(), p.getId()) > 0) {
            throw new BusinessException("该应用下路径已被其它策略占用：" + scopeText(p) + p.getPrefix());
        }
        if (p.getEnabled() == null) p.setEnabled(true);
        mapper.update(p);
        publish();
    }

    @Transactional
    public void toggle(Long id, Boolean enabled) {
        if (id == null || mapper.selectById(id) == null) {
            throw new BusinessException("策略不存在或已被删除");
        }
        mapper.updateEnabled(id, Boolean.TRUE.equals(enabled));
        publish();
    }

    @Transactional
    public void delete(Long id) {
        if (id == null || mapper.selectById(id) == null) {
            throw new BusinessException("策略不存在或已被删除");
        }
        mapper.deleteById(id);
        // 同步清理该策略的计数，避免 ID 复用时继承历史数据
        try { redis.opsForHash().delete(STAT_KEY, id + "|hit", id + "|blk", id + "|pass"); } catch (Exception ignore) { }
        publish();
    }

    /** 作用域描述（用于提示文案） */
    private String scopeText(ApiPolicy p) {
        String aid = p.getAppId();
        if (aid == null || aid.isBlank()) return "全部应用 ";
        return appNames().getOrDefault(aid, "应用-" + aid) + " ";
    }

    private void validate(ApiPolicy p) {
        if (p == null) throw new BusinessException("参数不能为空");
        String name = p.getName() == null ? "" : p.getName().trim();
        String prefix = p.getPrefix() == null ? "" : p.getPrefix().trim();
        String action = p.getAction() == null ? "" : p.getAction().trim().toLowerCase();
        String appId = p.getAppId() == null ? "" : p.getAppId().trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new BusinessException("名称必填且长度不能超过 64");
        }
        // 所属应用：可空(全部应用)；非空时必须存在于引擎应用注册表
        if (!appId.isEmpty() && (appId.length() > 32 || !appNames().containsKey(appId))) {
            throw new BusinessException("所属应用不存在或非法：" + appId);
        }
        if (prefix.isEmpty() || prefix.length() > 255 || !SAFE_PREFIX.matcher(prefix).matches()) {
            throw new BusinessException("路径必须以 / 开头，仅允许字母数字及 / _ - . { } : ? % ~ * ，长度不超过 255");
        }
        // 纵深防御：拒绝目录穿越片段；通配符 * 仅允许出现在末尾（其余位置永不命中，属畸形配置）
        if (prefix.contains("..")) {
            throw new BusinessException("路径不允许包含 .. 目录穿越片段");
        }
        int star = prefix.indexOf('*');
        if (star >= 0 && star != prefix.length() - 1) {
            throw new BusinessException("通配符 * 仅允许出现在路径末尾");
        }
        if (!ACTIONS.contains(action)) {
            throw new BusinessException("动作只能是 block / log / pass");
        }
        if (p.getRemark() != null && p.getRemark().length() > 255) {
            throw new BusinessException("备注长度不能超过 255");
        }
        p.setName(name);
        p.setPrefix(prefix);
        p.setAction(action);
        p.setAppId(appId.isEmpty() ? null : appId);
    }

    /** 整表序列化为 JSON 发布到 Redis，并递增版本号触发引擎热加载。 */
    private void publish() {
        try {
            List<ApiPolicy> all = mapper.selectAll();
            redis.opsForValue().set(REDIS_KEY, om.writeValueAsString(all));
            Long ver = redis.opsForValue().increment(VERSION_KEY);
            log.info("API路径防护策略已发布: {} 条, version={}", all.size(), ver);
        } catch (Exception e) {
            // 发布失败需让调用方感知（数据库已改但引擎未同步），避免“看似已保存实则未生效”
            throw new BusinessException(500, "策略已保存但发布到引擎失败：" + e.getMessage());
        }
    }
}
