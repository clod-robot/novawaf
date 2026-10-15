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

import java.util.List;
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

    private static final Set<String> ACTIONS = Set.of("block", "log", "pass");
    // 仅允许路径安全字符：字母数字与 / _ - . { } : ? % ~ *；杜绝空白、引号、<>、分号、反斜杠、控制字符等。
    private static final Pattern SAFE_PREFIX = Pattern.compile("^/[A-Za-z0-9_\\-./{}:?%~*]*$");

    private final ApiPolicyMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    public List<ApiPolicy> list() {
        return mapper.selectAll();
    }

    @Transactional
    public void add(ApiPolicy p) {
        validate(p);
        if (mapper.countByPrefix(p.getPrefix(), null) > 0) {
            throw new BusinessException("该路径策略已存在：" + p.getPrefix());
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
        if (mapper.countByPrefix(p.getPrefix(), p.getId()) > 0) {
            throw new BusinessException("该路径已被其它策略占用：" + p.getPrefix());
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
        publish();
    }

    private void validate(ApiPolicy p) {
        if (p == null) throw new BusinessException("参数不能为空");
        String name = p.getName() == null ? "" : p.getName().trim();
        String prefix = p.getPrefix() == null ? "" : p.getPrefix().trim();
        String action = p.getAction() == null ? "" : p.getAction().trim().toLowerCase();
        if (name.isEmpty() || name.length() > 64) {
            throw new BusinessException("名称必填且长度不能超过 64");
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
