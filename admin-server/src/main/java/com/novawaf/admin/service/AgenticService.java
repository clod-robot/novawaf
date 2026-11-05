package com.novawaf.admin.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.AgenticConfig;
import com.novawaf.admin.mapper.AgenticConfigMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agentic AI 引擎服务：大模型研判未知 API 威胁。
 * - 配置：MySQL 单行 → Redis novawaf:ai:agentic + INCR 版本号，引擎 5s 内热加载；
 * - 轨迹：读取引擎 RPUSH 的 novawaf:ai:agentic:traces（环形保留），按时间倒序展示。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AgenticService {

    public static final String CONFIG_KEY = "novawaf:ai:agentic";
    public static final String CONFIG_VERSION = "novawaf:ai:agentic:version";
    public static final String TRACE_KEY = "novawaf:ai:agentic:traces";

    private final AgenticConfigMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    public AgenticConfig config() {
        AgenticConfig c = mapper.selectSingleton();
        if (c == null) {
            c = new AgenticConfig();
            c.setId(1L);
            c.setEnabled(false);
            c.setBlock(false);
            c.setThreshold(0.6);
            c.setMaxSteps(4);
            c.setBudgetPerMin(20);
            c.setCacheTtlSec(300);
            c.setTraceMax(2000);
            c.setLlmEnabled(false);
            c.setLlmTimeoutMs(8000);
            c.setLlmMaxRetries(1);
            c.setLlmMaxTokens(512);
        }
        c.setLlmApiKeyMask(ApiGuardService.maskSecret(c.getLlmApiKey()));
        c.setLlmApiKey(null);   // 密钥不以明文出接口
        return c;
    }

    @Transactional
    public AgenticConfig saveConfig(AgenticConfig c) {
        if (c == null) throw new BusinessException("参数不能为空");
        AgenticConfig old = mapper.selectSingleton();
        double threshold = c.getThreshold() == null ? 0.6 : c.getThreshold();
        int maxSteps = c.getMaxSteps() == null ? 4 : c.getMaxSteps();
        int budget = c.getBudgetPerMin() == null ? 20 : c.getBudgetPerMin();
        int ttl = c.getCacheTtlSec() == null ? 300 : c.getCacheTtlSec();
        int traceMax = c.getTraceMax() == null ? 2000 : c.getTraceMax();
        int timeoutMs = c.getLlmTimeoutMs() == null ? 8000 : c.getLlmTimeoutMs();
        int retries = c.getLlmMaxRetries() == null ? 1 : c.getLlmMaxRetries();
        int maxTokens = c.getLlmMaxTokens() == null ? 512 : c.getLlmMaxTokens();
        if (threshold < 0.1 || threshold > 1.0) throw new BusinessException("判定阈值需在 0.1 ~ 1.0");
        if (maxSteps < 1 || maxSteps > 10) throw new BusinessException("代理循环最大步数需在 1 ~ 10");
        if (budget < 0 || budget > 2000) throw new BusinessException("每分钟调用预算需在 0 ~ 2000");
        if (ttl < 30 || ttl > 86400) throw new BusinessException("缓存 TTL 需在 30 ~ 86400 秒");
        if (traceMax < 100 || traceMax > 10000) throw new BusinessException("轨迹保留条数需在 100 ~ 10000");
        if (timeoutMs < 500 || timeoutMs > 60000) throw new BusinessException("模型调用超时需在 500 ~ 60000 毫秒");
        if (retries < 0 || retries > 5) throw new BusinessException("失败重试次数需在 0 ~ 5");
        if (maxTokens < 64 || maxTokens > 4096) throw new BusinessException("最大输出 token 需在 64 ~ 4096");
        String endpoint = c.getLlmEndpoint() == null ? "" : c.getLlmEndpoint().trim();
        if (!endpoint.isEmpty()) {
            if (endpoint.length() > 255 || !(endpoint.startsWith("http://") || endpoint.startsWith("https://"))) {
                throw new BusinessException("模型地址需为 http(s):// 开头的完整 URL，且不超过 255 字符");
            }
        }
        String model = c.getLlmModel() == null ? "" : c.getLlmModel().trim();
        if (model.length() > 64) throw new BusinessException("模型名不能超过 64 字符");

        // 前端回传脱敏值时保留原密钥
        String key = c.getLlmApiKey();
        if (key == null || key.isEmpty() || key.contains("****")) {
            key = old == null ? null : old.getLlmApiKey();
        }
        if (key != null && key.length() > 512) throw new BusinessException("API Key 长度不能超过 512");

        AgenticConfig row = new AgenticConfig();
        row.setId(1L);
        row.setEnabled(Boolean.TRUE.equals(c.getEnabled()));
        row.setBlock(Boolean.TRUE.equals(c.getBlock()));
        row.setThreshold(threshold);
        row.setMaxSteps(maxSteps);
        row.setBudgetPerMin(budget);
        row.setCacheTtlSec(ttl);
        row.setTraceMax(traceMax);
        row.setLlmEnabled(Boolean.TRUE.equals(c.getLlmEnabled()));
        row.setLlmEndpoint(endpoint.isEmpty() ? null : endpoint);
        row.setLlmApiKey(key);
        row.setLlmModel(model.isEmpty() ? null : model);
        row.setLlmTimeoutMs(timeoutMs);
        row.setLlmMaxRetries(retries);
        row.setLlmMaxTokens(maxTokens);
        if (old == null) mapper.insertSingleton(row);
        else mapper.updateSingleton(row);

        publish(row);
        return config();
    }

    /** 发布配置：{"enabled","block","threshold","maxSteps","budgetPerMin","cacheTtlSec","traceMax","traceKey","llm":{...}} */
    private void publish(AgenticConfig c) {
        try {
            ObjectNode root = om.createObjectNode();
            root.put("enabled", Boolean.TRUE.equals(c.getEnabled()));
            root.put("block", Boolean.TRUE.equals(c.getBlock()));
            root.put("threshold", c.getThreshold());
            root.put("maxSteps", c.getMaxSteps());
            root.put("budgetPerMin", c.getBudgetPerMin());
            root.put("cacheTtlSec", c.getCacheTtlSec());
            root.put("traceMax", c.getTraceMax());
            root.put("traceKey", TRACE_KEY);
            ObjectNode llm = om.createObjectNode();
            llm.put("enabled", Boolean.TRUE.equals(c.getLlmEnabled()));
            llm.put("endpoint", c.getLlmEndpoint() == null ? "" : c.getLlmEndpoint());
            llm.put("apiKey", c.getLlmApiKey() == null ? "" : c.getLlmApiKey());
            llm.put("model", c.getLlmModel() == null ? "" : c.getLlmModel());
            llm.put("timeoutMs", c.getLlmTimeoutMs());
            llm.put("maxRetries", c.getLlmMaxRetries());
            llm.put("maxTokens", c.getLlmMaxTokens());
            root.set("llm", llm);
            redis.opsForValue().set(CONFIG_KEY, om.writeValueAsString(root));
            Long ver = redis.opsForValue().increment(CONFIG_VERSION);
            log.info("Agentic AI 配置已发布: enabled={}, block={}, llm={}, version={}",
                    c.getEnabled(), c.getBlock(), c.getLlmEnabled(), ver);
        } catch (Exception e) {
            throw new BusinessException(500, "配置已保存但发布到引擎失败：" + e.getMessage());
        }
    }

    /** 最近研判轨迹（倒序，最新在前）。 */
    public Map<String, Object> traces(int limit) {
        int n = Math.min(500, Math.max(1, limit));
        List<Map<String, Object>> out = new ArrayList<>();
        long total = 0;
        try {
            Long size = redis.opsForList().size(TRACE_KEY);
            total = size == null ? 0 : size;
            List<String> raw = redis.opsForList().range(TRACE_KEY, -n, -1);
            if (raw != null) {
                // Redis 列表头旧尾新，倒序遍历给出最新优先
                for (int i = raw.size() - 1; i >= 0; i--) {
                    Map<String, Object> m = parseTrace(raw.get(i));
                    if (m != null) out.add(m);
                }
            }
        } catch (Exception e) {
            log.warn("读取 Agentic 轨迹失败: {}", e.getMessage());
        }
        // 兜底：引擎可能把空数组轨迹写成 []，解析失败的条目直接跳过
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("total", total);
        r.put("items", out);
        return r;
    }

    private Map<String, Object> parseTrace(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return om.readValue(raw, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            return null;
        }
    }

    public void clearTraces() {
        try {
            redis.delete(TRACE_KEY);
        } catch (Exception e) {
            throw new BusinessException(500, "清空轨迹失败：" + e.getMessage());
        }
    }
}
