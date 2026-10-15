package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.SafeExec;
import com.novawaf.admin.entity.DeployConfig;
import com.novawaf.admin.mapper.DeployConfigMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 部署方式服务：
 * - HA 配置：MySQL 单行表为真值，保存后发布到 Redis（novawaf:deploy:config + version）；
 * - NAT 探测结果：读取 novawaf:deploy:nat（离线脚本与本服务共用同一 key），
 *   或以固定 argv 受控执行 detect_nat.py 后回写。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeployService {

    public static final String CONFIG_KEY = "novawaf:deploy:config";
    public static final String CONFIG_VERSION_KEY = "novawaf:deploy:config:version";
    public static final String NAT_KEY = "novawaf:deploy:nat";

    private static final Set<String> HA_MODES = Set.of("single", "master-backup", "cluster");
    private static final Set<String> NODE_ROLES = Set.of("master", "backup", "node");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern NODE_NAME = Pattern.compile("^[\\w.\\-\\u4e00-\\u9fa5 ]{1,64}$");
    private static final int MAX_NODES = 64;
    private static final int OUTPUT_LIMIT = 262144;

    private final DeployConfigMapper mapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /** 探测脚本绝对路径，由 application.yml 提供（nova.deploy.detect-script），留空则禁用一键探测 */
    @Value("${nova.deploy.detect-script:}")
    private String detectScript;

    @Value("${nova.deploy.detect-timeout-ms:10000}")
    private long detectTimeoutMs;

    /** 聚合返回：HA 配置 + 最近一次 NAT 探测结果（从未探测时 nat=null）。 */
    public Map<String, Object> get() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("ha", loadHa());
        data.put("nat", readNat());
        return data;
    }

    private Map<String, Object> loadHa() {
        DeployConfig c = mapper.selectSingleton();
        Map<String, Object> ha = new LinkedHashMap<>();
        if (c == null) {
            ha.put("haMode", "single");
            ha.put("vip", "");
            ha.put("nodes", "[]");
            ha.put("remark", "");
            return ha;
        }
        ha.put("id", c.getId());
        ha.put("haMode", c.getHaMode());
        ha.put("vip", c.getVip() == null ? "" : c.getVip());
        ha.put("nodes", c.getNodes() == null ? "[]" : c.getNodes());
        ha.put("remark", c.getRemark() == null ? "" : c.getRemark());
        ha.put("createTime", c.getCreateTime());
        ha.put("updateTime", c.getUpdateTime());
        return ha;
    }

    /** 校验并保存 HA 配置（固定 id=1 upsert），成功后发布 Redis。 */
    @Transactional
    public DeployConfig saveHa(DeployConfig req) {
        DeployConfig c = normalize(req);
        if (mapper.selectSingleton() == null) {
            mapper.insertSingleton(c);
        } else {
            mapper.updateSingleton(c);
        }
        DeployConfig row = mapper.selectSingleton();
        publish(row);
        return row;
    }

    private DeployConfig normalize(DeployConfig req) {
        if (req == null) {
            throw new BusinessException("参数不能为空");
        }
        String mode = req.getHaMode() == null ? "" : req.getHaMode().trim().toLowerCase();
        if (!HA_MODES.contains(mode)) {
            throw new BusinessException("HA 模式只能是 single / master-backup / cluster");
        }

        String vip = req.getVip() == null ? "" : req.getVip().trim();
        if (!vip.isEmpty() && !isIpv4(vip)) {
            throw new BusinessException("VIP 必须是合法的 IPv4 地址（如 192.168.1.100）");
        }

        String remark = req.getRemark() == null ? "" : req.getRemark().trim();
        if (remark.length() > 255) {
            throw new BusinessException("备注长度不能超过 255");
        }

        String nodesJson = normalizeNodes(req.getNodes());

        DeployConfig c = new DeployConfig();
        c.setId(1L);
        c.setHaMode(mode);
        c.setVip(vip.isEmpty() ? null : vip);
        c.setNodes(nodesJson);
        c.setRemark(remark.isEmpty() ? null : remark);
        return c;
    }

    /** 校验 nodes JSON 数组并重新序列化为规范 JSON（脏数据不允许入库）。 */
    private String normalizeNodes(String raw) {
        String text = raw == null ? "" : raw.trim();
        if (text.isEmpty()) {
            text = "[]";
        }
        JsonNode node;
        try {
            node = om.readTree(text);
        } catch (Exception e) {
            throw new BusinessException("节点列表不是合法 JSON");
        }
        if (node == null || !node.isArray()) {
            throw new BusinessException("节点列表必须是 JSON 数组");
        }
        ArrayNode arr = (ArrayNode) node;
        if (arr.size() > MAX_NODES) {
            throw new BusinessException("节点数量不能超过 " + MAX_NODES);
        }
        ArrayNode canonical = om.createArrayNode();
        for (JsonNode n : arr) {
            if (n == null || !n.isObject()) {
                throw new BusinessException("每个节点必须是对象 {name,ip,role,priority,enabled}");
            }
            String name = n.path("name").asText("").trim();
            String ip = n.path("ip").asText("").trim();
            String role = n.path("role").asText("").trim().toLowerCase();
            if (!NODE_NAME.matcher(name).matches()) {
                throw new BusinessException("节点名称必填，仅允许中英文/数字及 _-. 空格，长度不超过 64");
            }
            if (!isIpv4(ip)) {
                throw new BusinessException("节点 IP 必须是合法 IPv4：" + name);
            }
            if (!NODE_ROLES.contains(role)) {
                throw new BusinessException("节点角色只能是 master / backup / node：" + name);
            }
            int priority = n.hasNonNull("priority") ? n.get("priority").asInt(-1) : 100;
            if (priority < 0 || priority > 1000) {
                throw new BusinessException("节点优先级取值 0-1000：" + name);
            }
            boolean enabled = !n.has("enabled") || n.get("enabled").asBoolean(true);

            ObjectNode item = om.createObjectNode();
            item.put("name", name);
            item.put("ip", ip);
            item.put("role", role);
            item.put("priority", priority);
            item.put("enabled", enabled);
            canonical.add(item);
        }
        try {
            return om.writeValueAsString(canonical);
        } catch (Exception e) {
            throw new BusinessException(500, "节点列表序列化失败");
        }
    }

    private static boolean isIpv4(String s) {
        var m = IPV4.matcher(s);
        if (!m.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            if (Integer.parseInt(m.group(i)) > 255) {
                return false;
            }
        }
        return true;
    }

    /** 发布 HA 配置到 Redis 并递增版本号（MySQL 已改但发布失败需让调用方感知）。 */
    private void publish(DeployConfig c) {
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("haMode", c.getHaMode());
            payload.put("vip", c.getVip());
            payload.put("nodes", om.readValue(c.getNodes(), Object.class));
            payload.put("remark", c.getRemark());
            payload.put("updateTime", c.getUpdateTime() == null ? System.currentTimeMillis() : c.getUpdateTime().getTime());
            redis.opsForValue().set(CONFIG_KEY, om.writeValueAsString(payload));
            redis.opsForValue().increment(CONFIG_VERSION_KEY);
            log.info("HA 部署配置已发布: haMode={}, version key={}", c.getHaMode(), CONFIG_VERSION_KEY);
        } catch (Exception e) {
            throw new BusinessException(500, "HA 配置已保存但发布到 Redis 失败：" + e.getMessage());
        }
    }

    private Object readNat() {
        String raw = redis.opsForValue().get(NAT_KEY);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return om.readValue(raw, Object.class);
        } catch (Exception e) {
            log.warn("NAT 探测结果解析失败，忽略: {}", e.toString());
            return null;
        }
    }

    /**
     * 一键探测：固定 argv 执行 python3 &lt;配置内绝对路径脚本&gt;，无 shell、有超时、输出封顶。
     * 脚本输出 JSON 写回 novawaf:deploy:nat 并返回；脚本不可自行接受外部传入参数。
     */
    public Object detectNat() {
        if (detectScript == null || detectScript.isBlank()) {
            throw new BusinessException(500, "探测脚本路径未配置(nova.deploy.detect-script)");
        }
        Path script = Path.of(detectScript);
        if (!Files.isRegularFile(script)) {
            throw new BusinessException(500, "探测脚本未安装：" + detectScript);
        }
        String out = SafeExec.run(List.of("python3", detectScript), detectTimeoutMs, OUTPUT_LIMIT);
        String json = extractJson(out);
        JsonNode node;
        try {
            node = om.readTree(json);
        } catch (Exception e) {
            throw new BusinessException(500, "探测脚本输出不是合法 JSON");
        }
        if (node == null || !node.hasNonNull("natType")) {
            throw new BusinessException(500, "探测脚本输出缺少 natType 字段");
        }
        redis.opsForValue().set(NAT_KEY, json);
        try {
            return om.readValue(json, Object.class);
        } catch (Exception e) {
            throw new BusinessException(500, "探测结果回读失败");
        }
    }

    /** 脚本理论上只输出 JSON；兼容误带前后置日志行的情况，截取首个 { 到末个 }。 */
    private static String extractJson(String out) {
        if (out == null) {
            throw new BusinessException(500, "探测脚本无输出");
        }
        String t = out.trim();
        int l = t.indexOf('{');
        int r = t.lastIndexOf('}');
        if (l < 0 || r <= l) {
            throw new BusinessException(500, "探测脚本输出中未找到 JSON");
        }
        return t.substring(l, r + 1);
    }
}
