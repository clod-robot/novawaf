package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.entity.ApiGuardConfig;
import com.novawaf.admin.entity.ApiGuardRule;
import com.novawaf.admin.entity.ApiToken;
import com.novawaf.admin.mapper.ApiGuardConfigMapper;
import com.novawaf.admin.mapper.ApiGuardRuleMapper;
import com.novawaf.admin.mapper.ApiTokenMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * API 级别防护服务：
 * - 限流策略：MySQL 真值 → 整表发布 Redis novawf:api:guard（含 Token 配置）+ INCR 版本号；
 * - 不透明令牌白名单 → Redis novawaf:api:tokens（JSON 字符串数组）；
 * - 响应脱敏 → Redis novawaf:dlp:config。
 * 引擎每 5s 比对版本号热加载，保存即发布。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiGuardService {

    public static final String GUARD_KEY = "novawaf:api:guard";
    public static final String GUARD_VERSION = "novawaf:api:guard:version";
    public static final String TOKEN_KEY = "novawaf:api:tokens";
    public static final String TOKEN_VERSION = "novawaf:api:tokens:version";
    public static final String DLP_KEY = "novawaf:dlp:config";
    public static final String DLP_VERSION = "novawaf:dlp:config:version";

    private static final Set<String> METHODS =
            Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY");
    private static final Set<String> SCOPES = Set.of("ip", "token", "global");
    private static final Set<String> ACTIONS = Set.of("monitor", "429", "ban");
    private static final Set<String> MODES = Set.of("jwt", "opaque", "any");
    private static final Set<String> DLP_ACTIONS = Set.of("mask", "log", "block", "off");
    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9_\\-./{}:?%~*]*$");
    private static final Pattern ALG = Pattern.compile("^[A-Za-z0-9, _-]{0,64}$");

    private final ApiGuardRuleMapper ruleMapper;
    private final ApiGuardConfigMapper cfgMapper;
    private final ApiTokenMapper tokenMapper;
    private final ApiAssetService assets;
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /* ============================ 限流策略 ============================ */

    public List<ApiGuardRule> rules() {
        Map<String, String> names = assets.appNames();
        List<ApiGuardRule> all = ruleMapper.selectAll();
        for (ApiGuardRule r : all) {
            String aid = r.getAppId();
            r.setAppName(aid == null || aid.isBlank() ? "全部应用" : names.getOrDefault(aid, "应用-" + aid));
        }
        return all;
    }

    @Transactional
    public void addRule(ApiGuardRule r) {
        normalizeRule(r, true);
        if (ruleMapper.countByKey(r.getAppId(), r.getMethod(), r.getPath(), null) > 0) {
            throw new BusinessException("该应用下同方法同路径的策略已存在：" + r.getMethod() + " " + r.getPath());
        }
        if (r.getEnabled() == null) r.setEnabled(true);
        ruleMapper.insert(r);
        publishGuard();
    }

    @Transactional
    public void updateRule(ApiGuardRule r) {
        if (r.getId() == null || ruleMapper.selectById(r.getId()) == null) throw new BusinessException("策略不存在或已被删除");
        normalizeRule(r, true);
        if (ruleMapper.countByKey(r.getAppId(), r.getMethod(), r.getPath(), r.getId()) > 0) {
            throw new BusinessException("该应用下同方法同路径已被其它策略占用：" + r.getMethod() + " " + r.getPath());
        }
        if (r.getEnabled() == null) r.setEnabled(true);
        ruleMapper.update(r);
        publishGuard();
    }

    @Transactional
    public void toggleRule(Long id, Boolean enabled) {
        if (id == null || ruleMapper.selectById(id) == null) throw new BusinessException("策略不存在或已被删除");
        ruleMapper.updateEnabled(id, Boolean.TRUE.equals(enabled));
        publishGuard();
    }

    @Transactional
    public void deleteRule(Long id) {
        if (id == null || ruleMapper.selectById(id) == null) throw new BusinessException("策略不存在或已被删除");
        ruleMapper.deleteById(id);
        publishGuard();
    }

    private void normalizeRule(ApiGuardRule r, boolean strict) {
        if (r == null) throw new BusinessException("参数不能为空");
        String name = r.getName() == null ? "" : r.getName().trim();
        String method = r.getMethod() == null ? "" : r.getMethod().trim().toUpperCase();
        String path = r.getPath() == null ? "" : r.getPath().trim();
        String appId = r.getAppId() == null ? "" : r.getAppId().trim();
        String scope = r.getScope() == null ? "ip" : r.getScope().trim().toLowerCase();
        String action = r.getAction() == null ? "429" : r.getAction().trim().toLowerCase();
        if (name.isEmpty() || name.length() > 64) throw new BusinessException("策略名称必填且不超过 64 字符");
        if (method.isEmpty()) method = "ANY";
        if (!METHODS.contains(method)) throw new BusinessException("请求方法非法：" + method);
        if (path.isEmpty() || path.length() > 255 || !SAFE_PATH.matcher(path).matches()) {
            throw new BusinessException("路径必须以 / 开头，仅允许字母数字及 / _ - . { } : ? % ~ * ，长度不超过 255");
        }
        if (path.contains("..")) throw new BusinessException("路径不允许包含 .. 目录穿越片段");
        int star = path.indexOf('*');
        if (star >= 0 && star != path.length() - 1) throw new BusinessException("通配符 * 仅允许出现在路径末尾");
        if (!appId.isEmpty() && (appId.length() > 32 || !assets.appNames().containsKey(appId))) {
            if (strict) throw new BusinessException("所属应用不存在或非法：" + appId);
            else appId = "";
        }
        if (!SCOPES.contains(scope)) throw new BusinessException("限流维度只能是 ip / token / global");
        if (!ACTIONS.contains(action)) throw new BusinessException("动作只能是 monitor / 429 / ban");
        int qps = r.getQps() == null ? 10 : r.getQps();
        int burst = r.getBurst() == null ? Math.max(qps * 2, 10) : r.getBurst();
        int banSec = r.getBanSec() == null ? 60 : r.getBanSec();
        if (qps < 1 || qps > 1000000) throw new BusinessException("QPS 需在 1 ~ 1000000");
        if (burst < 1 || burst > 1000000) throw new BusinessException("突发桶容量需在 1 ~ 1000000");
        if (banSec < 1 || banSec > 86400) throw new BusinessException("封禁时长需在 1 ~ 86400 秒");
        if (r.getRemark() != null && r.getRemark().length() > 255) throw new BusinessException("备注不能超过 255 字符");
        r.setName(name);
        r.setMethod(method);
        r.setPath(path);
        r.setAppId(appId.isEmpty() ? null : appId);
        r.setScope(scope);
        r.setAction(action);
        r.setQps(qps);
        r.setBurst(burst);
        r.setBanSec(banSec);
        if (r.getTokenRequired() == null) r.setTokenRequired(false);
    }

    /* ============================ 全局配置 ============================ */

    public ApiGuardConfig config() {
        ApiGuardConfig c = cfgMapper.selectSingleton();
        if (c == null) {
            c = new ApiGuardConfig();
            c.setId(1L);
            c.setEnabled(true);
            c.setStage("monitor");
            c.setTokenEnabled(true);
            c.setTokenEnforce(false);
            c.setTokenMode("any");
            c.setTokenAlg("HS256");
            c.setTokenMaxAge(86400);
            c.setTokenRequireIat(false);
            c.setTokenReuseWindow(60);
            c.setTokenReuseMaxIps(8);
            c.setTokenEnforceReuse(false);
            c.setDlpEnabled(false);
            c.setDlpAction("mask");
            c.setDlpMaxBytes(1L << 20);
        }
        // 密钥脱敏返回，避免明文密钥随列表接口外泄
        c.setTokenSecret(maskSecret(c.getTokenSecret()));
        return c;
    }

    @Transactional
    public ApiGuardConfig saveConfig(ApiGuardConfig c) {
        if (c == null) throw new BusinessException("参数不能为空");
        ApiGuardConfig old = cfgMapper.selectSingleton();
        String stage = c.getStage() == null ? "monitor" : c.getStage().trim().toLowerCase();
        String mode = c.getTokenMode() == null ? "any" : c.getTokenMode().trim().toLowerCase();
        String alg = c.getTokenAlg() == null ? "HS256" : c.getTokenAlg().trim();
        String dlpAction = c.getDlpAction() == null ? "mask" : c.getDlpAction().trim().toLowerCase();
        if (!"monitor".equals(stage) && !"enforce".equals(stage)) throw new BusinessException("生效阶段只能是 monitor / enforce");
        if (!MODES.contains(mode)) throw new BusinessException("令牌模式只能是 jwt / opaque / any");
        if (!ALG.matcher(alg).matches()) throw new BusinessException("签名算法声明非法（仅允许逗号分隔的算法名）");
        if (!DLP_ACTIONS.contains(dlpAction)) throw new BusinessException("脱敏动作只能是 mask / log / block / off");
        int maxAge = c.getTokenMaxAge() == null ? 86400 : c.getTokenMaxAge();
        int reuseWindow = c.getTokenReuseWindow() == null ? 60 : c.getTokenReuseWindow();
        int reuseMaxIps = c.getTokenReuseMaxIps() == null ? 8 : c.getTokenReuseMaxIps();
        long maxBytes = c.getDlpMaxBytes() == null ? (1L << 20) : c.getDlpMaxBytes();
        if (maxAge < 60 || maxAge > 31536000) throw new BusinessException("令牌最大有效期需在 60 ~ 31536000 秒");
        if (reuseWindow < 0 || reuseWindow > 86400) throw new BusinessException("复用检测窗口需在 0 ~ 86400 秒");
        if (reuseMaxIps < 1 || reuseMaxIps > 1000) throw new BusinessException("复用来源 IP 上限需在 1 ~ 1000");
        if (maxBytes < 1024 || maxBytes > (16L << 20)) throw new BusinessException("脱敏响应体上限需在 1KB ~ 16MB");

        // 前端回传脱敏值时不覆盖真实密钥
        String secret = c.getTokenSecret();
        if (secret == null || secret.isEmpty() || secret.contains("****")) {
            secret = old == null ? null : old.getTokenSecret();
        }
        if (secret != null && secret.length() > 512) throw new BusinessException("密钥长度不能超过 512");

        ApiGuardConfig row = new ApiGuardConfig();
        row.setId(1L);
        row.setEnabled(c.getEnabled() == null ? Boolean.TRUE : c.getEnabled());
        row.setStage(stage);
        row.setTokenEnabled(c.getTokenEnabled() == null ? Boolean.TRUE : c.getTokenEnabled());
        row.setTokenEnforce(Boolean.TRUE.equals(c.getTokenEnforce()));
        row.setTokenMode(mode);
        row.setTokenAlg(alg);
        row.setTokenSecret(secret);
        row.setTokenMaxAge(maxAge);
        row.setTokenRequireIat(Boolean.TRUE.equals(c.getTokenRequireIat()));
        row.setTokenReuseWindow(reuseWindow);
        row.setTokenReuseMaxIps(reuseMaxIps);
        row.setTokenEnforceReuse(Boolean.TRUE.equals(c.getTokenEnforceReuse()));
        row.setDlpEnabled(Boolean.TRUE.equals(c.getDlpEnabled()));
        row.setDlpAction(dlpAction);
        row.setDlpMaxBytes(maxBytes);
        if (old == null) cfgMapper.insertSingleton(row);
        else cfgMapper.updateSingleton(row);

        publishGuard();
        publishDlp(row);
        ApiGuardConfig ret = config();
        ret.setTokenSecret(maskSecret(secret));
        return ret;
    }

    /* ============================ 令牌白名单 ============================ */

    public List<ApiToken> tokens() {
        Map<String, String> names = assets.appNames();
        List<ApiToken> all = tokenMapper.selectAll();
        for (ApiToken t : all) {
            String aid = t.getAppId();
            t.setAppName(aid == null || aid.isBlank() ? "全部应用" : names.getOrDefault(aid, "应用-" + aid));
            t.setTokenMask(maskSecret(t.getToken()));
            t.setToken(null);   // 列表不返回明文令牌
        }
        return all;
    }

    @Transactional
    public void addToken(ApiToken t) {
        normalizeToken(t);
        if (tokenMapper.countByToken(t.getToken(), null) > 0) throw new BusinessException("该令牌已存在");
        if (t.getEnabled() == null) t.setEnabled(true);
        tokenMapper.insert(t);
        publishTokens();
    }

    @Transactional
    public void updateToken(ApiToken t) {
        if (t.getId() == null || tokenMapper.selectById(t.getId()) == null) throw new BusinessException("令牌不存在或已被删除");
        // 前端编辑时回传的是脱敏值，保留原令牌
        if (t.getToken() == null || t.getToken().isBlank() || t.getToken().contains("****")) {
            t.setToken(tokenMapper.selectById(t.getId()).getToken());
        }
        normalizeToken(t);
        if (tokenMapper.countByToken(t.getToken(), t.getId()) > 0) throw new BusinessException("该令牌已被其它记录占用");
        if (t.getEnabled() == null) t.setEnabled(true);
        tokenMapper.update(t);
        publishTokens();
    }

    @Transactional
    public void toggleToken(Long id, Boolean enabled) {
        if (id == null || tokenMapper.selectById(id) == null) throw new BusinessException("令牌不存在或已被删除");
        tokenMapper.updateEnabled(id, Boolean.TRUE.equals(enabled));
        publishTokens();
    }

    @Transactional
    public void deleteToken(Long id) {
        if (id == null || tokenMapper.selectById(id) == null) throw new BusinessException("令牌不存在或已被删除");
        tokenMapper.deleteById(id);
        publishTokens();
    }

    private void normalizeToken(ApiToken t) {
        if (t == null) throw new BusinessException("参数不能为空");
        String name = t.getName() == null ? "" : t.getName().trim();
        String token = t.getToken() == null ? "" : t.getToken().trim();
        String appId = t.getAppId() == null ? "" : t.getAppId().trim();
        if (name.isEmpty() || name.length() > 64) throw new BusinessException("令牌名称必填且不超过 64 字符");
        if (token.isEmpty() || token.length() > 512) throw new BusinessException("令牌值必填且不超过 512 字符");
        if (token.chars().anyMatch(Character::isWhitespace)) throw new BusinessException("令牌值不能包含空白字符");
        if (!appId.isEmpty() && (appId.length() > 32 || !assets.appNames().containsKey(appId))) {
            throw new BusinessException("所属应用不存在或非法：" + appId);
        }
        if (t.getRemark() != null && t.getRemark().length() > 255) throw new BusinessException("备注不能超过 255 字符");
        t.setName(name);
        t.setToken(token);
        t.setAppId(appId.isEmpty() ? null : appId);
    }

    /* ============================ 发布 ============================ */

    /** 发布限流策略 + 令牌校验配置：{"enabled","stage"(0/1),"rules":[...],"token":{...}}。 */
    private void publishGuard() {
        try {
            ApiGuardConfig c = cfgMapper.selectSingleton();
            ObjectNode root = om.createObjectNode();
            root.put("enabled", c == null || Boolean.TRUE.equals(c.getEnabled()));
            // 引擎 stage 为数值：0=观察期，1=正式生效
            root.put("stage", c != null && "enforce".equalsIgnoreCase(c.getStage()) ? 1 : 0);

            ArrayNode rules = om.createArrayNode();
            for (ApiGuardRule r : ruleMapper.selectEnabled()) {
                ObjectNode n = om.createObjectNode();
                n.put("id", String.valueOf(r.getId()));
                n.put("appId", r.getAppId() == null ? "" : r.getAppId());
                n.put("method", r.getMethod());
                n.put("path", r.getPath());
                n.put("qps", r.getQps());
                n.put("burst", r.getBurst());
                n.put("scope", r.getScope());
                n.put("action", r.getAction());
                n.put("banSec", r.getBanSec());
                n.put("tokenRequired", Boolean.TRUE.equals(r.getTokenRequired()));
                rules.add(n);
            }
            root.set("rules", rules);

            ObjectNode tk = om.createObjectNode();
            tk.put("enabled", c == null || Boolean.TRUE.equals(c.getTokenEnabled()));
            tk.put("enforce", c != null && Boolean.TRUE.equals(c.getTokenEnforce()));
            tk.put("mode", c == null ? "any" : c.getTokenMode());
            tk.put("maxAgeSec", c == null ? 86400 : c.getTokenMaxAge());
            tk.put("requireIat", c != null && Boolean.TRUE.equals(c.getTokenRequireIat()));
            tk.put("reuseWindowSec", c == null ? 60 : c.getTokenReuseWindow());
            tk.put("reuseMaxIps", c == null ? 8 : c.getTokenReuseMaxIps());
            tk.put("enforceReuse", c != null && Boolean.TRUE.equals(c.getTokenEnforceReuse()));
            if (c != null && c.getTokenSecret() != null) tk.put("secret", c.getTokenSecret());
            ArrayNode algs = om.createArrayNode();
            if (c != null && c.getTokenAlg() != null) {
                for (String a : c.getTokenAlg().split(",")) {
                    String s = a.trim().toUpperCase();
                    if (!s.isEmpty()) algs.add(s);
                }
            }
            tk.set("algWhitelist", algs);
            root.set("token", tk);

            redis.opsForValue().set(GUARD_KEY, om.writeValueAsString(root));
            Long ver = redis.opsForValue().increment(GUARD_VERSION);
            log.info("API 防护策略已发布: {} 条规则, stage={}, version={}", rules.size(), root.get("stage"), ver);
        } catch (Exception e) {
            throw new BusinessException(500, "策略已保存但发布到引擎失败：" + e.getMessage());
        }
    }

    /** 发布不透明令牌白名单：["token1","token2"]。 */
    private void publishTokens() {
        try {
            ArrayNode arr = om.createArrayNode();
            for (ApiToken t : tokenMapper.selectActive()) arr.add(t.getToken());
            redis.opsForValue().set(TOKEN_KEY, om.writeValueAsString(arr));
            Long ver = redis.opsForValue().increment(TOKEN_VERSION);
            log.info("API 令牌白名单已发布: {} 个, version={}", arr.size(), ver);
        } catch (Exception e) {
            throw new BusinessException(500, "令牌已保存但发布到引擎失败：" + e.getMessage());
        }
    }

    /** 发布响应脱敏配置：{"enabled","action","maxBytes"}。 */
    private void publishDlp(ApiGuardConfig c) {
        try {
            ObjectNode n = om.createObjectNode();
            n.put("enabled", Boolean.TRUE.equals(c.getDlpEnabled()));
            n.put("action", c.getDlpAction());
            n.put("maxBytes", c.getDlpMaxBytes());
            redis.opsForValue().set(DLP_KEY, om.writeValueAsString(n));
            redis.opsForValue().increment(DLP_VERSION);
            log.info("响应脱敏配置已发布: enabled={}, action={}", c.getDlpEnabled(), c.getDlpAction());
        } catch (Exception e) {
            throw new BusinessException(500, "脱敏配置已保存但发布到引擎失败：" + e.getMessage());
        }
    }

    /** 敏感值脱敏：保留首 6 位与末 4 位，中间以 **** 代替。 */
    public static String maskSecret(String v) {
        if (v == null || v.isEmpty()) return v;
        if (v.length() <= 10) return "****";
        return v.substring(0, 6) + "****" + v.substring(v.length() - 4);
    }

    /** 规则/配置汇总（供前端概览卡片）。 */
    public Map<String, Object> stats() {
        Map<String, Object> m = new LinkedHashMap<>();
        List<ApiGuardRule> rs = ruleMapper.selectAll();
        int on = 0, tokenReq = 0;
        for (ApiGuardRule r : rs) {
            if (Boolean.TRUE.equals(r.getEnabled())) on++;
            if (Boolean.TRUE.equals(r.getTokenRequired())) tokenReq++;
        }
        m.put("rules", rs.size());
        m.put("enabledRules", on);
        m.put("tokenRequiredRules", tokenReq);
        m.put("whitelistTokens", tokenMapper.selectActive().size());
        return m;
    }
}
