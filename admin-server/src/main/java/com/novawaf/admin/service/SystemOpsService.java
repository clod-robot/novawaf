package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.SafeExec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 引擎系统维护（在线一键升级 / 零停机滚动重启 / 版本回退）：
 * 状态唯一真值源是服务器上的 engine_ops.sh（版本目录 + current/previous 符号链接），
 * 本服务仅以固定 argv（sudo 免密、无 shell 拼接）调起并解析其 JSON 输出。
 * 升级/回退失败由脚本自动回切旧版本，本层不再做二次决策。
 */
@Slf4j
@Service
public class SystemOpsService {

    private static final Pattern VERSION = Pattern.compile("^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$");
    private static final int OUTPUT_LIMIT = 262144;

    @Value("${nova.ops.script:/opt/novawaf/bin/engine_ops.sh}")
    private String script;
    @Value("${nova.ops.root:/opt/novawaf/engine}")
    private String root;
    @Value("${nova.ops.sudo:true}")
    private boolean sudo;
    @Value("${nova.ops.max-upload-mb:256}")
    private long maxUploadMb;

    private final ObjectMapper om = new ObjectMapper();

    /** 总览：版本清单 + 运行状态（master/worker/端口/运行版本） */
    public Map<String, Object> overview() {
        Map<String, Object> list = run(List.of("list"), 15000);
        Map<String, Object> status = run(List.of("status"), 15000);
        Map<String, Object> data = new LinkedHashMap<>(status);
        data.put("versions", list.get("versions"));
        return data;
    }

    /**
     * 上传引擎二进制并安装为新版本（不切换运行版本）。
     * 版本号以二进制自身 --version 输出为准，杜绝人工输入与文件不一致。
     */
    public Map<String, Object> install(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new BusinessException("安装包不能为空");
        }
        long max = maxUploadMb * 1024 * 1024;
        if (file.getSize() > max) {
            throw new BusinessException("安装包超过 " + maxUploadMb + "MB 上限");
        }
        Path uploads = Path.of(root, "uploads");
        Path tmp = uploads.resolve(UUID.randomUUID() + ".bin");
        try {
            Files.createDirectories(uploads);
            file.transferTo(tmp);
            return run(List.of("install", tmp.toString()), 60000);
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.warn("engine install failed: {}", e.toString());
            throw new BusinessException(500, "安装包写入失败：" + e.getMessage());
        } finally {
            try { Files.deleteIfExists(tmp); } catch (Exception ignore) { /* 脚本 mv 成功则已不存在 */ }
        }
    }

    /** 一键升级：切换到已安装版本（脚本内完成 符号链接切换→SIGUSR2 滚动→校验→失败自动回切） */
    public Map<String, Object> upgrade(String version) {
        String v = version == null ? "" : version.trim();
        if (!VERSION.matcher(v).matches()) {
            throw new BusinessException("版本号非法");
        }
        return run(List.of("activate", v), 120000);
    }

    /** 版本回退：切回 previous 符号链接指向的上一版本 */
    public Map<String, Object> rollback() {
        return run(List.of("rollback"), 120000);
    }

    /** 零停机滚动重启（同版本换新 worker） */
    public Map<String, Object> restart() {
        return run(List.of("restart"), 120000);
    }

    private Map<String, Object> run(List<String> args, long timeoutMs) {
        List<String> argv = new ArrayList<>();
        if (sudo) {
            argv.add("sudo");
            argv.add("-n");
        }
        argv.add(script);
        argv.addAll(args);
        String out = SafeExec.run(argv, timeoutMs, OUTPUT_LIMIT);
        JsonNode node;
        try {
            node = om.readTree(out.trim());
        } catch (Exception e) {
            throw new BusinessException(500, "运维脚本输出非法：" + tail(out));
        }
        if (node == null || !node.path("ok").asBoolean(false)) {
            String err = node == null ? "未知错误" : node.path("error").asText("未知错误");
            throw new BusinessException(500, err);
        }
        try {
            return om.convertValue(node, Map.class);
        } catch (Exception e) {
            throw new BusinessException(500, "运维脚本结果解析失败");
        }
    }

    private static String tail(String s) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= 200 ? t : t.substring(t.length() - 200);
    }
}
