package com.novawaf.admin.common;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 受控外部进程执行器（仅供后台“一键探测”等固定脚本场景使用）。
 * 安全约束（等保/代码安全）：
 * 1. 调用方必须传入固定 argv，ProcessBuilder 不经 shell 解释，杜绝命令注入；
 * 2. 强制超时，超时 destroyForcibly；
 * 3. stdout+stderr 合并流由独立守护线程持续排空（防管道阻塞死锁），输出大小封顶；
 * 4. 非零退出/超时/超限均抛 BusinessException，错误信息仅回显尾部少量内容。
 */
@Slf4j
public final class SafeExec {

    private SafeExec() {
    }

    /**
     * 执行命令并返回标准输出（已合并 stderr）。
     *
     * @param argv      固定参数列表（第一项为可执行文件，不允许出现 shell 拼接）
     * @param timeoutMs 超时毫秒
     * @param maxBytes  输出最大字节数
     */
    public static String run(List<String> argv, long timeoutMs, int maxBytes) {
        if (argv == null || argv.isEmpty() || argv.get(0) == null || argv.get(0).isBlank()) {
            throw new BusinessException(500, "执行命令不能为空");
        }
        if (timeoutMs <= 0 || maxBytes <= 0) {
            throw new BusinessException(500, "执行超时/输出上限配置非法");
        }
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);

        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new BusinessException(500, "无法启动进程: " + e.getMessage());
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread drain = new Thread(() -> copyCapped(p.getInputStream(), out, maxBytes), "safeexec-drain");
        drain.setDaemon(true);
        drain.start();

        boolean finished;
        try {
            finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            joinQuiet(drain);
            throw new BusinessException(500, "脚本执行被中断");
        }

        if (!finished) {
            p.destroyForcibly();
            joinQuiet(drain);
            log.warn("SafeExec 超时终止: {}", argv.get(0));
            throw new BusinessException(504, "脚本执行超时(>" + timeoutMs + "ms)，已终止");
        }
        joinQuiet(drain);

        if (out.size() > maxBytes) {
            p.destroyForcibly();
            throw new BusinessException(500, "脚本输出超过上限 " + maxBytes + " 字节，已终止");
        }
        String text = out.toString(StandardCharsets.UTF_8);
        if (p.exitValue() != 0) {
            throw new BusinessException(500, "脚本执行失败(exit=" + p.exitValue() + "): " + tail(text));
        }
        return text;
    }

    /** 持续排空进程输出；超过上限后只排空不缓存（避免子进程写满管道阻塞）。 */
    private static void copyCapped(InputStream in, ByteArrayOutputStream out, int maxBytes) {
        byte[] buf = new byte[4096];
        int total = 0;
        try {
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total <= maxBytes) {
                    out.write(buf, 0, n);
                }
            }
        } catch (IOException ignore) {
            // 进程被销毁时管道关闭，属预期路径
        }
    }

    private static void joinQuiet(Thread t) {
        try {
            t.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String tail(String text) {
        String oneLine = text.replaceAll("\\s+", " ").trim();
        if (oneLine.length() <= 500) {
            return oneLine;
        }
        return oneLine.substring(oneLine.length() - 500);
    }
}
