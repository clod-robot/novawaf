import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.instrument.Instrumentation;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NovaWAF mini-RASP Agent —— Java 反序列化应用层防护（RMI/JMX/任意 ObjectInputStream 入口）
 *
 * 原理：JEP 290（JDK 9+ 序列化过滤器）+ JEP 415（JDK 17+ filter factory）。
 * 通过 Config.setSerialFilterFactory 注册 JVM 全局过滤器工厂，所有反序列化流
 * （RMI、JMX、业务自定义 ObjectInputStream）在类解析阶段即被拦截，无需字节码织入。
 *
 * 命中黑名单类或资源超限时返回 REJECTED，JVM 抛出 InvalidClassException，
 * 反序列化被阻断；同时写告警日志（含类名与调用栈摘要）。
 *
 * 挂载方式：java -javaagent:mini-rasp-agent.jar ...
 * 配置（系统属性）：
 *   -Dnova.rasp.log=<path>       告警日志路径（默认 ./rasp_alert.log）
 *   -Dnova.rasp.monitor=true     监控模式：只告警不阻断（默认 false=阻断）
 */
public final class MiniRaspAgent {

    /** 反序列化 gadget 类名黑名单（包前缀或类名子串，与 WAF 引擎 RMI 规则对齐） */
    private static final List<String> BLACKLIST = Arrays.asList(
            "org.apache.commons.collections.functors",
            "org.apache.commons.collections4.functors",
            "org.apache.commons.beanutils",
            "com.sun.rowset.JdbcRowSetImpl",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "org.apache.xalan.xsltc.trax.TemplatesImpl",
            "org.codehaus.groovy",
            "groovy.lang.GroovyShell",
            "bsh.Interpreter",
            "com.mchange.v2.c3p0",
            "org.mozilla.javascript",
            "org.apache.commons.configuration",
            "clojure.core$",
            "javax.management.BadAttributeValueExpException",
            "javax.script.ScriptEngineManager"
    );

    /** 资源面限制（防反序列化 DoS），宽松于正常业务、远低于攻击载荷 */
    private static final long MAX_DEPTH = 64L;
    private static final long MAX_REFS  = 200_000L;
    private static final long MAX_BYTES = 16L * 1024 * 1024;

    private static final AtomicLong blockedCount = new AtomicLong();
    private static volatile String logPath;
    private static volatile boolean monitorOnly;

    public static void premain(String args, Instrumentation inst) { install(); }
    public static void agentmain(String args, Instrumentation inst) { install(); }

    private static void install() {
        logPath = System.getProperty("nova.rasp.log", "./rasp_alert.log");
        monitorOnly = Boolean.parseBoolean(System.getProperty("nova.rasp.monitor", "false"));

        // JEP 415：注册全局过滤器工厂。current = JVM 现有过滤器（含 jdk.serialFilter 配置的），
        // next = 流创建方请求的过滤器。返回组合过滤器：先跑我们的黑名单，再委托原过滤器。
        ObjectInputFilter.Config.setSerialFilterFactory((current, next) -> filterInfo -> {
            ObjectInputFilter.Status st = check(filterInfo);
            if (st != ObjectInputFilter.Status.UNDECIDED) {
                alert(filterInfo, st);
                if (monitorOnly) {
                    // 监控模式：告警但不阻断，继续走原过滤链
                } else {
                    return st;  // REJECTED → JVM 抛 InvalidClassException
                }
            }
            if (next != null) {
                ObjectInputFilter.Status ns = next.checkInput(filterInfo);
                if (ns != null && ns != ObjectInputFilter.Status.UNDECIDED) return ns;
            }
            if (current != null) {
                ObjectInputFilter.Status cs = current.checkInput(filterInfo);
                if (cs != null && cs != ObjectInputFilter.Status.UNDECIDED) return cs;
            }
            return ObjectInputFilter.Status.UNDECIDED;
        });

        System.err.println("[NovaRASP] installed. log=" + logPath
                + " monitor=" + monitorOnly + " rules=" + BLACKLIST.size());
    }

    private static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
        Class<?> cls = info.serialClass();
        if (cls != null) {
            String name = cls.getName();
            for (String bad : BLACKLIST) {
                if (name.startsWith(bad) || name.contains(bad)) {
                    return ObjectInputFilter.Status.REJECTED;
                }
            }
        }
        if (info.depth() > MAX_DEPTH || info.references() > MAX_REFS || info.streamBytes() > MAX_BYTES) {
            return ObjectInputFilter.Status.REJECTED;
        }
        return ObjectInputFilter.Status.UNDECIDED;
    }

    /** 告警：时间戳 + 类名 + 深度/引用/字节数 + 截断调用栈 */
    private static void alert(ObjectInputFilter.FilterInfo info, ObjectInputFilter.Status st) {
        long n = blockedCount.incrementAndGet();
        Class<?> cls = info.serialClass();
        StringBuilder sb = new StringBuilder(512);
        sb.append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
          .append(" [NovaRASP] #").append(n)
          .append(" action=").append(monitorOnly ? "ALERT" : st)
          .append(" class=").append(cls != null ? cls.getName() : "<n/a>")
          .append(" depth=").append(info.depth())
          .append(" refs=").append(info.references())
          .append(" bytes=").append(info.streamBytes())
          .append('\n');
        // 调用栈摘要（定位业务入口，截前 12 帧）
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        int limit = Math.min(stack.length, 14);
        for (int i = 2; i < limit; i++) {
            sb.append("    at ").append(stack[i]).append('\n');
        }
        synchronized (MiniRaspAgent.class) {
            try (FileWriter fw = new FileWriter(logPath, true)) {
                fw.write(sb.toString());
            } catch (IOException ignored) {
                // fail-open：日志写失败不影响防护
            }
        }
        System.err.print(sb);
    }

    private MiniRaspAgent() {}
}
