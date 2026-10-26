package com.novawaf.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novawaf.admin.common.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/** 读取引擎写入 Redis 的 WAF 数据(与 C++ 控制台同一套 Key) */
@Service
@RequiredArgsConstructor
public class WafRedisService {
    private final StringRedisTemplate redis;
    private final ObjectMapper om = new ObjectMapper();

    /** 解析 JSON 字符串为对象(失败返回原始结构) */
    @SuppressWarnings("unchecked")
    private Object parse(String s) {
        if (s == null) return null;
        try { return om.readValue(s, Object.class); }
        catch (Exception e) { return s; }
    }

    public Object getJson(String key) { return parse(redis.opsForValue().get(key)); }

    /** novawaf:logs —— 全量日志 JSON 数组, 支持分页切片(按倒序) */
    @SuppressWarnings("unchecked")
    public Map<String, Object> logs(int page, int size, String keyword) {
        Object obj = getJson("novawaf:logs");
        List<Object> all = (obj instanceof List) ? (List<Object>) obj : new ArrayList<>();
        Collections.reverse(all); // 最新在前
        List<Object> filtered = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            String kw = keyword.toLowerCase();
            for (Object o : all) {
                if (String.valueOf(o).toLowerCase().contains(kw)) filtered.add(o);
            }
        } else {
            filtered.addAll(all);
        }
        long total = filtered.size();
        int from = Math.min((page - 1) * size, filtered.size());
        int to = Math.min(from + size, filtered.size());
        Map<String, Object> m = new HashMap<>();
        m.put("total", total);
        m.put("rows", filtered.subList(from, to));
        return m;
    }

    public Object rules() {
        ensureRulesSeed();
        return getJson("novawaf:rules");
    }

    /** 引擎只消费 novawaf:rules, 管理端需负责灌入初始自定义规则集; 仅当键缺失/为空时写入, 不覆盖用户已编辑内容。
     *  规则库 = 通用攻击特征 + CVE 定向漏洞规则（国产组件/国际通用），与仓库 rules/cve_rules.json 一致（由 scripts/gen_java_rules.py 生成）。 */
    private static final String DEFAULT_RULES = "["
            + "{\"id\":1,\"name\":\"SQL注入-联合查询\",\"pattern\":\"union select\",\"category\":\"SQLi\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"critical\",\"desc\":\"UNION SELECT 联合查询注入特征\"},"
            + "{\"id\":2,\"name\":\"SQL注入-恒真绕过\",\"pattern\":\"' or '1'='1\",\"category\":\"SQLi\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"critical\",\"desc\":\"永真条件认证绕过\"},"
            + "{\"id\":3,\"name\":\"XSS-脚本标签\",\"pattern\":\"<script\",\"category\":\"XSS\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"high\",\"desc\":\"script 标签注入\"},"
            + "{\"id\":4,\"name\":\"XSS-事件处理器\",\"pattern\":\"onerror=\",\"category\":\"XSS\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"high\",\"desc\":\"HTML 事件属性注入\"},"
            + "{\"id\":5,\"name\":\"命令执行-敏感文件\",\"pattern\":\"/etc/passwd\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"critical\",\"desc\":\"读取 /etc/passwd 敏感文件\"},"
            + "{\"id\":6,\"name\":\"路径穿越\",\"pattern\":\"../\",\"category\":\"Traversal\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"high\",\"desc\":\"目录穿越 ../ 特征\"},"
            + "{\"id\":7,\"name\":\"XXE-外部实体\",\"pattern\":\"<!entity\",\"category\":\"XXE\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"high\",\"desc\":\"XML 外部实体注入\"},"
            + "{\"id\":8,\"name\":\"扫描器-Nikto\",\"pattern\":\"nikto\",\"category\":\"Scanner\",\"action\":\"log\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"medium\",\"desc\":\"Nikto 扫描器指纹\"},"
            + "{\"id\":9,\"name\":\"扫描器-Sqlmap\",\"pattern\":\"sqlmap\",\"category\":\"Scanner\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"high\",\"desc\":\"Sqlmap 扫描器指纹\"},"
            + "{\"id\":10,\"name\":\"信息探测-备份文件\",\"pattern\":\".bak\",\"category\":\"InfoLeak\",\"action\":\"block\",\"enabled\":true,\"group\":\"通用攻击特征\",\"severity\":\"medium\",\"desc\":\"备份文件探测（与引擎内置敏感后缀拦截一致置为 block）\"},"
            + "{\"id\":2001,\"name\":\"ThinkPHP 5.x invokefunction RCE\",\"pattern\":\"/think\\\\app/invokefunction\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2018-20062\",\"vulnName\":\"ThinkPHP 5.x 远程代码执行\",\"severity\":\"critical\",\"component\":\"ThinkPHP\",\"cvss\":9.8,\"year\":2018,\"desc\":\"ThinkPHP 5.x 未过滤控制器名，invokefunction 调用 call_user_func 执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2018-20062\"},"
            + "{\"id\":2002,\"name\":\"ThinkPHP 5.0.23 Request 反序列化 RCE\",\"pattern\":\"_method=__construct&filter[]\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CNVD-2018-24942\",\"vulnName\":\"ThinkPHP 5.0.23 远程代码执行\",\"severity\":\"critical\",\"component\":\"ThinkPHP\",\"cvss\":9.8,\"year\":2018,\"desc\":\"Request 类 __construct 覆盖 filter 导致 call_user_func 代码执行\",\"ref\":\"https://www.cnvd.org.cn/flaw/show/CNVD-2018-24942\"},"
            + "{\"id\":2003,\"name\":\"ThinkPHP 多语言 pearcmd 文件写 RCE\",\"pattern\":\"pearcmd\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2022-47945\",\"vulnName\":\"ThinkPHP 多语言模块命令执行\",\"severity\":\"critical\",\"component\":\"ThinkPHP\",\"cvss\":9.8,\"year\":2022,\"desc\":\"lang 参数目录穿越包含 pearcmd 写文件 getshell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2022-47945\"},"
            + "{\"id\":2004,\"name\":\"Fastjson JdbcRowSetImpl 反序列化\",\"pattern\":\"com.sun.rowset.jdbcrowsetimpl\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2017-18349\",\"vulnName\":\"Fastjson <=1.2.24 反序列化 RCE\",\"severity\":\"critical\",\"component\":\"Fastjson\",\"cvss\":9.8,\"year\":2017,\"desc\":\"JdbcRowSetImpl gadget JNDI 加载远程类执行任意代码（亦覆盖 Weblogic XMLDecoder 同类 gadget）\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2017-18349\"},"
            + "{\"id\":2005,\"name\":\"Fastjson TemplatesImpl 反序列化\",\"pattern\":\"com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CNVD-2022-40233\",\"vulnName\":\"Fastjson <=1.2.80 反序列化绕过 RCE\",\"severity\":\"critical\",\"component\":\"Fastjson\",\"cvss\":9.8,\"year\":2022,\"desc\":\"TemplatesImpl gadget 字节码加载执行任意代码\",\"ref\":\"https://www.cnvd.org.cn/flaw/show/CNVD-2022-40233\"},"
            + "{\"id\":2006,\"name\":\"Fastjson AutoType 绕过(java.lang.Class)\",\"pattern\":\"\\\"@type\\\":\\\"java.lang.class\\\"\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CNVD-2019-22238\",\"vulnName\":\"Fastjson 1.2.47 AutoType 绕过 RCE\",\"severity\":\"critical\",\"component\":\"Fastjson\",\"cvss\":9.8,\"year\":2019,\"desc\":\"java.lang.Class val 二次反序列化绕过 AutoType 黑名单\",\"ref\":\"https://www.cnvd.org.cn/flaw/show/CNVD-2019-22238\"},"
            + "{\"id\":2007,\"name\":\"Shiro-550 rememberMe 反序列化\",\"pattern\":\"rememberme=deleteme\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2016-4437\",\"vulnName\":\"Apache Shiro rememberMe 反序列化 RCE\",\"severity\":\"critical\",\"component\":\"Apache Shiro\",\"cvss\":9.8,\"year\":2016,\"desc\":\"硬编码 AES 密钥加密 rememberMe Cookie，反序列化 gadget 执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2016-4437\"},"
            + "{\"id\":2008,\"name\":\"Nacos 认证绕过(用户接口未授权)\",\"pattern\":\"/nacos/v1/auth/users?\",\"category\":\"AuthBypass\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2021-29441\",\"vulnName\":\"Nacos 认证绕过未授权访问\",\"severity\":\"high\",\"component\":\"Nacos\",\"cvss\":9.8,\"year\":2021,\"desc\":\"UA 伪造 serverIdentity 绕过认证，未授权枚举/新增用户\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-29441\"},"
            + "{\"id\":2009,\"name\":\"致远OA ajax.do 未授权文件上传\",\"pattern\":\"/seeyon/autoinstall.do.css/\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"vulnName\":\"致远OA A8 未授权文件上传 RCE\",\"severity\":\"critical\",\"component\":\"致远OA(Seeyon)\",\"cvss\":9.8,\"year\":2021,\"desc\":\"autoinstall.do.css/../ 绕过认证访问 ajax.do 上传 webshell\"},"
            + "{\"id\":2010,\"name\":\"泛微OA BSH 远程代码执行\",\"pattern\":\"/weaver/bsh.servlet.bshmethod\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CNVD-2019-32204\",\"vulnName\":\"泛微 e-cology BSH RCE\",\"severity\":\"critical\",\"component\":\"泛微OA(Weaver)\",\"cvss\":9.8,\"year\":2019,\"desc\":\"bsh.servlet.BshServlet 未授权执行 BeanShell 脚本\",\"ref\":\"https://www.cnvd.org.cn/flaw/show/CNVD-2019-32204\"},"
            + "{\"id\":2011,\"name\":\"用友NC BSH 远程代码执行\",\"pattern\":\"/servlet/~ic/bsh.servlet.bsh.servletexec\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CNVD-2021-30167\",\"vulnName\":\"用友 NC BeanShell 远程代码执行\",\"severity\":\"critical\",\"component\":\"用友NC(Yonyou)\",\"cvss\":9.8,\"year\":2021,\"desc\":\"~ic/bsh.servlet.BshServlet 未授权执行 BeanShell\",\"ref\":\"https://www.cnvd.org.cn/flaw/show/CNVD-2021-30167\"},"
            + "{\"id\":2012,\"name\":\"海康威视 命令注入\",\"pattern\":\"/sdk/weblanguage\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国产组件\",\"cve\":\"CVE-2021-36260\",\"vulnName\":\"Hikvision 设备 webLanguage 命令注入 RCE\",\"severity\":\"critical\",\"component\":\"海康威视(Hikvision)\",\"cvss\":9.8,\"year\":2021,\"desc\":\"PUT /SDK/webLanguage 未过滤 $(cmd) 注入，root 权限执行\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-36260\"},"
            + "{\"id\":3001,\"name\":\"Log4Shell JNDI 注入\",\"pattern\":\"${jndi:\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-44228\",\"vulnName\":\"Apache Log4j2 JNDI 注入 RCE(Log4Shell)\",\"severity\":\"critical\",\"component\":\"Apache Log4j2\",\"cvss\":10.0,\"year\":2021,\"desc\":\"Log4j2 JNDI lookup 注入远程加载类执行任意代码，覆盖 ${${lower:...}} 大小写混淆\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\"},"
            + "{\"id\":3002,\"name\":\"Log4Shell LDAP 协议特征\",\"pattern\":\"jndi:ldap://\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-44228\",\"vulnName\":\"Apache Log4j2 JNDI 注入 RCE(Log4Shell)\",\"severity\":\"critical\",\"component\":\"Apache Log4j2\",\"cvss\":10.0,\"year\":2021,\"desc\":\"拦截经分隔符混淆变形后的 ldap 协议 JNDI 引用\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\"},"
            + "{\"id\":3003,\"name\":\"Log4Shell RMI 协议特征\",\"pattern\":\"jndi:rmi://\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-44228\",\"vulnName\":\"Apache Log4j2 JNDI 注入 RCE(Log4Shell)\",\"severity\":\"critical\",\"component\":\"Apache Log4j2\",\"cvss\":10.0,\"year\":2021,\"desc\":\"拦截经混淆变形后的 rmi 协议 JNDI 引用\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\"},"
            + "{\"id\":3004,\"name\":\"Spring4Shell ClassLoader 操纵\",\"pattern\":\"class.module.classloader\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2022-22965\",\"vulnName\":\"Spring Framework ClassLoader RCE(Spring4Shell)\",\"severity\":\"critical\",\"component\":\"Spring Framework\",\"cvss\":9.8,\"year\":2022,\"desc\":\"绑定 class.module.classLoader 改写 Tomcat 日志配置写 JSP webshell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2022-22965\"},"
            + "{\"id\":3005,\"name\":\"Struts2 S2-045 Content-Type 注入\",\"pattern\":\"(#_='multipart/form-data')\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2017-5638\",\"vulnName\":\"Struts2 Jakarta Multipart OGNL RCE(S2-045)\",\"severity\":\"critical\",\"component\":\"Apache Struts2\",\"cvss\":10.0,\"year\":2017,\"desc\":\"恶意 Content-Type 头触发 OGNL 表达式执行\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2017-5638\"},"
            + "{\"id\":3006,\"name\":\"Struts2 OGNL MemberAccess 覆盖\",\"pattern\":\"(#_memberaccess\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2017-5638\",\"vulnName\":\"Struts2 OGNL 注入(S2-045/046 系列)\",\"severity\":\"critical\",\"component\":\"Apache Struts2\",\"cvss\":10.0,\"year\":2017,\"desc\":\"OGNL 表达式覆盖 _memberAccess 安全管理执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2017-5638\"},"
            + "{\"id\":3007,\"name\":\"Confluence OGNL 注入 Runtime.exec\",\"pattern\":\"getruntime().exec(\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2022-26134\",\"vulnName\":\"Atlassian Confluence OGNL 注入 RCE\",\"severity\":\"critical\",\"component\":\"Atlassian Confluence\",\"cvss\":9.8,\"year\":2022,\"desc\":\"URI 中 OGNL 表达式 ${...} 注入执行 Runtime.exec（同锚点亦覆盖其他 Java RCE）\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2022-26134\"},"
            + "{\"id\":3008,\"name\":\"Citrix ADC 目录遍历 RCE\",\"pattern\":\"/vpn/../vpns/\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2019-19781\",\"vulnName\":\"Citrix ADC/Gateway 目录遍历 RCE\",\"severity\":\"critical\",\"component\":\"Citrix ADC\",\"cvss\":9.8,\"year\":2019,\"desc\":\"/vpn/../vpns/ 路径遍历写 Perl 脚本执行任意命令\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2019-19781\"},"
            + "{\"id\":3009,\"name\":\"F5 BIG-IP TMUI 路径绕过 RCE\",\"pattern\":\"/tmui/login.jsp/..;/\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2020-5902\",\"vulnName\":\"F5 BIG-IP TMUI 认证绕过 RCE\",\"severity\":\"critical\",\"component\":\"F5 BIG-IP\",\"cvss\":9.8,\"year\":2020,\"desc\":\"..; 路径混淆绕过 TMUI 认证执行任意命令\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2020-5902\"},"
            + "{\"id\":3010,\"name\":\"FortiOS SSLVPN 路径遍历\",\"pattern\":\"/remote/fgt_lang?lang=/\",\"category\":\"InfoLeak\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2018-13379\",\"vulnName\":\"Fortinet FortiOS SSLVPN 路径遍历读取会话\",\"severity\":\"critical\",\"component\":\"Fortinet FortiOS\",\"cvss\":9.8,\"year\":2018,\"desc\":\"fgt_lang lang 参数路径遍历读取 sslvpn_websession 窃取凭据\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2018-13379\"},"
            + "{\"id\":3011,\"name\":\"Pulse Secure 任意文件读取\",\"pattern\":\"/dana/html5acc/\",\"category\":\"InfoLeak\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2019-11510\",\"vulnName\":\"Pulse Secure VPN 任意文件读取\",\"severity\":\"critical\",\"component\":\"Pulse Secure\",\"cvss\":10.0,\"year\":2019,\"desc\":\"/dana-na/../dana/html5acc/ 未授权读取敏感文件与会话\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2019-11510\"},"
            + "{\"id\":3012,\"name\":\"Weblogic Console 认证绕过\",\"pattern\":\"_nfpb=true&_pagelabel\",\"category\":\"AuthBypass\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2020-14882\",\"vulnName\":\"Weblogic Console 认证绕过 RCE\",\"severity\":\"critical\",\"component\":\"Oracle Weblogic\",\"cvss\":9.8,\"year\":2020,\"desc\":\"双重编码 + _nfpb/_pageLabel 绕过 console 认证执行代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2020-14882\"},"
            + "{\"id\":3013,\"name\":\"Weblogic WLS-WSAT XMLDecoder 反序列化\",\"pattern\":\"/wls-wsat/\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2017-10271\",\"vulnName\":\"Weblogic WLS-WSAT XMLDecoder RCE\",\"severity\":\"critical\",\"component\":\"Oracle Weblogic\",\"cvss\":9.8,\"year\":2017,\"desc\":\"wls-wsat 组件 XMLDecoder 反序列化执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2017-10271\"},"
            + "{\"id\":3014,\"name\":\"JBoss EJBInvokerServlet 反序列化\",\"pattern\":\"/invoker/readonly\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2017-12149\",\"vulnName\":\"JBoss AS 6.x invoker/readonly 反序列化 RCE\",\"severity\":\"critical\",\"component\":\"JBoss\",\"cvss\":9.8,\"year\":2017,\"desc\":\"EJBInvokerServlet 未授权反序列化执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2017-12149\"},"
            + "{\"id\":3015,\"name\":\"JBoss JMXInvokerServlet 反序列化\",\"pattern\":\"/invoker/jmxinvokerservlet\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2015-7501\",\"vulnName\":\"JBoss JMXInvokerServlet 反序列化 RCE\",\"severity\":\"critical\",\"component\":\"JBoss\",\"cvss\":9.8,\"year\":2015,\"desc\":\"JMXInvokerServlet commons-collections gadget 反序列化 RCE\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2015-7501\"},"
            + "{\"id\":3016,\"name\":\"Shellshock Bash 环境变量注入\",\"pattern\":\"() { :;};\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2014-6271\",\"vulnName\":\"Bash Shellshock 环境变量命令注入\",\"severity\":\"critical\",\"component\":\"GNU Bash/CGI\",\"cvss\":10.0,\"year\":2014,\"desc\":\"() { :;}; 函数定义注入经 CGI 环境变量执行任意命令\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2014-6271\"},"
            + "{\"id\":3017,\"name\":\"Exchange ProxyShell 路径混淆\",\"pattern\":\"/autodiscover/autodiscover.json?\",\"category\":\"SSRF\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-34473\",\"vulnName\":\"Exchange Server ProxyShell 认证绕过 SSRF RCE\",\"severity\":\"critical\",\"component\":\"MS Exchange\",\"cvss\":9.8,\"year\":2021,\"desc\":\"autodiscover.json 显式 URL 绕过 ACL 访问后端 PowerShell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-34473\"},"
            + "{\"id\":3018,\"name\":\"Exchange ProxyLogon SSRF\",\"pattern\":\"x-anonresource=\",\"category\":\"SSRF\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-26855\",\"vulnName\":\"Exchange Server ProxyLogon SSRF 写 webshell\",\"severity\":\"critical\",\"component\":\"MS Exchange\",\"cvss\":9.8,\"year\":2021,\"desc\":\"X-AnonResource Cookie SSRF 未授权访问 ECP 后端写 webshell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-26855\"},"
            + "{\"id\":3019,\"name\":\"Solr Velocity 模板 RCE\",\"pattern\":\"params.resource.loader.enabled=true\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2019-0193\",\"vulnName\":\"Apache Solr VelocityResponseWriter RCE\",\"severity\":\"critical\",\"component\":\"Apache Solr\",\"cvss\":9.8,\"year\":2019,\"desc\":\"config API 开启 params.resource.loader 后 Velocity 模板注入执行命令\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2019-0193\"},"
            + "{\"id\":3020,\"name\":\"Drupalgeddon2 Render API RCE\",\"pattern\":\"element_parents=account/mail/\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2018-7600\",\"vulnName\":\"Drupal core Render API RCE(Drupalgeddon2)\",\"severity\":\"critical\",\"component\":\"Drupal\",\"cvss\":9.8,\"year\":2018,\"desc\":\"Form API #post_render 回调注入执行任意代码\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2018-7600\"},"
            + "{\"id\":3021,\"name\":\"Jenkins ScriptSecurity 沙箱绕过 RCE\",\"pattern\":\"descriptorbyname/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.securescriptwhiteloader\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2018-1000861\",\"vulnName\":\"Jenkins Stapler 路由绕过沙箱 RCE\",\"severity\":\"critical\",\"component\":\"Jenkins\",\"cvss\":9.8,\"year\":2018,\"desc\":\"Stapler 动态路由调用 ScriptSecurity 描述符方法绕过沙箱执行 Groovy\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2018-1000861\"},"
            + "{\"id\":3022,\"name\":\"Hadoop YARN 未授权 RCE\",\"pattern\":\"/ws/v1/cluster/apps/new-application\",\"category\":\"AuthBypass\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"vulnName\":\"Hadoop YARN ResourceManager 未授权命令执行\",\"severity\":\"high\",\"component\":\"Apache Hadoop\",\"cvss\":9.8,\"year\":2016,\"desc\":\"ResourceManager REST API 未授权创建 application 执行任意命令\"},"
            + "{\"id\":3023,\"name\":\"ActiveMQ Web控制台探测\",\"pattern\":\"/admin/test/systemproperties.jsp\",\"category\":\"InfoLeak\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"vulnName\":\"ActiveMQ Web Console 测试页信息泄露/利用入口\",\"severity\":\"medium\",\"component\":\"Apache ActiveMQ\",\"cvss\":7.5,\"year\":2015,\"desc\":\"默认 Web 控制台 test 页面泄露系统属性，常作为漏洞利用入口\"},"
            + "{\"id\":3024,\"name\":\"vCenter vROPS 插件文件上传\",\"pattern\":\"/ui/vropspluginui/rest/services/uploadova\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"国际通用\",\"cve\":\"CVE-2021-21972\",\"vulnName\":\"VMware vCenter vROPS 插件未授权文件上传 RCE\",\"severity\":\"critical\",\"component\":\"VMware vCenter\",\"cvss\":9.8,\"year\":2021,\"desc\":\"uploadova 接口未授权上传 tar 写 webshell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2021-21972\"},"
            + "{\"id\":4001,\"name\":\"PHP 伪协议 php://input 代码执行\",\"pattern\":\"php://input\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"cve\":\"CVE-2026-6735\",\"vulnName\":\"PHP URL 净化不当致伪协议绕过\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.8,\"year\":2026,\"desc\":\"php://input 读取原始请求体传入 include/eval 执行任意代码；PHP<8.2.31/8.3.31/8.4.21/8.5.6 存在 URL 净化缺陷可绕过过滤\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-6735\"},"
            + "{\"id\":4002,\"name\":\"PHP 伪协议 php://filter 源码读取\",\"pattern\":\"php://filter\",\"category\":\"LFI\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"cve\":\"CVE-2026-6735\",\"vulnName\":\"PHP URL 净化不当致伪协议绕过\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.8,\"year\":2026,\"desc\":\"php://filter 链式过滤器 base64 读取任意源码/配置文件，常与文件包含组合 getshell\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-6735\"},"
            + "{\"id\":4003,\"name\":\"PHP phar:// 反序列化\",\"pattern\":\"phar://\",\"category\":\"Deserialization\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"vulnName\":\"PHP phar 反序列化对象注入\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.8,\"year\":2026,\"desc\":\"phar:// 触发 PHAR 元数据反序列化，配合 POP 链执行任意代码（file_exists/is_dir 等均可触发）\"},"
            + "{\"id\":4004,\"name\":\"PHP data://text/plain 代码执行\",\"pattern\":\"data://text/plain\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"vulnName\":\"PHP data 包装器远程代码执行\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.8,\"year\":2026,\"desc\":\"allow_url_include 开启时 data://text/plain;base64,<payload> 直接 include 执行任意 PHP 代码\"},"
            + "{\"id\":4005,\"name\":\"PHP expect:// 命令执行\",\"pattern\":\"expect://\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"vulnName\":\"PHP expect 包装器命令执行\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.8,\"year\":2026,\"desc\":\"expect:// 包装器直接执行系统命令，无需上传文件\"},"
            + "{\"id\":4006,\"name\":\"PHP-CGI auto_prepend_file 参数注入\",\"pattern\":\"auto_prepend_file\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"cve\":\"CVE-2026-109618\",\"vulnName\":\"PHP2Shell 未认证远程代码执行\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.2,\"year\":2026,\"desc\":\"PHP-CGI 模式下通过查询串注入 -d auto_prepend_file=php://input 执行请求体代码（PHP2Shell 利用链）\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-109618\"},"
            + "{\"id\":4007,\"name\":\"PHP-CGI allow_url_include 参数注入\",\"pattern\":\"allow_url_include\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"PHP漏洞防护\",\"cve\":\"CVE-2026-109619\",\"vulnName\":\"PHP2Shell 未认证远程代码执行\",\"severity\":\"critical\",\"component\":\"PHP\",\"cvss\":9.2,\"year\":2026,\"desc\":\"PHP-CGI 模式下注入 -d allow_url_include=1 配合 data://php:// 包装器远程包含执行代码（PHP2Shell 利用链）\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-109619\"},"
            + "{\"id\":5001,\"name\":\"Ivanti Sentry handleMessage 命令注入\",\"pattern\":\"/mics/api/v2/sentry/mics-config/handlemessage\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"cve\":\"CVE-2026-10520\",\"vulnName\":\"Ivanti Sentry OS 命令注入 RCE\",\"severity\":\"critical\",\"component\":\"Ivanti Sentry\",\"cvss\":10.0,\"year\":2026,\"desc\":\"未认证 POST handleMessage 接口注入 commandexec 指令以 root 执行任意命令，watchTowr 已公开 PoC 且在野利用，修复版本 R10.5.2/R10.6.2/R10.7.1\",\"ref\":\"https://www.cve.org/CVERecord?id=CVE-2026-10520\"},"
            + "{\"id\":5002,\"name\":\"AhsayCBS UpdateReceivers 命令注入\",\"pattern\":\"/rps/api/json/updatereceivers.do\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"cve\":\"CVE-2026-105134\",\"vulnName\":\"AhsayCBS 备份平台命令注入 RCE\",\"severity\":\"critical\",\"component\":\"AhsayCBS\",\"cvss\":10.0,\"year\":2026,\"desc\":\"random 参数 OS 命令注入，与 CVE-2026-105133 认证绕过组合在野利用投放 JSP webshell 与 XMRig 挖矿，升级 10.3.4 修复\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-105134\"},"
            + "{\"id\":5003,\"name\":\"Chamilo LMS big-upload 未授权文件上传\",\"pattern\":\"big-upload.php\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"cve\":\"CVE-2026-45140\",\"vulnName\":\"Chamilo LMS CStudio 未授权文件上传 RCE\",\"severity\":\"critical\",\"component\":\"Chamilo LMS\",\"cvss\":9.8,\"year\":2026,\"desc\":\"CStudio 插件 big-upload.php 上传流程缺陷，未认证上传恶意文件 getshell，2.0.1 修复\",\"ref\":\"https://www.wiz.io/vulnerability-database/cve/cve-2026-45140\"},"
            + "{\"id\":5004,\"name\":\"NetScaler doAuthentication 日志注入 RCE\",\"pattern\":\"/nf/auth/doauthentication.do\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"cve\":\"CVE-2026-88771\",\"vulnName\":\"Citrix NetScaler ADC/Gateway 预认证命令注入\",\"severity\":\"critical\",\"component\":\"Citrix NetScaler\",\"cvss\":9.5,\"year\":2026,\"desc\":\"login 参数写入伪造 Pitboss 日志行，ns_monuploadd_err.pl 解析时 shell 注入执行命令投递 webshell（应急虚拟补丁：若 WAF 前置真实 NetScaler 网关请按需停用以免阻断 VPN 登录）\",\"ref\":\"https://kudelskisecurity.com/research/citrix-netscaler-adc-and-netscaler-gateway-remote-code-execution-zero-days\"},"
            + "{\"id\":5005,\"name\":\"泛微E-cology dubboApi debug 未授权 RCE\",\"pattern\":\"/papi/esearch/data/devops/dubboapi/debug/method\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"cve\":\"CVE-2026-22679\",\"vulnName\":\"泛微 E-cology 10.0 未授权远程代码执行\",\"severity\":\"critical\",\"component\":\"泛微OA(Weaver)\",\"cvss\":9.8,\"year\":2026,\"desc\":\"debug/method 端点 interfaceName/methodName 未校验直通 Dubbo RPC 调用命令执行，2026年3月起在野利用，升级至 20260312 补丁修复\",\"ref\":\"https://nvd.nist.gov/vuln/detail/CVE-2026-22679\"},"
            + "{\"id\":5006,\"name\":\"金蝶EAS BSHService 未授权文件上传\",\"pattern\":\"/ormrpc/services/bshservice\",\"category\":\"RCE\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"vulnName\":\"金蝶 EAS BSHService 任意文件上传 RCE\",\"severity\":\"critical\",\"component\":\"金蝶EAS(Kingdee)\",\"cvss\":9.8,\"year\":2026,\"desc\":\"BSHService 接口未授权任意文件上传导致远程命令执行，官方建议该接口仅允许内网可信 IP 访问\",\"ref\":\"https://inc.tsu.edu.cn/2026/0409/c3545a134325/page.htm\"},"
            + "{\"id\":5007,\"name\":\"用友U8Cloud XChangeServlet SQL注入\",\"pattern\":\"xchangeservlet\",\"category\":\"SQLi\",\"action\":\"block\",\"enabled\":true,\"group\":\"2026应急\",\"vulnName\":\"用友 U8Cloud XChangeServlet SQL注入\",\"severity\":\"critical\",\"component\":\"用友U8Cloud(Yonyou)\",\"cvss\":9.8,\"year\":2026,\"desc\":\"XChangeServlet 接口存在 SQL 注入，未认证攻击者可注入恶意 SQL 窃取/篡改数据，2026年7月公开\",\"ref\":\"https://net.xmu.edu.cn/info/1041/9522.htm\"}"
            + "]";

    public void ensureRulesSeed() {
        String cur = redis.opsForValue().get("novawaf:rules");
        if (cur == null || cur.isBlank() || "[]".equals(cur.trim())) {
            redis.opsForValue().set("novawaf:rules", DEFAULT_RULES);
            bumpRulesVersion();
        }
    }

    /** 防护应用列表(novawaf:apps)，叠加每应用今日统计与引擎能力标签 */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> apps() {
        List<Map<String, Object>> out = new ArrayList<>();
        Object obj = getJson("novawaf:apps");
        if (!(obj instanceof List)) return out;
        long todayStartMin = ((long) (System.currentTimeMillis() / 1000) / 86400) * 86400 / 60; // 今日 0 点的分钟桶
        // 引擎已具备的防护能力（全局生效），按真实能力标注
        List<String> features = List.of("攻击防护", "CC防护", "BOT防护", "身份认证");
        for (Object o : (List<Object>) obj) {
            if (!(o instanceof Map)) continue;
            Map<String, Object> a = (Map<String, Object>) o;
            Object idO = a.get("id");
            String id = idO == null ? "" : String.valueOf(idO);
            long todayReq = 0, todayBlk = 0, qps = 0;
            // 今日请求/拦截：累加 novawaf:traffic:{id} 今日各分钟桶
            try {
                List<String> buckets = redis.opsForList().range("novawaf:traffic:" + id, 0, -1);
                if (buckets != null) for (String s : buckets) {
                    Object bo = parse(s);
                    if (!(bo instanceof Map)) continue;
                    Map<String, Object> b = (Map<String, Object>) bo;
                    if (toLong(b.get("t")) < todayStartMin) continue;
                    todayReq += toLong(b.get("req"));
                    todayBlk += toLong(b.get("blk"));
                }
            } catch (Exception ignore) {}
            // 实时 QPS：取 novawaf:traffic:stat:{id}
            try {
                Object so = getJson("novawaf:traffic:stat:" + id);
                if (so instanceof Map) qps = toLong(((Map<String, Object>) so).get("qps"));
            } catch (Exception ignore) {}
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("name", a.get("name"));
            m.put("host", a.get("host"));
            m.put("upstreamHost", a.get("upstreamHost"));
            m.put("upstreamPort", a.get("upstreamPort"));
            m.put("statsEnabled", Boolean.TRUE.equals(a.get("statsEnabled")));
            m.put("loginUrl", a.get("loginUrl") == null ? "" : a.get("loginUrl"));
            String mv = str(a.get("mode"));
            m.put("mode", "observe".equals(mv) ? "观察" : "maintenance".equals(mv) ? "维护" : "防护");
            m.put("todayReq", todayReq);
            m.put("todayBlock", todayBlk);
            m.put("qps", qps);
            m.put("features", features);
            out.add(m);
        }
        return out;
    }

    /** 新增防护应用：校验后写回 novawaf:apps 并递增版本号触发引擎热加载 */
    @SuppressWarnings("unchecked")
    public synchronized void addApp(Map<String, Object> req) {
        List<Object> list = readApps();
        String host = str(req.get("host")).trim();
        String upHost = str(req.get("upstreamHost")).trim();
        long port = toLong(req.get("upstreamPort"));
        String name = str(req.get("name")).trim();
        if (host.isEmpty()) throw new BusinessException(400, "域名不能为空");
        if (upHost.isEmpty()) throw new BusinessException(400, "上游地址不能为空");
        if (port < 1 || port > 65535) throw new BusinessException(400, "上游端口非法(1-65535)");
        // host/上游必须是纯主机名或 IP，禁止协议头、路径、端口，否则会匹配不到应用或造成回环
        if (host.contains("://") || host.contains("/") || host.contains(":") || host.matches(".*\\s.*"))
            throw new BusinessException(400, "防护域名只能是主机名/IP(如 nac 或 192.168.100.2)，不能带 http://、路径或端口");
        if (upHost.contains("://") || upHost.contains("/") || upHost.matches(".*\\s.*"))
            throw new BusinessException(400, "上游地址只能是主机名/IP，不能带协议、路径或端口(端口单独填)");
        // 防回环：上游不能指向本机对外入口端口(如 443/80 经 nginx 又回到 WAF)
        if (port == 443 || port == 80)
            throw new BusinessException(400, "上游端口不能是 80/443(会与 nginx 入口形成回环)");
        for (Object o : list) {
            if (o instanceof Map && host.equalsIgnoreCase(str(((Map<String, Object>) o).get("host"))))
                throw new BusinessException(409, "域名已存在: " + host);
        }
        int maxId = 0;
        for (Object o : list) if (o instanceof Map) maxId = Math.max(maxId, (int) toLong(((Map<String, Object>) o).get("id")));
        Map<String, Object> app = new LinkedHashMap<>();
        app.put("id", maxId + 1);
        app.put("name", name.isEmpty() ? host : name);
        app.put("host", host);
        app.put("upstreamHost", upHost);
        app.put("upstreamPort", (int) port);
        app.put("statsEnabled", Boolean.TRUE.equals(req.get("statsEnabled")));
        app.put("loginUrl", normLoginUrl(req.get("loginUrl")));
        app.put("mode", normMode(req.get("mode")));
        app.put("default", false);
        list.add(app);
        persistApps(list);
    }

    /** 归一化运行模式：protect(防护)/observe(观察)/maintenance(维护) */
    private String normMode(Object o) {
        String v = str(o);
        return ("observe".equals(v) || "maintenance".equals(v)) ? v : "protect";
    }

    /** 归一化登录页地址：允许空、http(s):// 绝对地址、以 / 开头的同源路径；其余一律拒绝 */
    private String normLoginUrl(Object o) {
        String v = str(o).trim();
        if (v.isEmpty()) return "";
        if (!(v.startsWith("/") || v.startsWith("http://") || v.startsWith("https://")))
            throw new BusinessException(400, "登录页地址必须是 http(s):// 开头的完整地址，或以 / 开头的站内路径");
        if (v.matches(".*\\s.*")) throw new BusinessException(400, "登录页地址不能包含空白字符");
        return v;
    }

    /** 设置应用运行模式 */
    @SuppressWarnings("unchecked")
    public synchronized void setAppMode(String id, String mode) {
        String m = normMode(mode);
        List<Object> list = readApps();
        boolean found = false;
        for (Object o : list) {
            if (o instanceof Map && id.equals(str(((Map<String, Object>) o).get("id")))) {
                ((Map<String, Object>) o).put("mode", m);
                found = true;
                break;
            }
        }
        if (!found) throw new BusinessException(404, "应用不存在: id=" + id);
        persistApps(list);
    }

    /** 修改防护应用 */
    @SuppressWarnings("unchecked")
    public synchronized void updateApp(String id, Map<String, Object> req) {
        List<Object> list = readApps();
        String host = str(req.get("host")).trim();
        String upHost = str(req.get("upstreamHost")).trim();
        long port = toLong(req.get("upstreamPort"));
        String name = str(req.get("name")).trim();
        if (host.isEmpty()) throw new BusinessException(400, "域名不能为空");
        if (upHost.isEmpty()) throw new BusinessException(400, "上游地址不能为空");
        if (port < 1 || port > 65535) throw new BusinessException(400, "上游端口非法(1-65535)");
        if (host.contains("://") || host.contains("/") || host.contains(":") || host.matches(".*\\s.*"))
            throw new BusinessException(400, "防护域名只能是主机名/IP(如 nac 或 192.168.100.2)，不能带 http://、路径或端口");
        if (upHost.contains("://") || upHost.contains("/") || upHost.matches(".*\\s.*"))
            throw new BusinessException(400, "上游地址只能是主机名/IP，不能带协议、路径或端口(端口单独填)");
        if (port == 443 || port == 80)
            throw new BusinessException(400, "上游端口不能是 80/443(会与 nginx 入口形成回环)");
        boolean found = false;
        for (Object o : list) {
            if (!(o instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> a = (Map<String, Object>) o;
            if (!id.equals(str(a.get("id")))) continue;
            // 域名变更时校验不与其它应用重复
            if (!host.equalsIgnoreCase(str(a.get("host")))) {
                for (Object o2 : list) {
                    if (o2 instanceof Map && o2 != o
                            && host.equalsIgnoreCase(str(((Map<String, Object>) o2).get("host"))))
                        throw new BusinessException(409, "域名已存在: " + host);
                }
            }
            a.put("name", name.isEmpty() ? host : name);
            a.put("host", host);
            a.put("upstreamHost", upHost);
            a.put("upstreamPort", (int) port);
            if (req.containsKey("statsEnabled")) a.put("statsEnabled", Boolean.TRUE.equals(req.get("statsEnabled")));
            if (req.containsKey("loginUrl")) a.put("loginUrl", normLoginUrl(req.get("loginUrl")));
            if (req.containsKey("mode")) a.put("mode", normMode(req.get("mode")));
            found = true;
            break;
        }
        if (!found) throw new BusinessException(404, "应用不存在: id=" + id);
        persistApps(list);
    }

    /** 删除防护应用 */
    @SuppressWarnings("unchecked")
    public synchronized void deleteApp(String id) {
        List<Object> list = readApps();
        list.removeIf(o -> o instanceof Map && id.equals(str(((Map<String, Object>) o).get("id"))));
        persistApps(list);
    }

    @SuppressWarnings("unchecked")
    private List<Object> readApps() {
        List<Object> list = new ArrayList<>();
        Object cur = getJson("novawaf:apps");
        if (cur instanceof List) list.addAll((List<Object>) cur);
        return list;
    }

    private void persistApps(List<Object> list) {
        try {
            redis.opsForValue().set("novawaf:apps", om.writeValueAsString(list));
            redis.opsForValue().increment("novawaf:apps:version");   // 触发引擎热加载
        } catch (Exception e) {
            throw new BusinessException(500, "写入应用配置失败: " + e.getMessage());
        }
    }

    public Object stats() { return getJson("novawaf:stats"); }

    /** novawaf:ioc 是 CSV 文本, 解析为表格行 */
    public List<Map<String, String>> ioc() {
        String raw = redis.opsForValue().get("novawaf:ioc");
        List<Map<String, String>> rows = new ArrayList<>();
        if (raw == null) return rows;
        for (String line : raw.split("\\R")) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split(",", -1);
            if (f.length < 2) continue;
            Map<String, String> m = new LinkedHashMap<>();
            m.put("type", f[0]);
            m.put("value", f.length > 1 ? f[1] : "");
            m.put("severity", f.length > 2 ? f[2] : "");
            m.put("source", f.length > 3 ? f[3] : "");
            m.put("note", f.length > 4 ? f[4] : "");
            rows.add(m);
        }
        return rows;
    }

    /** novawaf:meta 是 hash, 必须用 hash 读(否则 WRONGTYPE) */
    public Map<String, String> iocMeta() {
        Map<Object, Object> raw = redis.opsForHash().entries("novawaf:meta");
        Map<String, String> m = new LinkedHashMap<>();
        if (raw != null) raw.forEach((k, v) -> m.put(String.valueOf(k), String.valueOf(v)));
        return m;
    }

    /** 最近 N 条事件(novawaf:events 是 Redis List) */
    public List<Object> events(int limit) {
        List<String> raw = redis.opsForList().range("novawaf:events", -limit, -1);
        List<Object> out = new ArrayList<>();
        if (raw != null) {
            Collections.reverse(raw);
            for (String s : raw) out.add(parse(s));
        }
        return out;
    }

    /** 攻击源真实计数(今天+昨天分桶合并): 与 TraceService 同源, 供仪表盘攻击源 TOP 使用 */
    private Map<String, Long> traceCntByIp() {
        Map<String, Long> byIp = new HashMap<>();
        java.time.LocalDate today = java.time.LocalDate.now(java.time.ZoneId.of("Asia/Shanghai"));
        for (java.time.LocalDate d : new java.time.LocalDate[]{today, today.minusDays(1)}) {
            String day = d.toString().replace("-", "");
            Map<Object, Object> cnt = redis.opsForHash().entries("novawaf:trace:cnt:" + day);
            for (Map.Entry<Object, Object> en : cnt.entrySet())
                byIp.merge(String.valueOf(en.getKey()), toLong(en.getValue()), Long::sum);
        }
        return byIp;
    }

    /** 实时 QPS 采样环形序列(novawaf:qps:ring, 每次 dashboard 调用采 1 点, 保留 120 点) */
    private List<Long> sampleQpsRing(long qps) {
        try {
            redis.opsForList().rightPush("novawaf:qps:ring", String.valueOf(qps));
            redis.opsForList().trim("novawaf:qps:ring", -120, -1);
            List<String> raw = redis.opsForList().range("novawaf:qps:ring", 0, -1);
            List<Long> out = new ArrayList<>();
            if (raw != null) for (String s : raw) out.add(toLong(s));
            return out;
        } catch (Exception e) {
            return List.of(qps);
        }
    }

    /** 仪表盘聚合: 真实对接流量统计 + 攻击事件 */
    @SuppressWarnings("unchecked")
    public Map<String, Object> dashboard() {
        Map<String, Object> out = new LinkedHashMap<>();
        // 1) 流量统计(聚合所有 novawaf:traffic:stat:* )
        long req = 0, pv = 0, blk = 0, a4 = 0, a5 = 0, qps = 0;
        Set<String> sess = new HashSet<>(), ips = new HashSet<>(), atk = new HashSet<>();
        try {
            Set<String> keys = redis.keys("novawaf:traffic:stat:*");
            if (keys != null) for (String k : keys) {
                Object o = getJson(k);
                if (!(o instanceof Map)) continue;
                Map<String, Object> m = (Map<String, Object>) o;
                Object curO = m.get("cur");
                if (curO instanceof Map) {
                    Map<String, Object> cur = (Map<String, Object>) curO;
                    req += toLong(cur.get("req")); pv += toLong(cur.get("pv"));
                    blk += toLong(cur.get("blk")); a4 += toLong(cur.get("a4")); a5 += toLong(cur.get("a5"));
                    qps = Math.max(qps, toLong(m.get("qps")));
                    addAll(sess, cur.get("sess")); addAll(ips, cur.get("ip")); addAll(atk, cur.get("atk"));
                }
            }
        } catch (Exception ignore) {}
        Map<String, Object> traffic = new LinkedHashMap<>();
        traffic.put("req", req); traffic.put("pv", pv); traffic.put("uv", sess.size());
        traffic.put("ip", ips.size()); traffic.put("blk", blk); traffic.put("a4", a4);
        traffic.put("a5", a5); traffic.put("atk", atk.size()); traffic.put("qps", qps);
        out.put("traffic", traffic);
        // QPS 采样序列(环形 120 点): 供实时 QPS 走势图, 页面刷新后立即可见历史曲线
        out.put("qpsSeries", sampleQpsRing(qps));

        // 2) 全局统计
        Object stats = getJson("novawaf:stats");
        out.put("stats", stats == null ? Map.of() : stats);

        // 3) 基于 events 的聚合(趋势/类型/规则/动作)
        List<Object> evs = events(500);
        Map<String, Long> byCat = new HashMap<>(), byRule = new HashMap<>(), byAction = new HashMap<>();
        TreeMap<Long, Long> trend = new TreeMap<>();
        for (Object e : evs) {
            if (!(e instanceof Map)) continue;
            Map<String, Object> ev = (Map<String, Object>) e;
            inc(byCat, str(ev.get("category")));
            inc(byRule, str(ev.get("ruleId")));
            inc(byAction, str(ev.get("action")));
            long ts = toLong(ev.get("ts"));
            if (ts > 0) inc(trend, (ts / 60) * 60); // 按分钟桶
        }
        out.put("byCategory", byCat);
        out.put("byRule", byRule);
        out.put("byAction", byAction);
        // 攻击源 TOP 改读引擎按天分桶的真实累计(novawaf:trace:cnt:YYYYMMDD, HINCRBY 持久计数,
        // 不封顶/不被高频源从明细窗口挤占): 修复 events 环形窗口被高频攻击源刷满后只剩单一 IP 的问题
        out.put("topIps", topN(traceCntByIp(), 10));
        // 趋势转数组：固定展示最近10分钟，按分钟桶补零，避免只出现有事件的分钟点
        List<Map<String, Object>> trendArr = new ArrayList<>();
        long curMin = (System.currentTimeMillis() / 1000 / 60) * 60;
        for (int i = 9; i >= 0; i--) {
            long t = curMin - i * 60L;
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("t", t); p.put("count", trend.getOrDefault(t, 0L)); trendArr.add(p);
        }
        out.put("trend", trendArr);
        out.put("events", evs.size() > 30 ? evs.subList(0, 30) : evs);

        // 4) 访问明细聚合(状态/国家/客户端/系统/受访域名/来源域名/受访页面)
        out.putAll(accessAgg(3000));
        return out;
    }

    /** 聚合 novawaf:access 访问日志流 */
    @SuppressWarnings("unchecked")
    private Map<String, Object> accessAgg(int limit) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Long> byStatus = new HashMap<>(), byCountry = new HashMap<>();
        Map<String, Long> byBrowser = new HashMap<>(), byOs = new HashMap<>();
        Map<String, Long> byHost = new HashMap<>(), byReferer = new HashMap<>();
        Map<String, Long> pageCnt = new HashMap<>();
        long total = 0;
        try {
            List<String> raw = redis.opsForList().range("novawaf:access", -limit, -1);
            if (raw != null) for (String s : raw) {
                Object o = parse(s);
                if (!(o instanceof Map)) continue;
                Map<String, Object> r = (Map<String, Object>) o;
                total++;
                String st = str(r.get("st"));
                inc(byStatus, st.isEmpty() ? "0" : st);
                String cty = str(r.get("cty"));
                inc(byCountry, cty.isEmpty() ? "未知" : cty);
                String ua = str(r.get("ua"));
                inc(byBrowser, browserOf(ua));
                inc(byOs, osOf(ua));
                String host = str(r.get("host"));
                inc(byHost, host.isEmpty() ? "-" : host);
                inc(byReferer, refererDomainOf(str(r.get("ref"))));
                inc(pageCnt, str(r.get("p")));
            }
        } catch (Exception ignore) {}
        out.put("accessTotal", total);
        out.put("byStatus", topN(byStatus, 15));
        out.put("byCountry", topN(byCountry, 15));
        out.put("byBrowser", topN(byBrowser, 10));
        out.put("byOs", topN(byOs, 10));
        out.put("byHost", topN(byHost, 15));
        out.put("byReferer", topN(byReferer, 15));
        out.put("topPages", topN(pageCnt, 15));
        return out;
    }

    private String browserOf(String ua) {
        if (ua == null || ua.isBlank()) return "未知";
        String u = ua.toLowerCase();
        if (u.contains("edg/")) return "Edge";
        if (u.contains("chrome/")) return "Chrome";
        if (u.contains("firefox/")) return "Firefox";
        if (u.contains("safari/")) return "Safari";
        if (u.contains("sqlmap")) return "sqlmap";
        if (u.contains("curl")) return "curl";
        if (u.contains("python")) return "Python";
        if (u.contains("go-http")) return "Go-http";
        return "其他";
    }
    private String osOf(String ua) {
        if (ua == null || ua.isBlank()) return "未知";
        String u = ua.toLowerCase();
        if (u.contains("windows")) return "Windows";
        if (u.contains("android")) return "Android";
        if (u.contains("iphone") || u.contains("ipad")) return "iOS";
        if (u.contains("mac os") || u.contains("macintosh")) return "macOS";
        if (u.contains("linux")) return "Linux";
        return "其他";
    }
    private String refererDomainOf(String ref) {
        if (ref == null || ref.isBlank()) return "直接访问";
        try {
            String s = ref;
            int p = s.indexOf("://");
            if (p >= 0) s = s.substring(p + 3);
            int slash = s.indexOf('/');
            if (slash >= 0) s = s.substring(0, slash);
            int q = s.indexOf('?');
            if (q >= 0) s = s.substring(0, q);
            return s.isEmpty() ? "直接访问" : s;
        } catch (Exception e) { return "直接访问"; }
    }

    private long toLong(Object o) { if (o == null) return 0; try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; } }
    private String str(Object o) { return o == null ? "" : String.valueOf(o); }
    private void inc(Map<String, Long> m, String k) { if (k == null || k.isEmpty()) return; m.merge(k, 1L, Long::sum); }
    private void inc(Map<Long, Long> m, Long k) { m.merge(k, 1L, Long::sum); }
    @SuppressWarnings("unchecked")
    private void addAll(Set<String> set, Object o) { if (o instanceof List) for (Object x : (List<Object>) o) set.add(String.valueOf(x)); }
    private List<Map<String, Object>> topN(Map<String, Long> m, int n) {
        return m.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(n)
                .map(e -> { Map<String, Object> p = new LinkedHashMap<>(); p.put("name", e.getKey()); p.put("value", e.getValue()); return p; })
                .toList();
    }

    /** bump 规则版本号触发引擎热加载 */
    public void bumpRulesVersion() {
        redis.opsForValue().increment("novawaf:rules:version");
    }

    public void setRules(String json) {
        redis.opsForValue().set("novawaf:rules", json);
        bumpRulesVersion();
    }
}
