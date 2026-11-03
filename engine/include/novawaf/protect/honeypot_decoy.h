// NovaWAF - 蜜罐诱饵内容渲染（观察模式核心：让踩点者"有所收获"，延长交互取证）
// 背景（复测设计评审）：蜜罐命中响应与 WAF 规则命中页完全同构，攻击者一眼识别
// 处置边界；且「命中即封禁」使取证链中断。改造为「记录+打标+诱饵放行」：
// 命中诱饵路径返回仿真内容（200 + 以假乱真的 .git 配置/.env/wp-login 页面），
// 攻击者继续深入 → 采集完整攻击链；触达 N 个不同诱饵后由 HoneypotGuard 升级封禁。
// 所有内容均为精心构造的假数据（凭证为随机占位串），绝不泄露真实信息。
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <ctime>

namespace novawaf {

class HoneypotDecoy {
public:
    // 按诱饵路径生成完整 200 响应（含状态行与头）。banner 为全站统一人格 Server 头。
    static std::string render(const std::string& path, const std::string& banner) {
        std::string body;
        std::string ctype = "text/html; charset=utf-8";
        if (starts(path, "/.git/"))            { body = gitBody(path);  ctype = "text/plain"; }
        else if (path == "/.env")              { body = envBody();      ctype = "text/plain"; }
        else if (starts(path, "/.svn/"))       { body = svnBody();      ctype = "text/plain"; }
        else if (starts(path, "/.aws/"))       { body = awsBody();      ctype = "application/json"; }
        else if (starts(path, "/.ssh/"))       { body = sshBody();      ctype = "text/plain"; }
        else if (starts(path, "/wp-admin") || starts(path, "/wp-includes") ||
                 starts(path, "/wordpress") || path == "/wp-login.php")
                                               { body = wpLoginHtml(); }
        else if (starts(path, "/phpmyadmin") || starts(path, "/pma"))
                                               { body = pmaHtml(); }
        else if (path == "/phpinfo.php")       { body = phpinfoHtml(); }
        else if (path == "/admin.php")         { body = adminHtml(); }
        else if (ends(path, ".php"))           { body = ""; }  // webshell 无参访问通常空输出
        else if (ends(path, ".sql"))           { body = sqlBody();      ctype = "text/plain"; }
        else if (ends(path, ".zip"))           { body = zipNote();      ctype = "text/plain"; }
        else if (path == "/web.config")        { body = webConfigXml(); ctype = "text/xml"; }
        else if (ends(path, ".bak"))           { body = configBak();    ctype = "text/plain"; }
        else if (path == "/server-status")     { body = serverStatusHtml(); }
        else if (starts(path, "/actuator"))    { body = actuatorJson(); ctype = "application/json"; }
        else if (starts(path, "/HNAP1"))       { body = hnapXml();      ctype = "text/xml"; }
        else if (starts(path, "/solr"))        { body = solrJson();     ctype = "application/json"; }
        else if (starts(path, "/jenkins"))     { body = jenkinsHtml(); }
        else                                   { body = adminHtml(); }

        std::string resp;
        resp.reserve(body.size() + 256);
        resp += "HTTP/1.1 200 OK\r\nServer: " + banner + "\r\n"
                "Content-Type: " + ctype + "\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        resp += body;
        return resp;
    }

private:
    static bool starts(const std::string& s, const char* pfx) {
        return s.compare(0, std::string(pfx).size(), pfx) == 0;
    }
    static bool ends(const std::string& s, const char* sfx) {
        std::string t(sfx);
        return s.size() >= t.size() && s.compare(s.size() - t.size(), t.size(), t) == 0;
    }

    // 伪随机十六串（时间+路径混合，内容不成为静态签名；仅为仿真，非安全用途）
    static std::string fakeHex(const char* salt, int len) {
        uint64_t h = 1469598103934665603ULL ^ (uint64_t)time(nullptr) / 3600;  // 小时级变化
        for (const char* p = salt; *p; ++p) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
        std::string out;
        static const char* kHex = "0123456789abcdef";
        for (int i = 0; i < len; ++i) {
            h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
            out += kHex[h & 15];
        }
        return out;
    }

    static std::string gitBody(const std::string& path) {
        if (path.find("HEAD") != std::string::npos)
            return "ref: refs/heads/master\n";
        if (path.find("config") != std::string::npos)
            return "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                   "\tbare = false\n\tlogallrefupdates = true\n"
                   "[remote \"origin\"]\n\turl = git@github.com:site/webapp.git\n"
                   "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
                   "[branch \"master\"]\n\tremote = origin\n\tmerge = refs/heads/master\n";
        if (path.find("index") != std::string::npos)
            return "DIRC\x00\x00\x00\x02";  // git index 魔数前缀
        return "refs/heads/master\nrefs/remotes/origin/master\n";
    }
    static std::string envBody() {
        return "APP_NAME=WebApp\nAPP_ENV=production\nAPP_DEBUG=false\n"
               "APP_KEY=base64:" + fakeHex("env-key", 32) + "\n"
               "DB_HOST=127.0.0.1\nDB_DATABASE=webapp\nDB_USERNAME=webapp\n"
               "DB_PASSWORD=" + fakeHex("db-pass", 16) + "\n"
               "REDIS_HOST=127.0.0.1\nCACHE_DRIVER=file\nSESSION_DRIVER=file\n";
    }
    static std::string svnBody() {
        return "12\n\nurn:uuid:" + fakeHex("svn-uuid", 8) + "-" + fakeHex("svn2", 4) +
               "\nfile:///svn/webapp\n";
    }
    static std::string awsBody() {
        return "{\"Version\": 1, \"AccessKeyId\": \"AKIA" + fakeHex("aws", 16) +
               "\", \"SecretAccessKey\": \"" + fakeHex("aws-secret", 32) + "\"}";
    }
    static std::string sshBody() {
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + fakeHex("ssh", 64) + " deploy@webapp\n";
    }
    static std::string sqlBody() {
        return "-- MySQL dump 10.19, Distrib 10.3.38, for debian-linux-gnu (x86_64)\n"
               "-- Host: localhost    Database: webapp\n"
               "CREATE TABLE `users` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
               "  `username` varchar(64) NOT NULL,\n  `password_hash` varchar(128) NOT NULL,\n"
               "  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
               "-- (0 rows affected)\n";
    }
    static std::string zipNote() { return "PK\x03\x04 archive backup (download incomplete)"; }
    static std::string webConfigXml() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n"
               "  <system.web><customErrors mode=\"Off\"/></system.web>\n</configuration>\n";
    }
    static std::string configBak() {
        return "<?php\ndefine('DB_HOST', 'localhost');\ndefine('DB_NAME', 'webapp');\n"
               "define('DB_USER', 'webapp');\ndefine('DB_PASS', '" + fakeHex("cfg", 16) + "');\n";
    }
    static std::string actuatorJson() {
        return "{\"_links\":{\"self\":{\"href\":\"/actuator\",\"templated\":false},"
               "\"health\":{\"href\":\"/actuator/health\",\"templated\":false},"
               "\"env\":{\"href\":\"/actuator/env\",\"templated\":false},"
               "\"metrics\":{\"href\":\"/actuator/metrics\",\"templated\":false}}}";
    }
    static std::string hnapXml() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
               "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
               "<soap:Body><GetDeviceSettingsResponse xmlns=\"http://purenetworks.com/HNAP1/\">"
               "<Result>OK</Result><VendorName>Alpha</VendorName><ModelName>DIR-868L</ModelName>"
               "</GetDeviceSettingsResponse></soap:Body></soap:Envelope>";
    }
    static std::string solrJson() {
        return "{\"responseHeader\":{\"status\":0,\"QTime\":1},\"response\":{\"numFound\":0,"
               "\"start\":0,\"docs\":[]}}";
    }

    static std::string wpLoginHtml() {
        return "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
               "<title>Log In &lsaquo; WebApp &#8212; WordPress</title>"
               "<link rel=\"stylesheet\" href=\"/wp-admin/css/login.min.css\"></head>"
               "<body class=\"login\"><div id=\"login\"><h1><a href=\"https://wordpress.org/\">"
               "Powered by WordPress</a></h1><form name=\"loginform\" id=\"loginform\" "
               "action=\"/wp-login.php\" method=\"post\"><p><label>Username or Email Address"
               "<input type=\"text\" name=\"log\" class=\"input\"></label></p>"
               "<p><label>Password<input type=\"password\" name=\"pwd\" class=\"input\"></label></p>"
               "<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" "
               "class=\"button button-primary\" value=\"Log In\"></p></form></div></body></html>";
    }
    static std::string pmaHtml() {
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
               "<title>phpMyAdmin</title></head><body>"
               "<div class=\"logo\"><a href=\"https://www.phpmyadmin.net/\">phpMyAdmin</a></div>"
               "<form method=\"post\" action=\"/phpmyadmin/index.php\">"
               "<fieldset><legend>Log in</legend>"
               "<div>Username: <input type=\"text\" name=\"pma_username\"></div>"
               "<div>Password: <input type=\"password\" name=\"pma_password\"></div>"
               "<div><input type=\"submit\" value=\"Go\"></div></fieldset></form></body></html>";
    }
    static std::string phpinfoHtml() {
        return "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>"
               "<div class=\"center\"><table border=\"0\" cellpadding=\"3\" width=\"600\">"
               "<tr class=\"h\"><td><h1>PHP Version 7.4.33</h1></td></tr></table>"
               "<table border=\"0\" cellpadding=\"3\" width=\"600\">"
               "<tr><td class=\"e\">System</td><td class=\"v\">Linux webapp 5.15.0-91-generic</td></tr>"
               "<tr><td class=\"e\">Server API</td><td class=\"v\">FPM/FastCGI</td></tr>"
               "</table></div></body></html>";
    }
    static std::string adminHtml() {
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Administration</title>"
               "</head><body><h2>Site Administration</h2>"
               "<form method=\"post\" action=\"/admin.php\">"
               "<p>User: <input name=\"user\"></p><p>Pass: <input type=\"password\" name=\"pass\"></p>"
               "<p><input type=\"submit\" value=\"Login\"></p></form></body></html>";
    }
    static std::string serverStatusHtml() {
        return "<!DOCTYPE html><html><head><title>Apache Status</title></head><body>"
               "<h1>Apache Server Status for 127.0.0.1</h1>"
               "<dl><dt>Server Version: Apache/2.4.52 (Ubuntu)</dt>"
               "<dt>Current Time: " + std::to_string(time(nullptr)) + "</dt>"
               "<dt>Total accesses: 12843 - CPU Usage: u12.3 s1.2</dt></dl></body></html>";
    }
    static std::string jenkinsHtml() {
        return "<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title></head>"
               "<body><div class=\"login\"><h1>Jenkins</h1>"
               "<form method=\"post\" action=\"/j_acegi_security_check\">"
               "<input name=\"j_username\" placeholder=\"Username\">"
               "<input name=\"j_password\" type=\"password\" placeholder=\"Password\">"
               "<input type=\"submit\" value=\"Sign in\"></form></div></body></html>";
    }
};

}  // namespace novawaf
