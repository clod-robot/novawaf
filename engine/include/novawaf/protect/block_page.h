// NovaWAF - 统一拦截/挑战响应渲染（独立拦截页 + 追踪ID + 指纹三态）
// 设计：
//   * 全引擎唯一拦截页出口，替换散落的 44 字节占位响应。
//   * 每次拦截生成全局唯一 Trace ID（trc-时间基36-随机5位），写入响应页 + X-Request-Id
//     响应头 + AttackEvent.trace，用户在控制台可按 ID 一键溯源完整攻击事件。
//   * 指纹三态：PUBLIC 输出品牌页 + X-WAF 头（wafw00f 可识别）；
//     HIDDEN 输出无品牌通用页 + Server: nginx 伪装（混入正常站点流量）。
//   * 纯函数无状态，热路径零分配之外的负担可忽略（拦截本就是低频冷路径）。
#pragma once

#include "novawaf/protect/mimic.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <sys/random.h>

namespace novawaf {

class BlockPage {
public:
    // 追踪 ID 生成：<base36时间>-<8位随机hex>，全局唯一、可按时间排序。
    // 故意不使用固定前缀（如 trc-），避免响应头/页面形成可被指纹库固化的产品级标识；
    // 排障仍可按该 ID 在事件中心溯源（控制台按 IP/时间关联）。
    static std::string genTraceId() {
        static const char* b36 = "0123456789abcdefghijklmnopqrstuvwxyz";
        uint64_t t = (uint64_t)std::time(nullptr);
        char tb[16];
        int i = 15;
        tb[i] = '\0';
        do { tb[--i] = b36[t % 36]; t /= 36; } while (t && i > 0);
        uint32_t rnd = 0;
        if (::getrandom(&rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) {
            rnd = (uint32_t)(t * 2654435761u) ^ 0x9e3779b9u;
        }
        char rb[10];
        std::snprintf(rb, sizeof(rb), "%08x", rnd);
        return std::string(tb + i) + "-" + rb;
    }

    // 渲染完整 HTTP 响应（状态行+头+HTML体）。
    //   status/statusText : 403 Forbidden / 503 Service Unavailable
    //   title             : 页面主标题（如"请求已被拦截"/"访问频率异常"）
    //   detail            : 补充说明（如命中类别，不泄露具体规则细节给攻击者）
    //   traceId           : genTraceId() 产物
    //   branded           : true=PUBLIC 品牌输出；false=HIDDEN 无品牌伪装
    static std::string render(const char* status, const char* statusText,
                              const std::string& title, const std::string& detail,
                              const std::string& traceId, bool branded) {
        // HIDDEN 模式（branded=false）：拦截页必须伪装成站点原生错误，不出现"拦截/防护"等
        // 自我宣告字样，否则等于向攻击者暴露 WAF 存在并提供"被拦=载荷被识别"的即时反馈通道。
        // 标题统一为状态码+状态文本，详情留空；PUBLIC 模式保留品牌化中文提示。
        std::string t = title;
        std::string d = detail;
        if (!branded) {
            t = std::string(status) + " " + statusText;
            d.clear();
        }
        std::string body = html(t, d, traceId, branded);
        std::string resp;
        resp.reserve(body.size() + 512);
        resp += "HTTP/1.1 ";
        resp += status;
        resp += " ";
        resp += statusText;
        resp += "\r\nContent-Type: text/html; charset=utf-8\r\n"
                "Cache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\n";
        if (branded) {
            // PUBLIC：品牌输出并回显追踪 ID，便于用户报障溯源
            resp += "Server: NovaWAF\r\nX-WAF: NovaWAF\r\n";
            resp += "X-Request-Id: " + traceId + "\r\n";
        } else {
            // HIDDEN：不向客户端回显 X-Request-Id（格式再随机也是可提取的弱特征；
            // 溯源 ID 只留在服务端事件中心，控制台按 IP/时间关联）。
            resp += "Server: " + MimicDefense::siteBanner() + "\r\n";
        }
        resp += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        resp += body;
        return resp;
    }

    // 拟态渲染：按画像输出目标服务器风格的原生错误页（无品牌、无 NovaWAF 痕迹）。
    //   tpl: 0=nginx 风格 1=Apache 风格 2=IIS 风格 3=nginx 404 风格 4=nginx 503 风格
    //   banner: Server 响应头与页脚签名（与画像一致）
    // 追踪 ID 不回显给客户端（格式再随机也是可提取的弱特征）；
    // 溯源走事件中心，控制台按 IP/时间关联。
    static std::string renderMimic(int status, const char* statusText, int tpl,
                                   const char* banner, const std::string& traceId) {
        (void)traceId;
        std::string body = mimicHtml(status, statusText, tpl, banner);
        std::string resp;
        resp.reserve(body.size() + 256);
        resp += "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n"
                "Server: " + banner + "\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        resp += body;
        return resp;
    }

    // 全站统一人格的通用错误页（413/429/400 等低频错误）。
    // 与拦截页同一 IIS 风格模板 + 固定 banner，消除不同错误出口之间的指纹分裂。
    // extraHead：可选附加响应头（如 "Retry-After: 60\r\n"）。
    static std::string renderStatus(int status, const char* statusText,
                                    const std::string& extraHead = "") {
        const std::string banner = MimicDefense::siteBanner();
        std::string body = iisHtml(status, statusText);
        std::string resp;
        resp.reserve(body.size() + 256);
        resp += "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n"
                "Server: " + banner + "\r\n"
                "Content-Type: text/html\r\n" + extraHead +
                "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        resp += body;
        return resp;
    }

    // 上游默认错误页正文改写（复测新增项：301/404 只改了 Server 头没改体，
    // <center>nginx</center> 默认页经 WAF 透传造成人格分裂）。
    // 判定特征：状态码在典型错误集合内 且 body 含 nginx 默认页签名；
    // 命中则以全站统一 IIS 人格模板重建 body，保留 Location/Date 等业务头，
    // 重写 Server/Content-Type/Content-Length。非错误页或业务自有错误页不动。
    static void rewriteUpstreamErrorBody(std::string& resp) {
        // 状态码解析
        if (resp.compare(0, 9, "HTTP/1.1 ") != 0 && resp.compare(0, 9, "HTTP/1.0 ") != 0)
            return;
        int status = std::atoi(resp.c_str() + 9);
        switch (status) {
            case 301: case 302: case 400: case 403: case 404: case 405:
            case 500: case 502: case 503: case 504: case 505: break;
            default: return;
        }
        size_t he = resp.find("\r\n\r\n");
        if (he == std::string::npos) return;
        // nginx 默认页签名：<center>nginx（页脚版权行；真实页为 <center>nginx/1.30.5</center>
        // 带版本号，按前缀匹配），只扫前 4KB 防大body误伤
        std::string head = resp.substr(0, he);
        size_t probeLen = resp.size() - he < 4096 ? resp.size() - he : 4096;
        if (resp.find("<center>nginx", he) == std::string::npos ||
            resp.find("<center>nginx", he) > he + probeLen)
            return;
        // 状态短语取原状态行（保持与状态码一致）；RFC 允许无短语，兜底 "Error"
        size_t eol = head.find("\r\n");
        std::string statusLine = head.substr(0, eol);
        std::string st = statusLine.size() > 13 ? statusLine.substr(13) : std::string("Error");
        std::string body = iisHtml(status, st.c_str());
        // 头区重建：剔除 Server/Content-Type/Content-Length，其余原样保留
        std::string out = statusLine + "\r\n";
        size_t pos = eol + 2;
        while (pos < head.size()) {
            size_t le = head.find("\r\n", pos);
            std::string line = (le == std::string::npos) ? head.substr(pos)
                                                         : head.substr(pos, le - pos);
            std::string low = line;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            if (low.compare(0, 7, "server:") != 0 &&
                low.compare(0, 13, "content-type:") != 0 &&
                low.compare(0, 15, "content-length:") != 0) {
                out += line;
                out += "\r\n";
            }
            if (le == std::string::npos) break;
            pos = le + 2;
        }
        out += "Server: " + MimicDefense::siteBanner() + "\r\n"
               "Content-Type: text/html\r\n"
               "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        resp = std::move(out);
    }

private:
    static std::string iisHtml(int status, const char* statusText) {
        std::string code = std::to_string(status);
        std::string title = code + " - " + statusText;
        return "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
               "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
               "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n"
               "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"/>\n"
               "<title>" + title + "</title>\n"
               "<style type=\"text/css\">body{margin:0;font-family:Verdana,Arial,sans-serif;"
               "font-size:.7em;background:#EFEFF0;color:#000}"
               "#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;}"
               "h1{font-size:1.4em;margin:0 0 0 0}h2{font-size:1.1em;margin:0 0 0 0}"
               "#content{padding:0 2% 2% 2%}</style>\n</head>\n"
               "<body><div id=\"header\"><h1>Server Error</h1></div>\n"
               "<div id=\"content\"><h2>" + title + "</h2>\n</div>\n</body></html>\n";
    }

    static std::string mimicHtml(int status, const char* statusText, int tpl,
                                 const char* banner) {
        std::string code = std::to_string(status);
        std::string title = code + " " + statusText;
        switch (tpl) {
            case 1:  // Apache 2.x 默认 403
                return "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                       "<html><head>\n<title>" + title + "</title>\n</head><body>\n"
                       "<h1>Forbidden</h1>\n"
                       "<p>You don't have permission to access this resource on this server.</p>\n"
                       "<hr>\n<address>" + banner + " Server at localhost Port 80</address>\n"
                       "</body></html>\n";
            case 2:  // IIS 10 默认 403
                return "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
                       "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
                       "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n"
                       "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"/>\n"
                       "<title>403 - Forbidden: Access is denied.</title>\n"
                       "<style type=\"text/css\">body{margin:0;font-family:Verdana,Arial,sans-serif;"
                       "font-size:.7em;background:#EFEFF0;color:#000}"
                       "#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;}"
                       "h1{font-size:1.4em;margin:0 0 0 0}h2{font-size:1.1em;margin:0 0 0 0}"
                       "h3{font-size:.9em;font-weight:normal;margin:0 0 0 0}"
                       "#content{padding:0 2% 2% 2%}</style>\n</head>\n"
                       "<body><div id=\"header\"><h1>Server Error</h1></div>\n"
                       "<div id=\"content\"><h2>403 - Forbidden: Access is denied.</h2>\n"
                       "<h3>You do not have permission to view this directory or page "
                       "using the credentials that you supplied.</h3></div>\n</body></html>\n";
            case 3:  // nginx 404（幽灵人格：被拦路径在扫描器报告中"不存在"）
                title = "404 Not Found";
                [[fallthrough]];
            case 4:  // nginx 503（过载人格：诱导扫描器降速）
                if (tpl == 4) title = "503 Service Temporarily Unavailable";
                [[fallthrough]];
            default:  // nginx 原生错误页风格
                return "<html>\n<head><title>" + title + "</title></head>\n"
                       "<body>\n<center><h1>" + title + "</h1></center>\n"
                       "<hr><center>" + banner + "</center>\n</body>\n</html>\n";
        }
    }

    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '<': o += "&lt;"; break;
                case '>': o += "&gt;"; break;
                case '&': o += "&amp;"; break;
                case '"': o += "&quot;"; break;
                default: o += c;
            }
        }
        return o;
    }

    static std::string html(const std::string& title, const std::string& detail,
                            const std::string& traceId, bool branded) {
        const char* brandFooter = branded
            ? "<div class=\"brand\">Protected by <b>NovaWAF</b></div>" : "";
        const char* sub = branded
            ? "NovaWAF \xe5\xae\x89\xe5\x85\xa8\xe9\x98\xb2\xe6\x8a\xa4\xe7\xb3\xbb\xe7\xbb\x9f\xe5\xb7\xb2\xe9\x98\xbb\xe6\xad\xa2\xe6\x9c\xac\xe6\xac\xa1\xe8\xae\xbf\xe9\x97\xae"
            : "\xe6\x9c\xac\xe6\xac\xa1\xe8\xae\xbf\xe9\x97\xae\xe8\xa2\xab\xe5\xae\x89\xe5\x85\xa8\xe7\xad\x96\xe7\x95\xa5\xe6\x8b\xa6\xe6\x88\xaa";
        std::string s = R"HTML(<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>)HTML";
        s += esc(title);
        s += R"HTML(</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:#f4f6fb;font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:#1f2733}
.card{width:min(520px,92vw);background:#fff;border-radius:14px;padding:44px 40px 36px;
 box-shadow:0 8px 40px rgba(31,39,51,.10);text-align:center}
.icon{width:72px;height:72px;margin:0 auto 22px;border-radius:50%;background:#fdecec;
 display:flex;align-items:center;justify-content:center}
h1{font-size:22px;font-weight:600;margin-bottom:10px}
.sub{font-size:14px;color:#6b7686;margin-bottom:6px}
.detail{font-size:13px;color:#98a2b3;margin-bottom:26px}
.trace{background:#f6f8fa;border:1px solid #e6eaf0;border-radius:8px;padding:12px 14px;
 font-family:ui-monospace,Consolas,monospace;font-size:13px;display:flex;gap:10px;
 align-items:center;justify-content:center}
.trace b{color:#475467;font-weight:600}
.copy{border:1px solid #d5dbe5;background:#fff;border-radius:6px;padding:4px 10px;
 font-size:12px;color:#475467;cursor:pointer}
.copy:hover{background:#f0f3f8}
.tip{margin-top:22px;font-size:12px;color:#98a2b3;line-height:1.7}
.brand{margin-top:26px;padding-top:18px;border-top:1px solid #eef1f6;
 font-size:12px;color:#98a2b3;letter-spacing:.5px}
.brand b{color:#3b6ef6}
</style>
</head>
<body>
<div class="card">
 <div class="icon">
  <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
   <path d="M12 2L4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"
     fill="none" stroke="#e0492f" stroke-width="1.8" stroke-linejoin="round"/>
   <path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="#e0492f" stroke-width="1.8"
     fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
 </div>
 <h1>)HTML";
        s += esc(title);
        s += "</h1>\n <div class=\"sub\">";
        s += sub;
        s += "</div>\n";
        if (!detail.empty()) {
            s += " <div class=\"detail\">";
            s += esc(detail);
            s += "</div>\n";
        }
        s += R"HTML( <div class="trace"><b>Trace ID</b><span id="tid">)HTML";
        s += esc(traceId);
        s += R"HTML(</span><button class="copy" onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById('tid').textContent);this.textContent='已复制'">复制</button></div>
 <div class="tip">如您认为本次拦截为误判，请联系网站管理员并提供上方 Trace ID 以便核查。</div>
)HTML";
        s += brandFooter;
        s += "\n</div>\n</body>\n</html>\n";
        return s;
    }
};

}  // namespace novawaf
