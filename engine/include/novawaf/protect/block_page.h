// NovaWAF - 统一拦截/挑战响应渲染（独立拦截页 + 追踪ID + 指纹三态）
// 设计：
//   * 全引擎唯一拦截页出口，替换散落的 44 字节占位响应。
//   * 每次拦截生成全局唯一 Trace ID（trc-时间基36-随机5位），写入响应页 + X-Request-Id
//     响应头 + AttackEvent.trace，用户在控制台可按 ID 一键溯源完整攻击事件。
//   * 指纹三态：PUBLIC 输出品牌页 + X-WAF 头（wafw00f 可识别）；
//     HIDDEN 输出无品牌通用页 + Server: nginx 伪装（混入正常站点流量）。
//   * 纯函数无状态，热路径零分配之外的负担可忽略（拦截本就是低频冷路径）。
#pragma once

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <sys/random.h>

namespace novawaf {

class BlockPage {
public:
    // trc-<base36时间>-<5位随机hex>，全局唯一、可按时间排序
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
        char rb[8];
        std::snprintf(rb, sizeof(rb), "%05x", rnd & 0xFFFFF);
        return std::string("trc-") + (tb + i) + "-" + rb;
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
        std::string body = html(title, detail, traceId, branded);
        std::string resp;
        resp.reserve(body.size() + 512);
        resp += "HTTP/1.1 ";
        resp += status;
        resp += " ";
        resp += statusText;
        resp += "\r\nContent-Type: text/html; charset=utf-8\r\n"
                "Cache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "X-Request-Id: " + traceId + "\r\n";
        if (branded) {
            resp += "Server: NovaWAF\r\nX-WAF: NovaWAF\r\n";
        } else {
            resp += "Server: nginx\r\n";  // 与前置反代保持一致，不暴露差异
        }
        resp += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        resp += body;
        return resp;
    }

private:
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
