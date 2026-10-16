#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NovaWAF CVE 规则库命中测试（本机发起，多线程并发）。

对 rules/cve_rules.json 中每条规则构造 payload（pattern URL 编码后置于 query 参数，
经引擎 Decoder 归一化还原后应命中）：
  - action=block -> 期望 403（零漏报）
  - action=log/pass -> 期望 200（仅记录）
另附良性/近似误报用例 -> 期望 200（零误报）。

用法: python scripts/cve_rules_test.py [host] [port] [host_header]
默认: 192.168.100.2 8099 nac
"""
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
HOST_HDR = sys.argv[3] if len(sys.argv) > 3 else "nac"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = json.load(open(os.path.join(ROOT, "rules", "cve_rules.json"), encoding="utf-8"))

# 良性与近似误报用例（期望 200）
BENIGN = [
    ("benign_product", "/product?id=42"),
    ("benign_search", "/search?q=hello%20world"),
    ("benign_list", "/api/list?page=1&size=20"),
    ("near_jndi_no_proto", "/?q=jndi:example"),                      # 无协议/无 ${，不应命中
    ("near_autodiscover_no_qm", "/?next=/autodiscover/autodiscover.json"),  # 无 .json?，不应命中
    ("near_class_module", "/?q=class.module"),                       # 前缀不完整，不应命中
    ("near_vpn_no_trav", "/?next=/vpn/login"),                       # 无 ../，不应命中
    ("near_type_no_gadget", "/?q=%22@type%22:%22java.lang.String%22"),  # 普通 @type，不应命中
]


def fire(path_qs):
    url = f"http://{HOST}:{PORT}{path_qs}"
    req = urllib.request.Request(url, headers={"Host": HOST_HDR, "User-Agent": "cve-test/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{e}"


def check_rule(r):
    pat = r["pattern"]
    enc = urllib.parse.quote(pat, safe="")
    expect = 403 if r.get("action", "block") == "block" else 200
    got = fire(f"/?q={enc}")
    ok = got == expect
    return (r["id"], r.get("cve", "-"), r["name"], r["action"], expect, got, ok)


def check_benign(item):
    name, pq = item
    got = fire(pq)
    return (name, 200, got, got == 200)


def main():
    fails = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(check_rule, RULES))
        bresults = list(ex.map(check_benign, BENIGN))

    n_block = sum(1 for r in RULES if r.get("action", "block") == "block")
    n_log = len(RULES) - n_block
    print(f"== CVE 规则命中: {len(RULES)} 条 (block={n_block} log/pass={n_log}) ==")
    for rid, cve, name, act, exp, got, ok in results:
        if not ok:
            fails.append((rid, name, exp, got))
        print(f"  [{'OK' if ok else 'FAIL'}] id={rid:<5} {cve:<18} act={act:<5} exp={exp} got={got}  {name}")

    print(f"== 良性/近似误报: {len(BENIGN)} 条 ==")
    bn_fail = 0
    for name, exp, got, ok in bresults:
        if not ok:
            bn_fail += 1
            fails.append((name, "benign", exp, got))
        print(f"  [{'OK' if ok else 'FAIL'}] {name:<28} exp={exp} got={got}")

    atk_fail = sum(1 for x in results if not x[6])
    print(f"\n汇总: 攻击漏报 {atk_fail}/{len(results)}，良性误报 {bn_fail}/{len(BENIGN)}")
    print("RESULT:", "PASS" if not fails else "FAIL")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
