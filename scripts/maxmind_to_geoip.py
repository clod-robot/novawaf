#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
maxmind_to_geoip.py — 将 MaxMind GeoLite2 Country CSV 转换为 NovaWAF geoip.txt 格式。

输入（GeoLite2-Country-CSV.zip 解压后）:
  - GeoLite2-Country-Blocks-IPv4.csv  列: network,geoname_id,registered_country_geoname_id,...
  - GeoLite2-Country-Locations-en.csv 列: geoname_id,locale_code,continent_code,
          continent_name,country_iso_code,country_name,...

输出 (NovaWAF 引擎 geo_filter.h 识别):
  cidr,CC[,country_name]      # 注释行与空行会被引擎忽略

用法:
  python3 maxmind_to_geoip.py --blocks GeoLite2-Country-Blocks-IPv4.csv \
                              --locations GeoLite2-Country-Locations-en.csv \
                              -o rules/geoip.txt
  # 或给定解压目录自动发现:
  python3 maxmind_to_geoip.py --dir ./GeoLite2-Country-CSV_xxx -o rules/geoip.txt

设计要点（等保/性能）:
  * 纯标准库，无第三方依赖，可在离线环境运行。
  * 国家代码统一大写；无国家映射的网段（仅大洲）跳过，避免误判。
  * 大文件流式处理，geoname_id→国家信息先建索引（dict），内存可控。
  * 结果按 CIDR 起点排序，与引擎二分查找一致；去重。
"""
import argparse
import csv
import ipaddress
import os
import sys


def _detect_files(directory):
    blocks = loc = None
    for name in os.listdir(directory):
        low = name.lower()
        if low.startswith("geolite2-country-blocks-ipv4") and low.endswith(".csv"):
            blocks = os.path.join(directory, name)
        elif low.startswith("geolite2-country-locations-en") and low.endswith(".csv"):
            loc = os.path.join(directory, name)
    return blocks, loc


def build_country_index(locations_path):
    """geoname_id -> (iso_code, country_name)"""
    idx = {}
    with open(locations_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gid = (row.get("geoname_id") or "").strip()
            iso = (row.get("country_iso_code") or "").strip().upper()
            name = (row.get("country_name") or "").strip()
            if not gid or not iso:
                continue  # 仅有大洲、无国家的行跳过
            idx[gid] = (iso, name)
    return idx


def _first_int(*vals):
    for v in vals:
        v = (v or "").strip()
        if v:
            return v
    return ""


def convert(blocks_path, locations_path, out_path, min_net=None, max_net=None):
    idx = build_country_index(locations_path)
    if not idx:
        print("ERROR: empty country index from", locations_path, file=sys.stderr)
        sys.exit(2)

    seen = set()
    rows = []  # (start_int, cidr, iso, name)
    kept = skipped = 0
    with open(blocks_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            net = (row.get("network") or "").strip()
            if not net:
                continue
            gid = _first_int(row.get("geoname_id"),
                             row.get("registered_country_geoname_id"))
            cc = idx.get(gid)
            if cc is None:
                skipped += 1
                continue
            iso, name = cc
            try:
                netobj = ipaddress.ip_network(net, strict=False)
            except ValueError:
                skipped += 1
                continue
            start = int(netobj.network_address)
            if min_net is not None and start < min_net:
                continue
            if max_net is not None and start > max_net:
                continue
            key = (start, net)
            if key in seen:
                continue
            seen.add(key)
            rows.append((start, net, iso, name))
            kept += 1

    rows.sort(key=lambda r: r[0])
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as out:
        out.write("# NovaWAF geoip.txt — generated from MaxMind GeoLite2 Country CSV\n")
        out.write("# format: cidr,CC[,country_name]   (lines with # / blank ignored by engine)\n")
        out.write("# source: GeoLite2-Country-CSV  (offline; replace with latest release)\n\n")
        for _start, cidr, iso, name in rows:
            if name:
                out.write(f"{cidr},{iso},{name}\n")
            else:
                out.write(f"{cidr},{iso}\n")
    print(f"OK: wrote {kept} CIDR ranges -> {out_path} (skipped {skipped} no-country rows)",
          file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="MaxMind GeoLite2 CSV -> NovaWAF geoip.txt")
    ap.add_argument("--blocks", help="GeoLite2-Country-Blocks-IPv4.csv path")
    ap.add_argument("--locations", help="GeoLite2-Country-Locations-en.csv path")
    ap.add_argument("--dir", help="directory containing both CSVs (auto-detect)")
    ap.add_argument("-o", "--out", default="geoip.txt", help="output geoip.txt path")
    args = ap.parse_args()

    blocks, loc = args.blocks, args.locations
    if args.dir:
        b, l = _detect_files(args.dir)
        blocks = blocks or b
        loc = loc or l
    if not blocks or not loc:
        ap.error("need --blocks and --locations (or --dir)")
    convert(blocks, loc, args.out)


if __name__ == "__main__":
    main()
