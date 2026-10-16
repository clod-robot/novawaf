#!/usr/bin/env python3
# 由 rules/cve_rules.json 重新生成 WafRedisService.java 的 DEFAULT_RULES 常量并就地拼接。
# 形如:  private static final String DEFAULT_RULES = "["
#                + "{r1},"
#                + "{r2}"
#                + "]";
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "rules", "cve_rules.json")
JAVA = os.path.join(ROOT, "admin-server", "src", "main", "java", "com", "novawaf",
                    "admin", "service", "WafRedisService.java")

with open(SRC, encoding="utf-8") as f:
    rules = json.load(f)

def jesc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

parts = [jesc(json.dumps(r, ensure_ascii=False, separators=(",", ":"))) for r in rules]

lines = ['    private static final String DEFAULT_RULES = "["']
for i, p in enumerate(parts):
    comma = "," if i < len(parts) - 1 else ""
    lines.append(f'            + "{p}{comma}"')
lines.append('            + "]";')
block = "\n".join(lines)

with open(JAVA, encoding="utf-8") as f:
    src = f.read()

pat = re.compile(r'    private static final String DEFAULT_RULES = "\[".*?\+ "\]";', re.S)
new_src, n = pat.subn(lambda m: block, src, count=1)
assert n == 1, "DEFAULT_RULES block not found"
with open(JAVA, "w", encoding="utf-8") as f:
    f.write(new_src)
print(f"spliced {len(parts)} rules into {os.path.basename(JAVA)}")
