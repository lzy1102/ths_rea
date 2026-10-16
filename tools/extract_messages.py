# -*- coding: utf-8 -*-
"""从 live4 内存区域提取协议消息样文本 (长文本段)"""
import glob
import re

pat = re.compile(rb"[\x20-\x7e\x0a\x0d\x09]{150,8000}")
results = []
for f in glob.glob(r"D:\ths_win_extract\dumps\live4_regions\region_*.bin"):
    data = open(f, "rb").read()
    for m in pat.finditer(data):
        s = m.group()
        # 过滤: 必须包含 '=' 和 (换行或'&'), 像消息
        if b"=" in s and (b"\n" in s or b"&" in s):
            n_eq = s.count(b"=")
            if n_eq >= 5:
                results.append((len(s), f.split("\\")[-1], m.start(), s))

print(f"共 {len(results)} 条候选")
results.sort(key=lambda x: -x[0])
seen = set()
shown = 0
for ln, fname, off, s in results:
    key = s[:60]
    if key in seen: continue
    seen.add(key)
    first_line = s.split(b"\n")[0][:80]
    print(f"len={ln:5d} {fname} @ {hex(off)}  | {first_line}")
    shown += 1
    if shown >= 60: break
