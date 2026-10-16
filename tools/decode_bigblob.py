# -*- coding: utf-8 -*-
import re

ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/"
DEC = {c: i for i, c in enumerate(ALPHABET)}

def de_decode(s):
    s = s.replace(" ", "+")
    vals = []
    for c in s:
        if c == "=":
            break
        v = DEC.get(c)
        if v is not None:
            vals.append(v)
    out = bytearray(); acc = 0; bits = 0
    for v in vals:
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)

SEG = re.compile(rb"[\x20-\x7e]{200000,}")

path = r"D:\ths_win_extract\dumps\live4_regions\region_1b155000_0016b000_p04_t20000.bin"
data = open(path, "rb").read()
m = re.search(rb"data=([A-Za-z0-9+/]+)", data)
assert m, "未找到"
blob = m.group(1).decode()
print(f"data= blob 长度 {len(blob)}")
raw = de_decode(blob)
print(f"解码后 {len(raw)} 字节")
print("前500字节:")
print(raw[:500].decode("gbk", "replace"))
print()
print("中段500字节:")
print(raw[len(raw)//2:len(raw)//2+500].decode("gbk", "replace"))
print()
print("尾段300字节:")
print(raw[-300:].decode("gbk", "replace"))
