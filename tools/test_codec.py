# -*- coding: utf-8 -*-
import re

ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/"
DEC = {c: i for i, c in enumerate(ALPHABET)}

def de_decode(s):
    s = s.replace(" ", "+").strip()
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

base = "D:/同花顺软件/同花顺/RES/Zyy/"
raw = open(base + "MsgReplace.json", "rb").read().decode("latin1")
print(f"MsgReplace.json 文本 {len(raw)} 字符")
dec = de_decode(raw)
print(f"自定义表解码: {len(dec)} 字节")
print("hex[:120]:", dec[:120].hex(" "))
print("gbk[:300]:")
print(dec[:300].decode("gbk", "replace"))
