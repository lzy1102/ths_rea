# -*- coding: utf-8 -*-
"""帧体 = XOR密钥流(+)自定义字母表文本 ? 按位置约束求解"""
import re

ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/"
ALSET = set(ALPHABET.encode())

def parse_follow_hex(path):
    node0 = bytearray()
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("\t"): continue
        m = re.match(r"^([0-9A-Fa-f]{8})  (.*)$", line)
        if not m: continue
        parts = m.group(2).split("  ")
        hexbuf = ""
        for p in parts:
            toks = p.split()
            if toks and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks):
                hexbuf += p.replace(" ", "")
            else: break
        try: node0 += bytes.fromhex(hexbuf[:len(hexbuf)//2*2])
        except: pass
    return bytes(node0)

def split_frames(data):
    frames, i = [], 0
    while True:
        i = data.find(b"\xfd\xfd\xfd\xfd", i)
        if i < 0 or i+12 > len(data): break
        try: ln = int(data[i+4:i+12], 16)
        except ValueError: i += 4; continue
        frames.append(data[i+12:i+12+ln]); i += 12+ln
    return frames

c2s = parse_follow_hex("captures/stream739_hex.txt")
cf = split_frames(c2s)

# 收集所有加密帧的 body (17以后) 按长度排序
bodies = []
for n, f in enumerate(cf):
    if n < 2 or len(f) < 40: continue
    bodies.append((n, f[17:]))

print(f"加密帧: {[n for n, b in bodies]}")

# 对第3帧做周期密钥求解
target = dict(bodies)[3]
print(f"目标帧 len={len(target)}")

for period in [1, 2, 4, 8, 16, 20, 24, 32, 64]:
    # 每个位置的密钥候选 (使该位置所有样本的 XOR 结果都在字母表内)
    ok = True
    keys = []
    for pos in range(period):
        samples = target[pos::period]
        cands = []
        for k in range(256):
            if all((b ^ k) in ALSET for b in samples):
                cands.append(k)
        if not cands:
            ok = False
            break
        keys.append(cands)
    if ok:
        print(f"周期 {period}: 每位置均有候选! {[c[:4] for c in keys]}")
    else:
        print(f"周期 {period}: 失败(样本约束太强或无解)")
