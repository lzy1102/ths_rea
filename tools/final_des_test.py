# -*- coding: utf-8 -*-
"""终极测试: 用会话密钥料解密抓包帧体"""
import struct, re, zlib, sys
sys.path.insert(0, "ths_client/trade_crypt")
from des_port import des_core, key_schedule, triple_crypt, reversed_pairs

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

ascii16 = b"L5k3zl1QD5Y71KJC"
hex12 = bytes.fromhex("b9facca9befdb0b2d6a4c8af")

key_cands = {
    "A16+H12_0_8": ascii16 + hex12[:8],
    "A16+H12_4_12": ascii16 + hex12[4:12],
    "H12_0_8+A16": hex12[:8] + ascii16,
    "A8_15+H12_0_8+A0_8": ascii16[8:16] + hex12[:8] + ascii16[:8],
    "H12x2": hex12 + hex12,
    "A16+H12_0_8^": bytes(a ^ b for a, b in zip(ascii16 + hex12[:8], b"11101"*8)),
}

def score_text(b):
    if not b: return 0
    n = sum(1 for c in b[:64] if 32 <= c < 127 or c in (9,10,13))
    gbk = 0
    try:
        s = b[:300].decode("gbk", "ignore")
        gbk = len(s)
    except: pass
    return n + gbk

# 帧3: 头15字节, 体176字节
for fname, frame in [("C2S3", cf[3]), ("C2S4", cf[4])]:
    body = frame[1 + 15:]  # 去掉mode(1)+头(15)
    body = body[:len(body)//8*8]
    print(f"===== {fname} body={len(body)}B ({len(body)//8} blocks) =====")
    for kname, key in key_cands.items():
        for dec in (True, False):
            try:
                out = bytearray()
                for i in range(0, len(body), 8):
                    out += triple_crypt(body[i:i+8], key, decrypt=dec)
                s = score_text(out)
                # 也试 zlib
                zok = False
                for off in range(0, 16):
                    try:
                        z = zlib.decompress(bytes(out[off:]))
                        if len(z) > 50: zok = True
                    except: pass
                if s > 60 or zok:
                    print(f"  *** {kname} decrypt={dec} score={s} zlib={zok}")
                    print("      ", bytes(out[:48]))
            except Exception as e:
                pass
print("done")
