# -*- coding: utf-8 -*-
"""暴力尝试解密 THS 交易协议 (stream739) 的 DES 加密块"""
import re
import sys
from Crypto.Cipher import DES, DES3

def parse_follow_hex(path):
    node0, node1 = bytearray(), bytearray()
    for line in open(path, encoding="utf-8", errors="replace"):
        srv = line.startswith("\t")
        line = line.rstrip("\r\n")
        if srv: line = line[1:]
        m = re.match(r"^([0-9A-Fa-f]{8})  (.*)$", line)
        if not m: continue
        parts = m.group(2).split("  ")
        hexbuf = ""
        for p in parts:
            toks = p.split()
            if toks and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks):
                hexbuf += p.replace(" ", "")
            else: break
        try: chunk = bytes.fromhex(hexbuf[:len(hexbuf)//2*2])
        except ValueError: continue
        (node1 if srv else node0).extend(chunk)
    return bytes(node0), bytes(node1)

def split_frames(data):
    frames, i = [], 0
    while True:
        i = data.find(b"\xfd\xfd\xfd\xfd", i)
        if i < 0 or i+12 > len(data): break
        try: ln = int(data[i+4:i+12], 16)
        except ValueError: i += 4; continue
        frames.append(data[i+12:i+12+ln]); i += 12+ln
    return frames

def score_bytes(b):
    good = 0
    for c in b[:200]:
        if 32 <= c < 127 or c in (10, 13):
            good += 1
        elif 0x81 <= c <= 0xFE:
            good += 0.5
    s = b[:400].decode("gbk", "ignore")
    bonus = 0
    for kw in ("cmd", "type", "retcode", "=", "zjzh", "wtsl", "nd=1.0", "msg"):
        if kw in s:
            bonus += 30
    return good + bonus, s

candidates = {}
k16 = b"L5k3zl1QD5Y71KJC"
k12 = bytes.fromhex("b9facca9befdb0b2d6a4c8af")
candidates["ascii16"] = k16
candidates["ascii16+zeros8"] = k16 + b"\x00" * 8
candidates["ascii16_3des24"] = k16 + k16[:8]
candidates["ascii8_first"] = k16[:8]
candidates["ascii8_last"] = k16[8:]
candidates["hex12+zeros"] = k12 + b"\x00" * 12
candidates["hex12x2"] = k12 + k12
candidates["hex12+ascii16"] = k12 + k16[:12]
candidates["ascii16_rev"] = k16[::-1]
candidates["ascii16+hex12first8"] = k16 + k12[:8]
candidates["hex12first8_desc"] = k12[:8]

def try_decrypt(ct, key):
    results = []
    if len(key) >= 16:
        try:
            kk = DES3.adjust_key_parity(key[:24] if len(key) >= 24 else key)
            c = DES3.new(kk, DES3.MODE_ECB)
            results.append(("3des-ecb", c.decrypt(ct[:len(ct)//8*8])))
            c = DES3.new(kk, DES3.MODE_CBC, iv=b"\x00" * 8)
            results.append(("3des-cbc0", c.decrypt(ct[:len(ct)//8*8])))
        except ValueError:
            pass
    if len(key) >= 8:
        c = DES.new(key[:8], DES.MODE_ECB)
        results.append(("des-ecb", c.decrypt(ct[:len(ct)//8*8])))
        c = DES.new(key[:8], DES.MODE_CBC, iv=b"\x00" * 8)
        results.append(("des-cbc0", c.decrypt(ct[:len(ct)//8*8])))
    return results

def main(path):
    c2s, s2c = parse_follow_hex(path)
    cf, sf = split_frames(c2s), split_frames(s2c)
    targets = []
    for n, f in enumerate(cf):
        if n >= 2:
            targets.append((f"C2S#{n}", f, 17))
    for n, f in enumerate(sf):
        if n >= 2 and len(f) > 16 and f[10] == 0x10:
            targets.append((f"S2C#{n}", f, 11))

    best_all = []
    for name, frame, base in targets[:6]:
        for kname, key in candidates.items():
            for off in range(base - 2, base + 6):
                ct = frame[off:]
                if len(ct) < 16: continue
                for mode, pt in try_decrypt(ct, key):
                    sc, s = score_bytes(pt)
                    best_all.append((sc, name, kname, mode, off, s))
    best_all.sort(key=lambda x: -x[0])
    for sc, name, kname, mode, off, s in best_all[:15]:
        print(f"score={sc:.0f} {name} key={kname} {mode} off={off}")
        print("   ", repr(s[:160]))
        print()

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "captures/stream739_hex.txt")
