# -*- coding: utf-8 -*-
"""3DES key-split + bit-order variants test on captured frame bodies"""
import re
from Crypto.Cipher import DES3

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

def bitrev_byte(b):
    r = 0
    for i in range(8):
        if b & (1 << i): r |= 1 << (7 - i)
    return r

def bitrev(data):
    return bytes(bitrev_byte(b) for b in data)

def word_rev(data):
    out = bytearray()
    for i in range(0, len(data) - len(data) % 4, 4):
        out += data[i:i+4][::-1]
    return bytes(out)

ascii16 = b"L5k3zl1QD5Y71KJC"
hex12 = bytes.fromhex("b9facca9befdb0b2d6a4c8af")

c2s = parse_follow_hex("captures/stream739_hex.txt")
cf = split_frames(c2s)

key_variants = {
    "A0-7 A8-15 H0-7": ascii16[:8] + ascii16[8:] + hex12[:8],
    "H0-7 A0-7 A8-15": hex12[:8] + ascii16[:8] + ascii16[8:],
    "A0-7 H0-7 H4-11": ascii16[:8] + hex12[:8] + hex12[4:12],
    "A0-7 A8-15 H4-11": ascii16[:8] + ascii16[8:] + hex12[4:12],
}

transforms = {
    "raw": lambda d: d,
    "bitrev_data": bitrev,
    "wordrev_data": word_rev,
    "bitrev_kd": None,  # key+data bitrev
}

def score(b):
    n = sum(1 for c in b[:96] if 32 <= c < 127 or c in (9, 10, 13) or 0x81 <= c <= 0xFE)
    return n

for fname, frame in [("C2S3", cf[3]), ("C2S4", cf[4])]:
    print(f"===== {fname} =====")
    data = frame[17:]
    data = data[:len(data)//8*8]
    for kname, key in key_variants.items():
        for ktrans in ("raw", "bitrev"):
            kk = bitrev(key) if ktrans == "bitrev" else key
            try:
                k3 = DES3.adjust_key_parity(kk)
            except Exception:
                continue
            for dtrans_name, dfn in [("raw", lambda d: d), ("bitrev", bitrev), ("wordrev", word_rev)]:
                d2 = dfn(data)
                for mode_name in ("ECB", "CBC0"):
                    try:
                        if mode_name == "ECB":
                            c = DES3.new(k3, DES3.MODE_ECB)
                        else:
                            c = DES3.new(k3, DES3.MODE_CBC, iv=b"\x00" * 8)
                        pt = c.decrypt(d2)
                        s = score(pt)
                        if s > 40:
                            print(f"  key={kname}[{ktrans}] data[{dtrans_name}] {mode_name}: score={s}")
                            print("   ", pt[:64])
                    except Exception:
                        pass
    print("  (done)")
