# -*- coding: utf-8 -*-
import re

ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/"
ALSET = set(ALPHABET.encode())

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

c2s, s2c = parse_follow_hex("captures/stream739_hex.txt")
cf, sf = split_frames(c2s), split_frames(s2c)

def check(label, frames, skip=2):
    for n, f in enumerate(frames):
        if n < skip or len(f) < 30: continue
        data = f[17:] if label == "C2S" else f[11:]
        in_alpha = sum(1 for b in data if b in ALSET)
        ratio = in_alpha / max(1, len(data))
        print(f"{label}#{n}: len={len(f)} data={len(data)} 字母表内={ratio*100:.1f}%")

check("C2S", cf)
print()
check("S2C", sf)
