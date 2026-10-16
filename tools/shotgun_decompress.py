# -*- coding: utf-8 -*-
"""帧载荷变换霰弹枪测试"""
import re, zlib, bz2, lzma
import lz4.block, lz4.frame
import snappy
import brotli

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
cf = split_frames(c2s)
sf = split_frames(s2c)

targets = [
    ("C2S#2", cf[2], 17),
    ("C2S#3", cf[3], 17),
    ("S2C#2", sf[2], 11),
]

def is_textish(b):
    if len(b) < 20: return False
    txt = 0
    for c in b[:300]:
        if 32 <= c < 127 or c in (9,10,13) or 0x81 <= c <= 0xFE:
            txt += 1
    return txt / min(300, len(b)) > 0.85

for name, frame, base_off in targets:
    print(f"===== {name} (len={len(frame)}) =====")
    for off in range(0, min(len(frame)-8, base_off+10)):
        d = frame[off:]
        tries = []
        for wb in (15, -15, 31, 47):
            try:
                tries.append((f"zlib{wb}", zlib.decompress(d, wb)))
            except Exception: pass
        try: tries.append(("bz2", bz2.decompress(d)))
        except Exception: pass
        try: tries.append(("lzma", lzma.decompress(d)))
        except Exception: pass
        try: tries.append(("lzma-raw", lzma.decompress(d, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1}])))
        except Exception: pass
        try: tries.append(("lz4blk", lz4.block.decompress(d)))
        except Exception: pass
        try: tries.append(("lz4blk-sz", lz4.block.decompress(d, uncompressed_size=8192)))
        except Exception: pass
        try: tries.append(("snappy", snappy.decompress(d)))
        except Exception: pass
        try: tries.append(("brotli", brotli.decompress(d)))
        except Exception: pass
        for tname, out in tries:
            if len(out) > 10:
                ok = is_textish(out)
                print(f"  *** {tname} @off={off} -> {len(out)}B textish={ok}")
                print("      ", out[:120])
    print()
