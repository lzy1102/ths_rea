# -*- coding: utf-8 -*-
"""解析 THS 交易协议 (stream739 follow-hex) → 拆帧 → zlib 解压 → 明文"""
import re
import zlib
import sys

def parse_follow_hex(path):
    node0, node1 = bytearray(), bytearray()
    for line in open(path, encoding="utf-8", errors="replace"):
        srv = line.startswith("\t")
        line = line.rstrip("\r\n")
        if srv:
            line = line[1:]
        m = re.match(r"^([0-9A-Fa-f]{8})  (.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        parts = rest.split("  ")
        hexbuf = ""
        for p in parts:
            toks = p.split()
            if toks and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks):
                hexbuf += p.replace(" ", "")
            else:
                break
        if len(hexbuf) % 2:
            hexbuf = hexbuf[:-1]
        try:
            chunk = bytes.fromhex(hexbuf)
        except ValueError:
            continue
        if srv:
            node1 += chunk
        else:
            node0 += chunk
    return bytes(node0), bytes(node1)

def split_frames(data):
    frames = []
    i = 0
    while True:
        i = data.find(b"\xfd\xfd\xfd\xfd", i)
        if i < 0:
            break
        if i + 12 > len(data):
            break
        try:
            ln = int(data[i+4:i+12], 16)
        except ValueError:
            i += 4
            continue
        payload = data[i+12:i+12+ln]
        frames.append(payload)
        i += 12 + ln
    return frames

def try_inflate(payload):
    for off in range(0, min(24, max(0, len(payload)-2))):
        if payload[off:off+2] == b"\x78\x9c":
            try:
                return off, zlib.decompress(payload[off:])
            except zlib.error:
                try:
                    d = zlib.decompressobj()
                    out = d.decompress(payload[off:])
                    if out:
                        return off, out
                except zlib.error:
                    pass
    return None, None

def main(path):
    c2s, s2c = parse_follow_hex(path)
    print(f"客户端->服务器 {len(c2s)} 字节, 服务器->客户端 {len(s2c)} 字节\n")
    for label, data in (("C2S", c2s), ("S2C", s2c)):
        frames = split_frames(data)
        print(f"===== {label}: {len(frames)} 帧 =====")
        for n, p in enumerate(frames):
            off, txt = try_inflate(p)
            if txt is not None:
                preview = txt[:600].decode("gbk", "replace")
                print(f"\n--- {label}#{n} len={len(p)} zlib@{off} -> {len(txt)}B ---")
                print(preview.replace("\x00", "·"))
            else:
                pv = p[:80].decode("gbk", "replace")
                print(f"\n--- {label}#{n} len={len(p)} 无zlib ---")
                print(pv.replace("\x00", "·"))
        print()

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "captures/stream739_hex.txt")
