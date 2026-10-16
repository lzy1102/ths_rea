# -*- coding: utf-8 -*-
"""S2C加密帧全模式解密矩阵: 目标=解出zlib/deflate/文本"""
import re, sys, struct, zlib
sys.path.insert(0, "ths_client/trade_crypt")
from des_port import des_core, key_schedule, reversed_pairs
from Crypto.Cipher import DES3, DES

raw = open("captures/stream739_hex.txt", encoding="utf-8", errors="replace").read()
dirs = {"c2s": bytearray(), "s2c": bytearray()}
for line in raw.splitlines():
    if line.startswith("\t"):
        m = re.match(r"^\t([0-9A-Fa-f]{8})  (.*)$", line); cur = dirs["s2c"]
    else:
        m = re.match(r"^([0-9A-Fa-f]{8})  (.*)$", line); cur = dirs["c2s"]
    if not m: continue
    parts = m.group(2).split("  "); hexbuf = ""
    for p in parts:
        toks = p.split()
        if toks and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks): hexbuf += p.replace(" ", "")
        else: break
    try: cur += bytes.fromhex(hexbuf[:len(hexbuf)//2*2])
    except: pass

def frames_of(data):
    out, i = [], 0
    while True:
        i = data.find(b"\xfd\xfd\xfd\xfd", i)
        if i < 0 or i+12 > len(data): break
        try: ln = int(data[i+4:i+12], 16)
        except ValueError: i += 4; continue
        out.append(data[i+12:i+12+ln]); i += 12+ln
    return out

sfs = frames_of(bytes(dirs["s2c"]))
body2 = sfs[2][11:]
body3 = sfs[3][11:]

ascii16 = b"L5k3zl1QD5Y71KJC"
bin12 = bytes.fromhex("b9facca9befdb0b2d6a4c8af")

# 乙方: 魔改DES 的块加密/解密函数对 (enc/dec)
def mk_port_keys(k24):
    k1 = key_schedule(k24[0:8]); k2 = key_schedule(k24[8:16]); k3 = key_schedule(k24[16:24])
    def enc(blk):
        w0, w1 = struct.unpack("<II", blk)
        for s in (k1, k2, k3): w0, w1 = des_core(w0, w1, s)
        return struct.pack("<II", w0, w1)
    def dec(blk):
        w0, w1 = struct.unpack("<II", blk)
        for s in (reversed_pairs(k3), reversed_pairs(k2), reversed_pairs(k1)): w0, w1 = des_core(w0, w1, s)
        return struct.pack("<II", w0, w1)
    return enc, dec

def mk_port_des(k8):
    ks = key_schedule(k8)
    def enc(blk):
        w0, w1 = struct.unpack("<II", blk); w0, w1 = des_core(w0, w1, ks)
        return struct.pack("<II", w0, w1)
    def dec(blk):
        w0, w1 = struct.unpack("<II", blk); w0, w1 = des_core(w0, w1, reversed_pairs(ks))
        return struct.pack("<II", w0, w1)
    return enc, dec

def mk_std3(k24):
    c = DES3.new(k24, DES3.MODE_ECB)
    return c.encrypt, c.decrypt

def mk_std1(k8):
    c = DES.new(k8, DES.MODE_ECB)
    return c.encrypt, c.decrypt

def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

def de_blockify(dec_fn, ct, mode, iv=None):
    """模式: ECB / CBC(前密文) / PCBC(前明文) / CBC_iv0 / 每块状态"""
    out = b""
    prev = iv if iv is not None else b"\x00"*8
    for i in range(0, len(ct) - len(ct) % 8, 8):
        blk = ct[i:i+8]
        d = dec_fn(blk)
        if mode == "ECB":
            p = d
        elif mode == "CBC":
            p = xor(d, prev)
            prev = blk
        elif mode == "PCBC":
            p = xor(d, prev)
            prev = xor(blk, p)  # propagating: prev = c ^ p
        out += p
    return out

def score(name, out, meta):
    hits = []
    if out[:2] == b"\x78\x9c": hits.append("ZLIB@0")
    for o in range(0, min(24, len(out)-1)):
        if out[o:o+2] == b"\x78\x9c": hits.append(f"ZLIB@{o}")
    # raw inflate attempt
    for o in range(0, min(16, len(out))):
        try:
            d = zlib.decompressobj(-15)
            r = d.decompress(out[o:])
            if len(r) > 200: hits.append(f"INFLATE@{o}:{len(r)}")
        except Exception: pass
    try:
        d = zlib.decompressobj(15)
        r = d.decompress(out)
        if len(r) > 200: hits.append(f"ZINFLATE:{len(r)}")
    except Exception: pass
    if hits:
        print(f"*** {name} [{meta}]: {hits}")
        print(f"    out[:40]={out[:40].hex(' ')}")
        return True
    return False

keys24 = {
    "A16+b0_8": ascii16 + bin12[:8],
    "A16+b4_12": ascii16 + bin12[4:12],
    "b0_8+A16": bin12[:8] + ascii16,
    "b4_12+A16": bin12[4:12] + ascii16,
    "A8+b8+A8": ascii16[:8] + bin12[:8] + ascii16[8:],
    "A16+A0_8": ascii16 + ascii16[:8],
    "A16+A8_16": ascii16 + ascii16[8:16],
    "b12+b12": bin12 + bin12,
    "A16only16": None,
}
keys8 = {"A[:8]": ascii16[:8], "A[8:]": ascii16[8:], "b[:8]": bin12[:8], "b[4:12]": bin12[4:12]}

found = False
for bname, body in (("S2C2", body2), ("S2C3", body3)):
    for off in (0, 4, 7, 8):  # 微调对齐
        ct = body[off:]
        for kname, k24 in keys24.items():
            if k24 is None: continue
            for mkname, mk in (("port3", mk_port_keys), ("std3", mk_std3)):
                try: enc, dec = mk(k24)
                except Exception: continue
                for mode in ("ECB", "CBC", "PCBC"):
                    for dirn, fn in (("dec", dec), ("enc", enc)):
                        out = de_blockify(fn, ct, mode)
                        if score(f"{bname}+{off}", out, f"{mkname}/{kname}/{mode}/{dirn}"):
                            found = True
        for kname, k8 in keys8.items():
            for mkname, mk in (("port1", mk_port_des), ("std1", mk_std1)):
                try: enc, dec = mk(k8)
                except Exception: continue
                for mode in ("ECB", "CBC", "PCBC"):
                    for dirn, fn in (("dec", dec), ("enc", enc)):
                        out = de_blockify(fn, ct, mode)
                        if score(f"{bname}+{off}", out, f"{mkname}/{kname}/{mode}/{dirn}"):
                            found = True
print("done, found=", found)
