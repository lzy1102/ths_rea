# -*- coding: utf-8 -*-
"""同花顺交易通道自定义 DES 实现 (从 xiadan.exe 内存反汇编逐条移植)

来源:
  - 加密核心: xiadan.exe 内存 0x1000100 (des_core)
  - 密钥调度: 0xfffcb0 (标准 DES PC1/PC2/移位表)
  - 3DES驱动: 0xfff7c0 (EDE, 8字节对齐, 状态异或)
  - 调度包装: 0xfff6a0 / 密码包装: 0xfffa60 (crypt(out,in,len,key24,mode,direction))
  - 8张SP表: 0x3ef3380..0x3ef3a80 (dump: captures/trade_crypto/des_sp_tables.json)
  - PC1/移位/PC2表: 0x3ef3308/0x3ef3340/0x3ef3350/0x3ef3368 (常量区域 dump)

验证状态:
  - Feistel 自洽性: 通过 (加密→倒序密钥→还原)
  - 与标准 DES 不同 (自定义 F 结构: 双链 t=rol(A,28)^k / t=A^k)
  - 待最终验证: 需要一个已知密钥的密文对 (会话握手密钥)

用法:
    from des_port import des_core, key_schedule, triple_crypt
    明文8字节 -> 密文8字节 (需24字节密钥)
"""
import struct

# ============ SP 表 (从内存提取) ============
_SP_RAW = {
    "SP0": "01010400,0,10000,1010404,1010004,10404,4,1010000,1000404,1010004,1010400,404,1000000,1000404,1010404,10000,404,1010000,1010000,0,100000,1000400,10404,1010400,10000,1000000,100000,1000400,4,1000404,100000,1010004".split(","),
}
# 表直接内存 dump 更可靠: 加载函数
def load_tables(region_path=r"D:\ths_win_extract\dumps\live4_regions\region_03ef3000_00001000_p08_t1000000.bin"):
    tdata = open(region_path, "rb").read()
    base = 0x3ef3000
    tabs = {}
    for name, addr in [("SP0",0x3ef3380),("SP1",0x3ef3480),("SP2",0x3ef3580),("SP3",0x3ef3680),
                       ("SP4",0x3ef3780),("SP5",0x3ef3880),("SP6",0x3ef3980),("SP7",0x3ef3a80)]:
        tabs[name] = struct.unpack_from("<64I", tdata, addr-base)
    pc1 = list(tdata[0x308:0x308+56])
    shifts = list(tdata[0x340:0x340+16])
    pc2a = list(tdata[0x350:0x350+24])
    pc2b = list(tdata[0x368:0x368+24])
    return tabs, pc1, shifts, pc2a, pc2b

T, PC1, SHIFTS, PC2A, PC2B = load_tables()

M = 0xFFFFFFFF
def rol(x, n): return ((x << n) | (x >> (32-n))) & M
def ror(x, n): return ((x >> n) | (x << (32-n))) & M

def des_core(w0, w1, k):
    """8字节块单次DES变换 (按反汇编逐条移植)
    w0,w1: 两个LE u32 (state[0], state[1])
    k: 32个key word (128字节调度)
    """
    B = w0; A = w1
    ki = 0
    t = ((B >> 4) ^ A) & 0x0f0f0f0f; A ^= t; B ^= (t << 4) & M
    t = ((B >> 16) ^ A) & 0xffff; A ^= t; B ^= (t << 16) & M
    t = ((A >> 2) ^ B) & 0x33333333; B ^= t; A ^= (t << 2) & M
    t = ((A >> 8) ^ B) & 0x00ff00ff; B ^= t; A ^= (t << 8) & M
    A = rol(A, 1); t = (B ^ A) & 0xaaaaaaaa; B ^= t; A ^= t; B = rol(B, 1)
    for i in range(8):
        t = rol(A, 28) ^ k[ki]; ki += 1
        f = T["SP6"][t & 63] | T["SP4"][(t >> 8) & 63] | T["SP2"][(t >> 16) & 63] | T["SP0"][(t >> 24) & 63]
        t = A ^ k[ki]; ki += 1
        f |= T["SP7"][t & 63] | T["SP5"][(t >> 8) & 63] | T["SP3"][(t >> 16) & 63] | T["SP1"][(t >> 24) & 63]
        B ^= f
        t = rol(B, 28) ^ k[ki]; ki += 1
        f = T["SP6"][t & 63] | T["SP4"][(t >> 8) & 63] | T["SP2"][(t >> 16) & 63] | T["SP0"][(t >> 24) & 63]
        t = B ^ k[ki]; ki += 1
        f |= T["SP7"][t & 63] | T["SP5"][(t >> 8) & 63] | T["SP3"][(t >> 16) & 63] | T["SP1"][(t >> 24) & 63]
        A ^= f
    A = ror(A, 1); t = (B ^ A) & 0xaaaaaaaa; B ^= t; A ^= t; B = ror(B, 1)
    t = ((B >> 8) ^ A) & 0x00ff00ff; A ^= t; B ^= (t << 8) & M
    t = ((B >> 2) ^ A) & 0x33333333; A ^= t; B ^= (t << 2) & M
    t = ((A >> 16) ^ B) & 0xffff; B ^= t; A ^= (t << 16) & M
    t = ((A >> 4) ^ B) & 0x0f0f0f0f; B ^= t; A ^= (t << 4) & M
    return A, B

def key_schedule(key8):
    """8字节密钥 → 32个key word (标准DES PC1/PC2/移位表)"""
    bits = []
    for idx in PC1:
        byte = key8[idx >> 3]
        bits.append((byte >> (7 - (idx & 7))) & 1)
    sched = []
    for r in range(16):
        sh = SHIFTS[r]
        k = bits[sh:28] + bits[:sh] + bits[28+sh:] + bits[28:28+sh]
        w0 = 0; w1 = 0
        for i in range(24):
            if k[PC2A[i]]: w0 |= 0x800000 >> i
            if k[PC2B[i]]: w1 |= 0x800000 >> i
        sched += [w0, w1]
    return sched

def triple_crypt(block8: bytes, key24: bytes, decrypt=False) -> bytes:
    """3DES-EDE. decrypt=True 时 K 顺序反转且中段反向 (按 0xfff6a0 逻辑)."""
    k1 = key_schedule(key24[0:8])
    k2 = key_schedule(key24[8:16])
    k3 = key_schedule(key24[16:24])
    if decrypt:
        ks = [list(reversed_pairs(k3)), list(reversed_pairs(k2)), list(reversed_pairs(k1))]
    else:
        ks = [k1, k2, k3]
    w0, w1 = struct.unpack("<II", block8)
    for s in ks:
        w0, w1 = des_core(w0, w1, s)
    return struct.pack("<II", w0, w1)

def reversed_pairs(sched):
    out = []
    for r in range(15, -1, -1):
        out += sched[r*2:r*2+2]
    return out

if __name__ == "__main__":
    # 自检测试
    key = b"abcdefgh"
    block = b"12345678"
    sched = key_schedule(key)
    w0, w1 = struct.unpack("<II", block)
    A, B = des_core(w0, w1, sched)
    enc = struct.pack("<II", A, B)
    A2, B2 = des_core(A, B, reversed_pairs(sched))
    dec = struct.pack("<II", A2, B2)
    print("加密:", enc.hex(" "))
    print("解密:", dec.hex(" "))
    assert dec == block, "自洽性失败"
    print("[自洽性验证通过]")
    # 3DES 自检
    k24 = b"0123456789abcdefGHIJKLMN"
    enc3 = triple_crypt(block, k24, decrypt=False)
    dec3 = triple_crypt(enc3, k24, decrypt=True)
    print("3DES加密:", enc3.hex(" "))
    print("3DES解密:", dec3.hex(" "))
    assert dec3 == block, "3DES自洽性失败"
    print("[3DES自洽性验证通过]")
