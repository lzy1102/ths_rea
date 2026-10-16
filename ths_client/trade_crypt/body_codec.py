# -*- coding: utf-8 -*-
"""交易通道消息体编解码器 (xiadan.exe 0xe34xx 管线) —— 完全破解版

管线 (编译级验证 + 双会话实测):
    发送: 明文 -> zlib.compress -> DES-CBC加密 -> body (写入帧)
    接收: body -> DES-CBC解密 -> zlib.decompress -> 明文

参数 (来自运行时密钥描述符 conn+0x9c9):
    KEY = b1 81 83 80 83 88 8d 81        (固定! 跨会话/跨消息恒定)
    K2 = K3 = 0                          (3DES-EDE 退化为单 DES: E_K1(D_0(E_0(x))) = E_K1(x))
    IV  = 每次登录会话变化 (8字节, 如 3d a6 0b f1 32 00 91 e2 / 14 1b 40 13 05 5b 88 6a)
          ← 存储于连接对象 conn+0x9c9+0x18; 来源 = S2C#1 明文尾部 b'E154.59.68\\x00' 之后 8 字节

验证记录:
    v3 会话 (IV=cb4295a7be472f1e): body(310B) -> 明文 570B ✓
    v6 会话 (IV=3da60bf1320091e2): body(318B) -> 明文 570B ✓ (首块与运行时zlib头完全一致)
    v3 的 0124 (同一IV): body(253B) -> 明文 488B ✓

用法:
    from body_codec import body_decrypt, body_encrypt
    plain = body_decrypt(body_bytes, iv=bytes.fromhex('3da60bf1320091e2'))
    body  = body_encrypt(plain_bytes, iv=...)
"""
import zlib

try:
    from Crypto.Cipher import DES
except ImportError:
    DES = None

DES_KEY = bytes.fromhex('b181838083888d81')
K24 = DES_KEY + b'\x00' * 16   # 3DES-EDE 全键 (K2=K3=0)


def _des_cbc(data: bytes, iv: bytes, encrypt: bool) -> bytes:
    """DES-CBC, iv 8字节; 任意长度按非分组对齐原则处理(尾部截断/零填充)"""
    if DES is None:
        raise RuntimeError("需要 pycryptodome: pip install pycryptodome")
    c = DES.new(DES_KEY, DES.MODE_ECB)
    out = bytearray()
    prev = iv
    if encrypt:
        # 零填充到8字节整数倍, 输出与输入等长(截断)
        pad = (-len(data)) % 8
        work = data + b'\x00' * pad
        for i in range(0, len(work), 8):
            blk = bytes(a ^ b for a, b in zip(work[i:i+8], prev))
            enc = c.encrypt(blk)
            out += enc
            prev = enc
        return bytes(out[:len(data)])
    else:
        n = len(data) // 8 * 8
        rem = data[n:]
        for i in range(0, n, 8):
            dec = c.decrypt(data[i:i+8])
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = data[i:i+8]
        if rem:
            # 尾部不满8字节: 解密零填充块后截断 (与客户端一致)
            pad_blk = rem + b'\x00' * (8 - len(rem))
            dec = c.decrypt(pad_blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))[:len(rem)]
        return bytes(out)


def body_decrypt(body: bytes, iv: bytes) -> bytes:
    """body -> 明文 (DES-CBC解密 + zlib解压; 自动处理尾部非对齐)"""
    z_full = _des_cbc(body, iv, encrypt=False)
    try:
        return zlib.decompressobj().decompress(z_full)
    except zlib.error:
        # 尾块容错: 只用分组对齐部分
        z_aligned = _des_cbc(body[:len(body) // 8 * 8], iv, encrypt=False)
        return zlib.decompressobj().decompress(z_aligned)


def des_cbc_encrypt(data: bytes, iv: bytes) -> bytes:
    """DES-CBC加密, 零填充到8字节 (返回完整填充后密文, 与客户端一致)"""
    if DES is None:
        raise RuntimeError("需要 pycryptodome: pip install pycryptodome")
    c = DES.new(DES_KEY, DES.MODE_ECB)
    pad = (-len(data)) % 8
    work = data + b'\x00' * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(work), 8):
        blk = bytes(a ^ b for a, b in zip(work[i:i+8], prev))
        enc = c.encrypt(blk)
        out += enc
        prev = enc
    return bytes(out)


def body_encrypt(plaintext: bytes, iv: bytes) -> tuple:
    """明文 -> (body, zlen): zlib压缩 + 零填充 + DES-CBC加密
    返回 (body_padded, len_zlib)。帧头 len1=len_zlib, len2=len(plaintext)。"""
    z = zlib.compress(plaintext, 6)
    return des_cbc_encrypt(z, iv), len(z)


def body_decrypt_raw(body: bytes, iv: bytes) -> bytes:
    """body -> zlib流 (不解压, 调试用)"""
    return _des_cbc(body, iv, encrypt=False)


def s2c_decrypt(body: bytes, iv: bytes) -> bytes:
    """S2C 0x10 加密体 -> 明文。

    结构与C2S不同: DES-CBC解密 -> [u32 LE 明文长度][zlib流]。
    实测(liveI 会话): 6/6 帧全部吻合, 长度头 == 解压后长度。
    """
    import struct
    dec = _des_cbc(body, iv, encrypt=False)
    if len(dec) < 4:
        raise ValueError("S2C 体太短")
    plen = struct.unpack('<I', dec[:4])[0]
    pt = zlib.decompressobj().decompress(dec[4:])
    if plen != len(pt):
        raise ValueError(f"S2C 长度头不符: 声明{plen} 实际{len(pt)}")
    return pt


if __name__ == '__main__':
    from pathlib import Path
    # 自测: v6 报文
    body = Path('../../captures/PAIR3_body.bin').read_bytes()
    pt = body_decrypt(body, bytes.fromhex('3da60bf1320091e2'))
    print(f"v6 buy body({len(body)}B) -> 明文 {len(pt)}B: {pt[:24].hex(' ')}")
    # v3
    body3 = Path('../../captures/PAIR_body_310.bin').read_bytes()
    pt3 = body_decrypt(body3, bytes.fromhex('cb4295a7be472f1e'))
    print(f"v3 buy body({len(body3)}B) -> 明文 {len(pt3)}B: {pt3[:24].hex(' ')}")
    # 0124
    import glob
    f124 = glob.glob('../../captures/buy3/send_content_1_*.bin')
    if f124:
        c = Path(f124[0]).read_bytes()
        b124 = bytes(c[16:16+253])
        pt124 = body_decrypt(b124, bytes.fromhex('cb4295a7be472f1e'))
        print(f"v3 0124 body(253B) -> 明文 {len(pt124)}B: {pt124[:24].hex(' ')}")
