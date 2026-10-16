# -*- coding: utf-8 -*-
"""RSA 加密 (服务器实测通过的方案)

方案: RSA-1024, e=65537, PKCS#1 v1.5 block type 0x02, base64 输出
验证: 用假账号请求 unified_login, 服务器返回"用户名或密码错误"
      (rcode=-10002) 证明解密与校验均通过
"""
import base64
import os

BLOCK_SIZE = 128


def rsa_encrypt_b64(msg, n: int, e: int, block_size: int = BLOCK_SIZE) -> str:
    if isinstance(msg, str):
        m = msg.encode("utf-8")
    else:
        m = bytes(msg)
    if len(m) > block_size - 11:
        raise ValueError("message too long for single RSA block")
    while True:
        ps = os.urandom(block_size - 3 - len(m))
        if 0 not in ps:
            break
    em = b"\x00\x02" + ps + b"\x00" + m
    c = pow(int.from_bytes(em, "big"), e, n)
    return base64.b64encode(c.to_bytes(block_size, "big")).decode()
