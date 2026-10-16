# -*- coding: utf-8 -*-
"""
THS 统一登录协议复刻测试（纯标准库，无第三方依赖）
流程: do_rsa get_pubkey -> RSA(PKCS#1 v1.5) 加密 -> unified_login

仅用于协议格式验证：默认用假账号测试，观察服务器响应。
用法: python ths_login_test.py [账号] [密码]
"""
import base64
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)"
BASE = "https://auth.10jqka.com.cn/verify2"
TA_APPID = "2020063035285685"
UVER = "E029.60.71.0088"


def http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return r.read().decode("gbk", "replace")


def get_pubkey():
    xml = http_get(f"{BASE}?reqtype=do_rsa&type=get_pubkey")
    n = int(re.search(r'modulus="([0-9A-Fa-f]+)"', xml).group(1), 16)
    e = int(re.search(r'publicExponent="([0-9A-Fa-f]+)"', xml).group(1), 16)
    ver = re.search(r'rsa_version="([^"]+)"', xml).group(1)
    return n, e, ver


def rsa_encrypt_b64(msg: str, n: int, e: int, k: int = 128, mode: str = "pkcs1") -> str:
    """RSA 加密 + base64。mode: pkcs1 | raw0r(右侧补零) | raw0l(左侧补零)"""
    m = msg.encode("utf-8")
    if mode == "pkcs1":
        if len(m) > k - 11:
            raise ValueError("message too long")
        while True:
            ps = os.urandom(k - 3 - len(m))
            if 0 not in ps:
                break
        em = b"\x00\x01" + ps + b"\x00" + m
    elif mode == "pkcs1b":
        if len(m) > k - 11:
            raise ValueError("message too long")
        while True:
            ps = os.urandom(k - 3 - len(m))
            if 0 not in ps:
                break
        em = b"\x00\x02" + ps + b"\x00" + m
    elif mode == "raw0r":
        em = m + b"\x00" * (k - len(m))
    elif mode == "raw0l":
        em = b"\x00" * (k - len(m)) + m
    else:
        raise ValueError(f"unknown mode {mode}")
    c = pow(int.from_bytes(em, "big"), e, n)
    return base64.b64encode(c.to_bytes(k, "big")).decode()


def unified_login(account: str, passwd: str, device: dict = None, mode: str = "pkcs1"):
    n, e, ver = get_pubkey()
    print(f"[i] pubkey: {n.bit_length()}bit e={e} version={ver} mode={mode}")

    params = {
        "reqtype": "unified_login",
        "account": rsa_encrypt_b64(account, n, e, mode=mode),
        "passwd": rsa_encrypt_b64(passwd, n, e, mode=mode),
        "rsa_version": ver,
        "msg": "1",
        "ta_appid": TA_APPID,
        "uver": UVER,
        "ttype": "PC",
    }
    if device:
        params.update(device)

    url = BASE + "?" + urllib.parse.urlencode(params)
    print(f"[i] request built ({len(url)} chars)")
    resp = http_get(url)
    print("[<] response:")
    print(resp[:1500])
    return resp


if __name__ == "__main__":
    acc = sys.argv[1] if len(sys.argv) > 1 else "test_fake_account_0001"
    pwd = sys.argv[2] if len(sys.argv) > 2 else "123456"
    mode = sys.argv[3] if len(sys.argv) > 3 else "pkcs1b"
    print(f"[i] testing with account={acc!r} (fake) mode={mode}")
    unified_login(acc, pwd, mode=mode)
