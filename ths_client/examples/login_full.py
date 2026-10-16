# -*- coding: utf-8 -*-
"""完整登录流程（可交付版, 不需要抓包）

流程:
    1. get_pubkey            (auth.10jqka.com.cn/verify2)
    2. RSA 加密 account/passwd (PKCS#1 v1.5 type 02)
    3. unified_login         -> userid / sessionid / signvalid
    4. docookie2.php         -> 会话 cookies
    5. 调 ugc 自选股接口验证会话
    6. 保存 session.json     (下次免登录)

设备指纹: 首次运行自动生成并保存在 device.json (每台机器固定)
    imei / did / ukey 均为 32 位十六进制

用法:
    python login_full.py             # 交互输入账号密码 (推荐)
    python login_full.py --test      # 协议自检 (假账号)
"""
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ths_client.login import ThsAuth
from ths_client.session import ThsSession

HERE = Path(__file__).resolve().parent
DEVICE_FILE = HERE / "device.json"
SESSION_FILE = HERE / "session.json"
RUN_LOG = HERE / "login_run.log"
UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36"


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
                st.flush()
            except Exception:
                pass

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


def _start_logging():
    log = open(RUN_LOG, "w", encoding="utf-8")
    sys.stdout = _Tee(sys.stdout, log)
    sys.stderr = _Tee(sys.stderr, log)
    return log


def load_or_create_device() -> dict:
    if DEVICE_FILE.exists():
        return json.loads(DEVICE_FILE.read_text(encoding="utf-8"))
    dev = {
        "imei": hashlib.md5(os.urandom(16)).hexdigest().upper(),
        "did": hashlib.md5(os.urandom(16)).hexdigest().upper(),
        "ukey": hashlib.md5(os.urandom(16)).hexdigest().upper(),
    }
    DEVICE_FILE.write_text(json.dumps(dev, indent=2), encoding="utf-8")
    print(f"[*] 已生成设备指纹 -> {DEVICE_FILE}")
    return dev


def verify_session(cookies: dict, verbose=True) -> bool:
    http = requests.Session()
    http.cookies.update(cookies)
    http.headers["User-Agent"] = UA
    try:
        r = http.get("https://ugc.10jqka.com.cn/optdata/selfstock/open/api/v1/query"
                     "?need_merge=0&from=thspc_main&support_all=1", timeout=20)
        j = r.json()
        field = j.get("data", {}).get("selfstock", "")
        n = len([c for c in field.split(",")[0].split("|") if c])
        if verbose:
            print(f"[*] 会话验证: 自选股接口返回 {n} 只 (HTTP {r.status_code})")
        return r.status_code == 200 and j.get("status_code") == 0
    except Exception as e:
        if verbose:
            print("[!] 会话验证异常:", e)
        return False


def login(account: str, passwd: str) -> ThsSession:
    dev = load_or_create_device()
    auth = ThsAuth()

    print("[1/5] 获取 RSA 公钥 ...")
    n, e, ver = auth.get_pubkey()
    print(f"      公钥 {n.bit_length()}bit, version={ver}")

    print("[2/5] 提交统一登录 ...")
    res = auth.unified_login(
        account, passwd,
        imei=dev["imei"], did=dev["did"], ukey=dev["ukey"])
    print(f"      code={res.get('code')} rcode={res.get('rcode')} msg={res.get('msg')}")

    if res.get("code") != "0" and not res.get("userid"):
        print("[!] 登录未成功。完整响应:")
        print(res.get("raw", ""))
        raise SystemExit(1)

    userid = res.get("userid") or res.get("user_id") or ""
    sessionid = res.get("sessionid") or res.get("session_id") or ""
    signvalid = res.get("signvalid") or ""
    expires = res.get("expires") or ""
    if not signvalid and expires:
        signvalid = expires.replace("-", "").replace(" ", "").replace(":", "")[:10]
    print(f"[3/5] userid={userid} sessionid={sessionid[:12]}... signvalid={signvalid}")

    sess = ThsSession(userid=userid, sessionid=sessionid, signvalid=signvalid,
                      account=account)

    print("[4/5] 获取会话 cookies ...")
    info = auth.fetch_cookies(userid, sessionid, signvalid)
    sess.cookies = info.get("cookies", {})
    print(f"      cookies: {list(sess.cookies.keys())}")

    print("[5/5] 验证会话 ...")
    if verify_session(sess.cookies):
        print("[OK] 会话可用!")
    else:
        print("[!] 会话验证未通过 (可能账号需要额外验证/绑定)")

    sess.save(SESSION_FILE)
    print(f"[OK] 会话已保存 -> {SESSION_FILE}")
    return sess


if __name__ == "__main__":
    _log = _start_logging()
    try:
        if len(sys.argv) > 2 and sys.argv[1] == "--secret":
            secret = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
            print("[*] 使用本地凭据文件登录 ...")
            login(secret["account"], secret["password"])
            raise SystemExit(0)

        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            print("[*] 协议自检 (假账号):")
            auth = ThsAuth()
            res = auth.unified_login("test_fake_account_0001", "123456")
            ok = res.get("rcode") == "-10002"
            print(f"    rcode={res.get('rcode')} msg={res.get('msg')}")
            print("[OK] 加密链路正常" if ok else "[!] 异常: " + str(res.get("raw")))
            raise SystemExit(0 if ok else 1)

        print("=" * 52)
        print(" 同花顺 Python 客户端 - 登录")
        print("=" * 52)
        acc = input("账号 (手机号/用户名): ").strip()
        pwd = getpass.getpass("密码 (输入不回显): ")
        login(acc, pwd)
    except SystemExit:
        raise
    except Exception:
        import traceback
        traceback.print_exc()
        print("\n[!] 发生异常, 详情已写入 login_run.log")
        raise SystemExit(1)
    finally:
        _log.flush()
        _log.close()
