# -*- coding: utf-8 -*-
"""扫码登录（手机同花顺 App 扫一扫, 无需密码）

协议 (来自 upass 扫码页 JS):
    GET  /scan/creatCode                     -> {qrid}
    GET  /scan/creatImg?qrid=<qrid>          -> 二维码 PNG
    POST /scan/getInfoNew {qrid,state,page_source}
         status: 1=等待扫码 2=已扫码待确认 3=成功(含 account/password/expireTime)
    成功后 -> unified_login(account, password) -> 会话 cookie

用法:
    python qr_login.py
"""
import json
import os
import sys
import time
import webbrowser
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ths_client.login import ThsAuth
from ths_client.session import ThsSession

HERE = Path(__file__).resolve().parent
SCAN_BASE = "http://upass.10jqka.com.cn"
SESSION_FILE = HERE / "session.json"
UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36"


def get_qrid(http: requests.Session) -> str:
    http.headers["Referer"] = "http://upass.10jqka.com.cn/scan?platform=pc_client"
    http.get(f"{SCAN_BASE}/scan", params={"platform": "pc_client"}, timeout=20)
    r = http.get(f"{SCAN_BASE}/scan/creatCode",
                 params={"platform": "pc_client"}, timeout=20)
    j = r.json()
    qrid = j.get("qrid") or j.get("data", {}).get("qrid")
    if not qrid:
        raise RuntimeError(f"creatCode 响应异常: {r.text[:200]}")
    return qrid


def save_qr(http: requests.Session, qrid: str) -> Path:
    r = http.get(f"{SCAN_BASE}/scan/creatImg", params={"qrid": qrid}, timeout=20)
    p = HERE / "qr.png"
    p.write_bytes(r.content)
    return p


def write_viewer() -> Path:
    html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>同花顺扫码登录</title></head>
<body style="text-align:center;font-family:sans-serif">
<h3>请用手机同花顺App扫描（过期自动刷新）</h3>
<img id="qr" src="qr.png" style="width:280px;height:280px">
<script>
setInterval(function(){document.getElementById('qr').src='qr.png?t='+Date.now();},2000);
</script></body></html>"""
    p = HERE / "qr_view.html"
    p.write_text(html, encoding="utf-8")
    return p


def refresh_qr(http: requests.Session, viewer_opened: bool):
    qrid = get_qrid(http)
    save_qr(http, qrid)
    if not viewer_opened:
        write_viewer()
        webbrowser.open((HERE / "qr_view.html").as_uri())
        print("      已在浏览器打开二维码查看页 (自动刷新)")
    else:
        print(f"      [刷新] 新 qrid = {qrid}")
    return qrid


def poll(http: requests.Session, qrid: str, timeout_s: int = 180) -> dict:
    deadline = time.time() + timeout_s
    state = 1
    last_status = None
    while time.time() < deadline:
        r = http.post(f"{SCAN_BASE}/scan/getInfoNew",
                      data={"qrid": qrid, "state": state,
                            "page_source": "client_screen"}, timeout=20)
        try:
            j = r.json()
        except Exception:
            print("[!] 响应非 JSON:", r.text[:120])
            time.sleep(2)
            continue
        st = int(j.get("status", -1))
        if st != last_status:
            labels = {0: "二维码失效", 1: "等待扫码...", 2: "已扫码, 请在手机上确认",
                      3: "确认成功!"}
            print(f"[*] status={st} {labels.get(st, '')}")
            last_status = st
        if st == 0:
            return {"status": 0}
        if st == 3:
            return j
        state = 1
        time.sleep(1.5)
    return {"status": -1, "error": "timeout"}


def main():
    http = requests.Session()
    http.headers["User-Agent"] = UA

    print("=" * 52)
    print(" 同花顺扫码登录 (二维码过期自动刷新)")
    print("=" * 52)
    print("[*] 请先确保手机同花顺App已登录 (QQ登录即可), 再扫码")
    viewer_opened = False
    deadline = time.time() + 300
    result = None
    while time.time() < deadline:
        qrid = refresh_qr(http, viewer_opened)
        viewer_opened = True
        res = poll(http, qrid, timeout_s=max(30, int(deadline - time.time())))
        if res.get("status") == 3:
            result = res
            break
    if not result:
        print("[!] 超时未完成扫码")
        raise SystemExit(1)
    res = result

    account = res.get("account", "")
    password = res.get("password", "")
    print(f"[3/4] 扫码成功! 完整凭据字段:")
    print("      " + json.dumps({k: v for k, v in res.items() if k != "raw"},
                                   ensure_ascii=False)[:400])

    dev = {}
    dev_file = HERE / "device.json"
    if dev_file.exists():
        dev = json.loads(dev_file.read_text(encoding="utf-8"))
    print(f"      设备参数: imei={str(dev.get('imei',''))[:8]}... "
          f"did={str(dev.get('did',''))[:8]}... ukey={str(dev.get('ukey',''))[:8]}...")

    import hashlib
    auth = ThsAuth()
    acc_s = str(account)
    pw = str(password)
    variants = [
        ("GBK账号+RSA密码", acc_s.encode("gbk"), pw, True, True),
        ("GBK账号+RSA(md5密码)", acc_s.encode("gbk"),
         hashlib.md5(pw.encode()).hexdigest(), True, True),
        ("UTF8账号+RSA密码(对照)", acc_s, pw, True, True),
        ("GBK账号+明文密码", acc_s.encode("gbk"), pw, True, False),
    ]

    login_res = None
    for label, acc, pwd, enc_acc, enc_pwd in variants:
        print(f"[*] 尝试登录方案: {label}")
        r = auth.unified_login(acc, pwd,
                               imei=dev.get("imei"), did=dev.get("did"),
                               ukey=dev.get("ukey"),
                               encrypt_account=enc_acc, encrypt_passwd=enc_pwd)
        print(f"    code={r.get('code')} rcode={r.get('rcode')} msg={r.get('msg')}")
        login_res = r
        if r.get("code") == "0" or r.get("userid"):
            break
    print(f"[4/4] 登录结果: {login_res.get('raw', '')[:300]}")
    if not (login_res.get("code") == "0" or login_res.get("userid")):
        print("[!] 所有方案均未成功, 原始响应已输出")
        raise SystemExit(1)

    userid = login_res.get("userid") or ""
    sessionid = login_res.get("sessionid") or ""
    signvalid = login_res.get("signvalid") or ""
    expires = login_res.get("expires") or ""
    if not signvalid and expires:
        signvalid = expires.replace("-", "").replace(" ", "").replace(":", "")[:10]
    print(f"[4/4] userid={userid} sessionid={str(sessionid)[:12]}... "
          f"signvalid={signvalid} expires={expires}")

    sess = ThsSession(userid=userid, sessionid=sessionid, signvalid=signvalid,
                      account=str(account))
    info = auth.fetch_cookies(userid, sessionid, signvalid)
    sess.cookies = info.get("cookies", {})
    sess.save(SESSION_FILE)
    print("[OK] 会话已保存 ->", SESSION_FILE)
    print("     cookies:", list(sess.cookies.keys()))


if __name__ == "__main__":
    main()
