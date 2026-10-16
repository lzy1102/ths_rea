# -*- coding: utf-8 -*-
"""ths_client 演示

用法:
    python ths_client_demo.py --test              # 假账号验证协议 (预期"用户名或密码错误")
    python ths_client_demo.py <账号> <密码>        # 真实登录 (仅限本人账号)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ths_client.login import ThsAuth
from ths_client.session import ThsSession
from ths_client.trade import build_buy, build_sell

SESSION_FILE = Path(__file__).resolve().parent / "session.json"


def main():
    args = [a for a in sys.argv[1:]]
    auth = ThsAuth()

    if not args or args[0] == "--test":
        print("[*] 协议自检: 假账号 unified_login")
        res = auth.unified_login("test_fake_account_0001", "123456")
        print("    code=%s rcode=%s msg=%s" % (res["code"], res["rcode"], res["msg"]))
        if res.get("rcode") == "-10002":
            print("[OK] 加密链路正常 (服务器已解密并校验, 仅账号不存在)")
        else:
            print("[!] 响应异常, 需要检查:", res)
        return

    account, passwd = args[0], args[1]
    print("[*] 登录:", account)
    res = auth.unified_login(account, passwd)
    print("    code=%s msg=%s" % (res["code"], res["msg"]))
    if res["code"] == "0" or res.get("userid"):
        sess = ThsSession(
            userid=res.get("userid", ""),
            sessionid=res.get("sessionid", ""),
            signvalid=res.get("signvalid", ""),
            account=account,
        )
        if sess.userid and sess.sessionid:
            print("[*] 落 cookie ...")
            info = auth.fetch_cookies(sess.userid, sess.sessionid, sess.signvalid)
            sess.cookies = info.get("cookies", {})
            print("    cookie:", list(sess.cookies.keys()))
        sess.save(SESSION_FILE)
        print("[OK] 会话已保存 ->", SESSION_FILE)
        print("     userid=%s sessionid=%s signvalid=%s" %
              (sess.userid, sess.sessionid, sess.signvalid))
    else:
        print("[!] 登录失败:", res.get("msg"))

    print("\n[示例] 下单报文预览:")
    print(build_buy("300012", "14.16", 100, userkey="31_12345678_1542"))
    print(build_sell("300012", "14.16", 100, userkey="31_12345678_1542"))


if __name__ == "__main__":
    main()
