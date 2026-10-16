# -*- coding: utf-8 -*-
"""统一登录 (同花顺通行证)

流程:
    GET  auth.10jqka.com.cn/verify2?reqtype=do_rsa&type=get_pubkey
    GET  auth.10jqka.com.cn/verify2?reqtype=unified_login&account=<RSA>&passwd=<RSA>&...
    成功响应含 userid/sessionid/signvalid -> 由 docookie2.php 落 cookie

参数说明 (来自客户端日志实测):
    rsa_version=default_5, ta_appid=2020063035285685, uver=E029.60.71.0088, ttype=PC
    imei/did/dpass/ukey 为设备参数, 可选 (缺失不阻塞解密校验)
"""
import re
import socket
import xml.etree.ElementTree as ET

import requests

from .crypto import rsa_encrypt_b64

AUTH_BASE = "https://auth.10jqka.com.cn/verify2"
COOKIE_URL = "http://upass.10jqka.com.cn/docookie2.php"
TA_APPID = "2020063035285685"
UVER = "E029.60.71.0088"
UA = ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")


class LoginError(Exception):
    pass


class ThsAuth:
    def __init__(self, timeout: int = 20):
        self.http = requests.Session()
        self.http.headers["User-Agent"] = UA
        self.timeout = timeout

    def get_pubkey(self):
        r = self.http.get(f"{AUTH_BASE}?reqtype=do_rsa&type=get_pubkey",
                          timeout=self.timeout)
        r.encoding = "gbk"
        xml = ET.fromstring(r.text)
        item = xml.find("item")
        if item is None:
            raise LoginError(f"get_pubkey 响应异常: {r.text[:200]}")
        n = int(item.get("modulus"), 16)
        e = int(item.get("publicExponent"), 16)
        return n, e, item.get("rsa_version", "default_5")

    def unified_login(self, account, passwd, *, imei=None, did=None,
                      ukey=None, dpass=None, hostname=None,
                      encrypt_account=True, encrypt_passwd=True) -> dict:
        n, e, ver = self.get_pubkey()

        def enc(val, flag):
            if not flag:
                return val if isinstance(val, str) else val.decode("gbk", "replace")
            return rsa_encrypt_b64(val, n, e)

        params = {
            "reqtype": "unified_login",
            "account": enc(account, encrypt_account),
            "passwd": enc(passwd, encrypt_passwd),
            "rsa_version": ver,
            "msg": "1",
            "ta_appid": TA_APPID,
            "uver": UVER,
            "ttype": "PC",
        }
        if imei:
            params["imei"] = imei
        if did:
            params["did"] = did
        if ukey:
            params["ukey"] = ukey
        if dpass:
            params["dpass"] = dpass
        r = self.http.get(AUTH_BASE, params=params, timeout=self.timeout)
        r.encoding = "gbk"
        return self.parse_response(r.text)

    @staticmethod
    def parse_response(xml_text: str) -> dict:
        root = ET.fromstring(xml_text)
        ret = root.find("ret")
        out = {
            "code": ret.get("code") if ret is not None else None,
            "msg": ret.get("msg") if ret is not None else None,
            "rcode": ret.get("rcode") if ret is not None else None,
            "raw": xml_text,
        }
        for item in root.findall("item"):
            out.update(item.attrib)
        for elem in root.iter():
            out.update(elem.attrib)
        for key in ("userid", "userId", "user_id", "sessionid", "sessionId",
                    "session_id", "signvalid", "signValid", "ticket"):
            if key not in out:
                m = re.search(rf'{key}="([^"]*)"', xml_text)
                if m:
                    out[key] = m.group(1)
        if "userid" not in out and out.get("userId"):
            out["userid"] = out["userId"]
        if "sessionid" not in out and out.get("sessionId"):
            out["sessionid"] = out["sessionId"]
        return out

    def fetch_cookies(self, userid: str, sessionid: str, signvalid: str):
        url = (f"{COOKIE_URL}?userid={userid}&sessionid={sessionid}"
               f"&signvalid={signvalid}")
        r = self.http.get(url, timeout=self.timeout)
        r.encoding = "gbk"
        return {"status": r.status_code, "body": r.text[:500],
                "cookies": self.http.cookies.get_dict()}

    def local_hostname(self) -> str:
        try:
            return socket.gethostname()
        except Exception:
            return ""
