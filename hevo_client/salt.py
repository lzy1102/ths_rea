import base64
import time
import xml.etree.ElementTree as ET

from .constants import AES_IV, APP_ID, AUTH_CENTER_URL, ENCRYPTED_KEY, SYMMETRIC_KEY
from .crypto import aes_decrypt_cbc, hmac_sha256_hex, rsa_encrypt_pkcs1_v15, sha256_hex
from .encoding import ascii_decode, encode_url, gbk_decode, gbk_encode, get_cord, handle_xor, hexin_base64_encode, make_query_string
from .errors import AuthError

SALT_GET_SALT_URL = "/verify3/gs"
SALT_LOGIN_URL = "/verify3/pwd_login"
SALT_SECOND_LOGIN_URL = "/verify3/pwd_login_again"
SALT_SIGN_VERSION = "3"
SALT_ENCODING = "gbk"
SALT_RESPONSE_TYPE = "json"


class SaltData:
    def __init__(self, dsk="", dsv="", ssv=""):
        self.dsk = dsk
        self.dsv = dsv
        self.ssv = ssv

    @property
    def Dsk(self):
        return self.dsk

    @property
    def Dsv(self):
        return self.dsv

    @property
    def Ssv(self):
        return self.ssv


class AuthSaltResponse:
    def __init__(self, code="", msg="", result=None):
        self.code = code
        self.msg = msg
        self.result = result if result is not None else SaltData()

    @property
    def Code(self):
        return self.code

    @property
    def Msg(self):
        return self.msg

    @property
    def Result(self):
        return self.result

    @classmethod
    def load_from_response(cls, text):
        import json
        obj = cls()
        try:
            data = json.loads(text)
        except Exception:
            raise AuthError("bad salt response")
        lower = dict((str(key).lower(), value) for key, value in data.items())
        obj.code = str(lower.get("code", ""))
        obj.msg = str(lower.get("msg", ""))
        result = lower.get("result") or {}
        if not isinstance(result, dict):
            result = {}
        result = dict((str(key).lower(), value) for key, value in result.items())
        obj.result = SaltData(
            dsk=str(result.get("dsk", "")),
            dsv=str(result.get("dsv", "")),
            ssv=str(result.get("ssv", "")),
        )
        return obj


def get_salt_sign_key(request_type="Salt", app_id=APP_ID, encrypted_key=ENCRYPTED_KEY,
                      initial_value=AES_IV, symmetric_key=SYMMETRIC_KEY):
    if request_type == "SaltTest":
        return app_id
    if request_type == "SaltDebug":
        return encrypted_key
    decrypted = aes_decrypt_cbc(encrypted_key, symmetric_key, initial_value)
    return base64.b64decode(decrypted).decode("utf-8")


def get_salt_sign_headers(body_str, sign_key, app_id=APP_ID, crnd=None, timestamp=None):
    if crnd is None:
        crnd = get_cord()
    if timestamp is None:
        from datetime import datetime
        timestamp = int((datetime.now() - datetime(1970, 1, 1, 8, 0, 0)).total_seconds())
    arg = sha256_hex(body_str).upper()
    message = "X-Auth-SignV3X-Auth-Time" + str(timestamp) + arg
    sign = hmac_sha256_hex(message, sign_key).upper()
    return {
        "X-Auth-AppId": app_id,
        "X-Auth-Sign": sign,
        "X-Auth-SignV": SALT_SIGN_VERSION,
        "X-Auth-Time": str(timestamp),
        "X-Auth-Crnd": crnd,
        "X-Auth-Ext": crnd,
    }


def encrypt_string(value, public_key):
    data = gbk_encode(value)
    encrypted = rsa_encrypt_pkcs1_v15(data, public_key.n, public_key.e)
    return encode_url(hexin_base64_encode(encrypted))


def second_encrypt_password_width_salt(password, dsv, public_key):
    key = sha256_hex(dsv)
    xored = handle_xor(password, key)
    value = base64.b64encode(xored.encode("ascii")).decode("ascii")
    return encrypt_string(value, public_key)


def encrypt_password_width_salt(password, crnd, salt_rsp, public_key):
    key = sha256_hex(crnd + salt_rsp.result.dsk)
    raw = base64.b64decode(salt_rsp.result.ssv)
    message = handle_xor(ascii_decode(raw), key)
    text = ""
    for part in message.split("$"):
        if not part:
            continue
        pieces = [item for item in part.split("=") if item]
        if len(pieces) >= 2:
            text = pieces[1]
    if not text:
        raise AuthError("salt arithmetic error")
    password2 = hmac_sha256_hex(password, text)
    return second_encrypt_password_width_salt(password2, salt_rsp.result.dsv, public_key)


def _salt_base_url(host):
    if "/verify2" in host:
        return host.rsplit("/verify2", 1)[0]
    return host.rstrip("/")


def get_salt_data(http_post, account_enc, rsa_version, sign_key, host=AUTH_CENTER_URL,
                  app_id=APP_ID, crnd=None):
    kvs = {
        "account": account_enc,
        "encoding": SALT_ENCODING,
        "rsa_version": rsa_version,
        "resp": SALT_RESPONSE_TYPE,
    }
    body = make_query_string(kvs)
    headers = get_salt_sign_headers(body, sign_key, app_id, crnd)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = http_post(_salt_base_url(host) + SALT_GET_SALT_URL, gbk_encode(body), headers)
    if isinstance(response, (bytes, bytearray)):
        text = gbk_decode(response)
    else:
        text = response
    return AuthSaltResponse.load_from_response(text)


def do_salt_auth(http_post, account_enc, enc_password, dsk, rsa_version, sign_key,
                 host=AUTH_CENTER_URL, app_id=APP_ID, crnd=None):
    kvs = {
        "account": account_enc,
        "passwd": enc_password,
        "dsk": dsk,
        "encoding": SALT_ENCODING,
        "rsa_version": rsa_version,
    }
    body = make_query_string(kvs)
    headers = get_salt_sign_headers(body, sign_key, app_id, crnd)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = http_post(_salt_base_url(host) + SALT_LOGIN_URL, gbk_encode(body), headers)
    if isinstance(response, (bytes, bytearray)):
        text = gbk_decode(response)
    else:
        text = response
    root = ET.fromstring(text)
    ret = root.find("ret")
    code = ret.get("code", "") if ret is not None else ""
    if code == "0":
        return root, None
    if code == "-10002":
        item = root.find("item")
        if item is None:
            raise AuthError("salt second login without item")
        data = SaltData(dsk=item.get("dsk") or "", dsv=item.get("dsv") or "")
        return root, data
    raise AuthError("salt auth failed: " + code)


def salt_auth_second_login(http_post, account_enc, password, data, public_key, sign_key,
                           host=AUTH_CENTER_URL, app_id=APP_ID, crnd=None):
    enc_password = second_encrypt_password_width_salt(password, data.dsv, public_key)
    kvs = {
        "account": account_enc,
        "passwd": enc_password,
        "dsk": data.dsk,
        "encoding": SALT_ENCODING,
        "rsa_version": public_key.rsa_version,
    }
    body = make_query_string(kvs)
    headers = get_salt_sign_headers(body, sign_key, app_id, crnd)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = http_post(_salt_base_url(host) + SALT_SECOND_LOGIN_URL, gbk_encode(body), headers)
    if isinstance(response, (bytes, bytearray)):
        text = gbk_decode(response)
    else:
        text = response
    return ET.fromstring(text)


def login_salt(username, password, http_get, http_post, request_type="Salt",
               host=AUTH_CENTER_URL, app_id=APP_ID):
    from .auth import AuthSessionV1, get_auth_public_key
    public_key = get_auth_public_key(http_get, host + "?reqtype=do_rsa&type=get_pubkey")
    if public_key.is_bad:
        raise AuthError("bad public key")
    crnd = get_cord()
    sign_key = get_salt_sign_key(request_type, app_id)
    account_enc = encrypt_string(username, public_key)
    salt_rsp = get_salt_data(http_post, account_enc, public_key.rsa_version, sign_key, host, app_id, crnd)
    if salt_rsp.code not in ("0", ""):
        raise AuthError("get salt failed: " + salt_rsp.code)
    enc_password = encrypt_password_width_salt(password, crnd, salt_rsp, public_key)
    root, second = do_salt_auth(http_post, account_enc, enc_password, salt_rsp.result.dsk,
                                public_key.rsa_version, sign_key, host, app_id, crnd)
    if second is not None:
        root = salt_auth_second_login(http_post, account_enc, password, second, public_key,
                                      sign_key, host, app_id, crnd)
    ret = root.find("ret")
    if ret is not None and ret.get("code", "0") not in ("0", ""):
        raise AuthError("salt login failed: " + ret.get("code", ""))
    item = root.find("item")
    session = AuthSessionV1()
    if item is not None:
        session.user_id = item.get("userid") or item.get("account") or ""
        session.session_id = item.get("sessionid") or ""
        session.rsa_version = item.get("rsa_version") or ""
    session.input_user_name = username
    session.input_password = password
    return session


AuthSaltResponse.LoadFromResponse = AuthSaltResponse.load_from_response
GetSaltSignKey = get_salt_sign_key
GetSaltSignHeaders = get_salt_sign_headers
EncryptString = encrypt_string
EncryptPasswordWidthSalt = encrypt_password_width_salt
SecondEncryptPasswordWidthSalt = second_encrypt_password_width_salt
GetSaltData = get_salt_data
DoSaltAuth = do_salt_auth
SaltAuthSecondLogin = salt_auth_second_login
LoginSalt = login_salt
