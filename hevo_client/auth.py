import base64
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime

from .constants import APP_ID, AUTH_CENTER_URL, DEFAULT_C_VERSION, DEFAULT_QSID, PRODUCT_NAME, PRODUCT_VALUE, SIGN_VERSION
from .crypto import md5_hex, rsa_encrypt_pkcs1_v15
from .encoding import (dictionary_to_ini_string, encode_signature, encode_url, gbk_decode, gbk_encode, hexin_base64_encode, make_query_string)
from .errors import AuthError

class AuthPublicKeyV1:
    def __init__(self):
        self.error_code = 0
        self.error_message = ""
        self.rsa_version = ""
        self.public_key = ""
        self.modulus = ""
        self.public_exponent = ""

    @property
    def is_bad(self):
        return self.error_code < 0

    @property
    def n(self):
        return int(self.modulus, 16) if self.modulus else 0

    @property
    def e(self):
        return int(self.public_exponent, 16) if self.public_exponent else 0

    @property
    def IsBad(self):
        return self.is_bad

    @property
    def N(self):
        return self.n

    @property
    def E(self):
        return self.e

    @property
    def ErrorCode(self):
        return self.error_code

    @property
    def ErrorMessage(self):
        return self.error_message

    @property
    def RsaVersion(self):
        return self.rsa_version

    @property
    def PublicKey(self):
        return self.public_key

    @property
    def Modulus(self):
        return self.modulus

    @property
    def PublicExponent(self):
        return self.public_exponent

    def ExportRSAParameters(self):
        class _RSAParameters(dict):
            pass
        result = _RSAParameters()
        result["modulus"] = self.modulus
        result["publicExponent"] = self.public_exponent
        result["Modulus"] = bytes.fromhex(self.modulus) if self.modulus else b""
        result["Exponent"] = bytes.fromhex(self.public_exponent) if self.public_exponent else b""
        result["n"] = self.n
        result["e"] = self.e
        result.Modulus = result["Modulus"]
        result.Exponent = result["Exponent"]
        result.modulus = result["modulus"]
        result.publicExponent = result["publicExponent"]
        result.n = result["n"]
        result.e = result["e"]
        return result

    @staticmethod
    def HexStringToBytes(hex_string):
        text = hex_string
        if len(text) % 2 != 0:
            text = "0" + text
        return bytes.fromhex(text)

    @classmethod
    def load_from_response(cls, text):
        obj = cls()
        try:
            root = ET.fromstring(text)
            ret = root.find("ret")
            obj.error_message = ret.get("msg", "")
            code = ret.get("code", "0")
            obj.error_code = int(code)
            item = root.find("item")
            if item is not None:
                obj.rsa_version = item.get("rsa_version") or ""
                obj.public_key = item.get("pubkey") or ""
                obj.modulus = item.get("modulus") or ""
                obj.public_exponent = item.get("publicExponent") or ""
        except Exception:
            raise AuthError("bad auth public key response")
        return obj

class AuthSessionV1:
    def __init__(self):
        self.is_bad = False
        self.error_code = 0
        self.error_message = ""
        self.rsa_version = ""
        self.user_id = ""
        self.session_id = ""
        self.input_user_name = ""
        self.input_password = ""
        self.auth_request_type = None

    @classmethod
    def load_from_response(cls, text):
        obj = cls()
        try:
            root = ET.fromstring(text)
            ret = root.find("ret")
            obj.error_message = ret.get("msg", "")
            obj.error_code = int(ret.get("code", "0"))
            obj.is_bad = obj.error_code < 0
            item = root.find("item")
            if item is not None:
                obj.user_id = item.get("userid") or item.get("account") or ""
                obj.session_id = item.get("sessionid") or ""
                obj.rsa_version = item.get("rsa_version") or ""
        except Exception:
            raise AuthError("bad auth session response")
        return obj

class AuthPassportV1:
    need_fix_passport_value_string = True

    def __init__(self):
        self.error_code = 0
        self.error_message = ""
        self.passport_value_string = ""
        self.signature = ""

    @property
    def is_bad(self):
        return self.error_code < 0

    @property
    def fixed_passport_value_string(self):
        index = self.passport_value_string.find("|signlength")
        if index >= 0:
            return self.passport_value_string[:index]
        return self.passport_value_string

    @property
    def passport_value_dictionary(self):
        result = {}
        for entry in self.passport_value_string.split("|"):
            if not entry:
                continue
            parts = entry.split("=")
            if len(parts) == 2:
                result[parts[0]] = parts[1]
        return result

    @property
    def sid_dictionary(self):
        result = {}
        text = self.passport_value_dictionary.get("sid", "")
        for part in text.split(";"):
            if not part:
                continue
            pieces = part.split(",")
            if len(pieces) == 2:
                result[pieces[0]] = pieces[1]
        return result

    @property
    def is_expired(self):
        try:
            if "signvalid" in self.passport_value_dictionary:
                value = self.passport_value_dictionary["signvalid"]
                dt = datetime.strptime(value, "%Y%m%d%H")
                if (dt - datetime.now()).total_seconds() / 3600.0 < 12.0:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def load_from_response(cls, text):
        obj = cls()
        try:
            root = ET.fromstring(text)
            ret = root.find("ret")
            obj.error_message = ret.get("msg", "")
            obj.error_code = int(ret.get("code", "0"))
            item = root.find("item")
            if item is not None:
                obj.passport_value_string = item.get("passport") or ""
                obj.signature = item.get("signature") or ""
        except Exception:
            raise AuthError("bad auth passport response")
        return obj

    @classmethod
    def bad_value(cls):
        obj = cls()
        obj.error_code = -100
        return obj

    def make_passport64_value(self):
        if self.need_fix_passport_value_string:
            text = self.fixed_passport_value_string
        else:
            text = self.passport_value_string
        text = text.replace("|", "\r\n") + "\r\n"
        text_bytes = gbk_encode(text)
        sig_bytes = gbk_encode(self.signature)
        enc_sig = encode_signature(sig_bytes)
        num = 5 + len(text_bytes) + len(enc_sig) + 1
        head = struct.pack("<hBh", num, 6, len(enc_sig))
        return base64.b64encode(head + enc_sig + text_bytes + b"\x00").decode("ascii")

def get_mac_address():
    try:
        import uuid
        node = uuid.getnode()
        return "-".join("%02X" % ((node >> (8 * i)) & 0xFF) for i in range(5, -1, -1))
    except Exception:
        return "00:00:00:00:00:00"

def get_imei_for_auth():
    mac = get_mac_address()
    try:
        return md5_hex(mac + "000000000000000000000000000000")
    except Exception:
        return "".join(mac.split("-")) + "AABBCCDDEEFFGGHHIIGG"

def convert_input_password_to_md5(password, stored_password=None, is_pwd_need_md5_process=True):
    if not password:
        return ""
    if not is_pwd_need_md5_process:
        return password
    if stored_password is not None and stored_password == password:
        return password
    if re.match(r"^[0-9a-fA-F]{32,}$", password):
        return password
    return md5_hex(password).lower()

def get_auth_public_key(http_get, url):
    content = http_get(url)
    if isinstance(content, (bytes, bytearray)):
        text = gbk_decode(content)
    else:
        text = content
    return AuthPublicKeyV1.load_from_response(text)

def get_auth_info(http_post, account, password, public_key, qsid=DEFAULT_QSID):
    account_bytes = gbk_encode(account)
    password_bytes = gbk_encode(password)
    n = public_key.n
    e = public_key.e
    enc_account = rsa_encrypt_pkcs1_v15(account_bytes, n, e)
    enc_password = rsa_encrypt_pkcs1_v15(password_bytes, n, e)
    b64_account = hexin_base64_encode(enc_account)
    b64_password = hexin_base64_encode(enc_password)
    kvs = {
        "account": encode_url(b64_account),
        "passwd": encode_url(b64_password),
        "reqtype": "unified_login",
        "rsa_version": public_key.rsa_version,
        "ta_appid": APP_ID,
    }
    query = make_query_string(kvs, sorted_keys=True)
    response = http_post(AUTH_CENTER_URL, gbk_encode(query), {"Content-Type": "application/x-www-form-urlencoded"})
    if isinstance(response, (bytes, bytearray)):
        text = gbk_decode(response)
    else:
        text = response
    session = AuthSessionV1.load_from_response(text)
    if session is None or session.is_bad:
        return None
    session.input_user_name = account
    session.input_password = password
    return session

def get_auth_passport(http_post, session, qsid=DEFAULT_QSID):
    kvs = {
        "reqtype": "verify",
        "product": "S01",
        "imei": get_imei_for_auth(),
        "userid": session.user_id,
        "sessionid": session.session_id,
        "qsid": qsid,
        "version": SIGN_VERSION,
        "sdsn": "",
        "securities": PRODUCT_NAME,
        "nohqlist": "0",
        "newwgflag": "3",
    }
    query = make_query_string(kvs, sorted_keys=True)
    response = http_post(AUTH_CENTER_URL, gbk_encode(query), {"Content-Type": "application/x-www-form-urlencoded"})
    if isinstance(response, (bytes, bytearray)):
        text = gbk_decode(response)
    else:
        text = response
    passport = AuthPassportV1.load_from_response(text)
    if passport.is_bad:
        return None
    return passport

def make_auth_bytes(passport64, user_id, qsid=DEFAULT_QSID, mac_address=None):
    if mac_address is None:
        mac_address = get_mac_address()
    ini = {
        "Ask": "login",
        "C-Version": PRODUCT_VALUE + DEFAULT_C_VERSION,
        "UserName": user_id,
        "C-Language": "zh_CN.GBK",
        "Qsid": qsid,
        "Passport64": passport64,
        "VerifyType": "1",
        "Mac64": base64.b64encode(gbk_encode(mac_address)).decode("ascii"),
    }
    ini_str = dictionary_to_ini_string(ini, "\n")
    if ini_str.endswith("\n"):
        ini_str = ini_str[:-1]
    body = gbk_encode(ini_str)
    return b"A" + struct.pack("<H", len("zh_CN.GBK")) + gbk_encode("zh_CN.GBK") + struct.pack("<H", len(body)) + body

def login(username, password, http_get, http_post, qsid=DEFAULT_QSID):
    public_key_url = AUTH_CENTER_URL + "?reqtype=do_rsa&type=get_pubkey"
    public_key = get_auth_public_key(http_get, public_key_url)
    if public_key.is_bad:
        raise AuthError("bad public key")
    session = get_auth_info(http_post, username, password, public_key, qsid)
    if session is None or session.is_bad:
        raise AuthError("bad auth session")
    passport = get_auth_passport(http_post, session, qsid)
    if passport is None or passport.is_bad:
        raise AuthError("bad auth passport")
    passport64 = passport.make_passport64_value()
    auth_bytes = make_auth_bytes(passport64, session.user_id, qsid, get_mac_address())
    return {
        "public_key": public_key,
        "session": session,
        "passport": passport,
        "passport64": passport64,
        "auth_bytes": auth_bytes,
    }


AuthPublicKeyV1.LoadFromResponse = AuthPublicKeyV1.load_from_response
AuthSessionV1.LoadFromResponse = AuthSessionV1.load_from_response
AuthPassportV1.LoadFromResponse = AuthPassportV1.load_from_response

AuthSessionV1.UserID = property(lambda self: self.user_id)
AuthSessionV1.SessionID = property(lambda self: self.session_id)
AuthSessionV1.RsaVersion = property(lambda self: self.rsa_version)
AuthSessionV1.ErrorCode = property(lambda self: self.error_code)
AuthSessionV1.ErrorMessage = property(lambda self: self.error_message)
AuthSessionV1.InputUserName = property(lambda self: self.input_user_name)
AuthSessionV1.InputPassword = property(lambda self: self.input_password)
AuthSessionV1.IsBad = property(lambda self: self.is_bad)

AuthPassportV1.PassportValueString = property(lambda self: self.passport_value_string)
AuthPassportV1.Signature = property(lambda self: self.signature)
AuthPassportV1.IsBad = property(lambda self: self.is_bad)
AuthPassportV1.IsExpired = property(lambda self: self.is_expired)
AuthPassportV1.SidDictionary = property(lambda self: self.sid_dictionary)
AuthPassportV1.PassportValueDictionary = property(lambda self: self.passport_value_dictionary)
AuthPassportV1.FixedPassportValueString = property(lambda self: self.fixed_passport_value_string)
AuthPassportV1.MakePassport64Value = AuthPassportV1.make_passport64_value
AuthPassportV1.LoadFromPlatformResponse = AuthPassportV1.load_from_response

class _AuthPassportBadValue:
    def __get__(self, obj, owner):
        return owner.bad_value()
    def __call__(self, *args, **kwargs):
        return AuthPassportV1.bad_value()

AuthPassportV1.BadValue = _AuthPassportBadValue()

GetMacAddress = get_mac_address
GetImeiForAuth = get_imei_for_auth
ConvertInputPasswordToMd5Encry = convert_input_password_to_md5
GetAuthPublicKey = get_auth_public_key
GetAuthInfo = get_auth_info
GetAuthPassport = get_auth_passport
MakeAuthBytes = make_auth_bytes


AuthPublicKeyV1.IsBad = property(lambda self: self.is_bad)
AuthPublicKeyV1.N = property(lambda self: self.n)
AuthPublicKeyV1.E = property(lambda self: self.e)
AuthPublicKeyV1.ErrorCode = property(lambda self: self.error_code)
AuthPublicKeyV1.ErrorMessage = property(lambda self: self.error_message)
AuthPublicKeyV1.RsaVersion = property(lambda self: self.rsa_version)
AuthPublicKeyV1.PublicKey = property(lambda self: self.public_key)
AuthPublicKeyV1.Modulus = property(lambda self: self.modulus)
AuthPublicKeyV1.PublicExponent = property(lambda self: self.public_exponent)
AuthPublicKeyV1.LoadFromResponse = AuthPublicKeyV1.load_from_response
AuthPublicKeyV1.HexStringToBytes = staticmethod(AuthPublicKeyV1.HexStringToBytes)
AuthSessionV1.IsBad = property(lambda self: self.is_bad)
AuthSessionV1.UserID = property(lambda self: self.user_id)
AuthSessionV1.SessionID = property(lambda self: self.session_id)
AuthSessionV1.RsaVersion = property(lambda self: self.rsa_version)
AuthSessionV1.ErrorCode = property(lambda self: self.error_code)
AuthSessionV1.ErrorMessage = property(lambda self: self.error_message)
AuthSessionV1.InputUserName = property(lambda self: self.input_user_name)
AuthSessionV1.InputPassword = property(lambda self: self.input_password)
AuthSessionV1.LoadFromResponse = AuthSessionV1.load_from_response
AuthPassportV1.IsBad = property(lambda self: self.is_bad)
AuthPassportV1.PassportValueString = property(lambda self: self.passport_value_string)
AuthPassportV1.Signature = property(lambda self: self.signature)
AuthPassportV1.IsExpired = property(lambda self: self.is_expired)
AuthPassportV1.SidDictionary = property(lambda self: self.sid_dictionary)
AuthPassportV1.PassportValueDictionary = property(lambda self: self.passport_value_dictionary)
AuthPassportV1.FixedPassportValueString = property(lambda self: self.fixed_passport_value_string)
AuthPassportV1.MakePassport64Value = AuthPassportV1.make_passport64_value
AuthPassportV1.LoadFromResponse = AuthPassportV1.load_from_response
AuthPassportV1.LoadFromPlatformResponse = AuthPassportV1.load_from_response
class _AuthPassportBadValue:
    def __get__(self, obj, owner):
        return owner.bad_value()
    def __call__(self, *args, **kwargs):
        return AuthPassportV1.bad_value()
AuthPassportV1.BadValue = _AuthPassportBadValue()
GetMacAddress = get_mac_address
GetImeiForAuth = get_imei_for_auth
ConvertInputPasswordToMd5Encry = convert_input_password_to_md5
GetAuthPublicKey = get_auth_public_key
GetAuthInfo = get_auth_info
GetAuthPassport = get_auth_passport
MakeAuthBytes = make_auth_bytes
