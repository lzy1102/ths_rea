import platform

APP_ID = "2022021120720687"
PRODUCT_NAME = "同花顺远航版"
AUTH_CENTER_HOST = "auth.10jqka.com.cn"
AUTH_CENTER_URL = "http://auth.10jqka.com.cn/verify2"
DEFAULT_QSID = "800"
ENCODING = "gbk"
SIGN_VERSION = "3"
DEFAULT_C_VERSION = "9.60.71"
PRODUCT_VALUE = "" if platform.system() == "Linux" else "hevo_"

AES_IV = "hevoclientpc0000"
SYMMETRIC_KEY = "thsqhtPC88^"
ENCRYPTED_KEY = "fCB+KE6AkKX4aIX8TenHxwPNztfT1j6jL/nj3Mwbnm0="

CUSTOM_BASE64_ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/\x00"
STANDARD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

REQUEST_ID_TREND = 207

DEFAULT_FIELDS = [
    "date_time",
    "open",
    "high",
    "low",
    "latest",
    "prev_close",
    "transaction_volume",
    "transaction_amount",
    "security_name",
    "rise_percentage",
]

MARKETS = {
    "USHA": "USHA",
    "USHB": "USHB",
    "USHI": "USHI",
}
