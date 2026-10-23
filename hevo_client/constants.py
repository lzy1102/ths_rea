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

REQUEST_ID_CANDLE_BASE = 210
REQUEST_ID_CANDLE_FINANCIAL = 211
REQUEST_ID_CANDLE_CALCULATION = 212
REQUEST_ID_CANDLE_EXTRA = 213
CANDLE_REQUEST_IDS = (
    REQUEST_ID_CANDLE_BASE,
    REQUEST_ID_CANDLE_FINANCIAL,
    REQUEST_ID_CANDLE_CALCULATION,
    REQUEST_ID_CANDLE_EXTRA,
)

PERIOD_REAL_IDS = {
    -1: 0,
    5: 16384,
    11: 20480,
    12: 24576,
    13: 24579,
    14: 28672,
    15: 12288,
    16: 12293,
    17: 12303,
    18: 12318,
    19: 12348,
    20: 12291,
    21: 12549,
    22: 12554,
    23: 12559,
    24: 12574,
    50: 16384,
}

PERIOD_ALIASES = {
    "trend": -1,
    "tick": -2,
    "day": 5,
    "daily": 5,
    "1d": 5,
    "week": 11,
    "weekly": 11,
    "1w": 11,
    "month": 12,
    "monthly": 12,
    "1M": 12,
    "season": 13,
    "quarter": 13,
    "1q": 13,
    "year": 14,
    "yearly": 14,
    "1y": 14,
    "one_min": 15,
    "1m": 15,
    "five_min": 16,
    "5m": 16,
    "fifteen_min": 17,
    "15m": 17,
    "thirty_min": 18,
    "30m": 18,
    "sixty_min": 19,
    "60m": 19,
    "three_min": 20,
    "3m": 20,
    "five_sec": 21,
    "5s": 21,
    "ten_sec": 22,
    "10s": 22,
    "fifteen_sec": 23,
    "15s": 23,
    "thirty_sec": 24,
    "30s": 24,
}

CANDLE_FIELD_IDS = {
    "date_time": 1,
    "market_type": 2,
    "full_code": 5,
    "prev_close": 6,
    "open": 7,
    "high": 8,
    "low": 9,
    "latest": 10,
    "close": 11,
    "transaction_volume": 13,
    "transaction_volume_shou": 13,
    "volume": 13,
    "transaction_amount": 19,
    "amount": 19,
    "security_name": 55,
    "trade_time": 56,
    "pre_settlement": 66,
    "time_stamp": 199,
    "real_turnover_rate": 2561,
    "turnover_NewYestodayrate": 68295,
    "rise_percentage": 199112,
    "turnover_rate": 1968584,
    "DQLTG": 2097453,
    "DQLTG2": 899,
    "DQLTG3": 900,
}

DEFAULT_CANDLE_FIELDS = [
    "low",
    "high",
    "transaction_volume",
    "open",
    "close",
    "transaction_amount",
    "turnover_rate",
    "prev_close",
]

RIGHT_VALUES = {
    "Forward": "Q",
    "Backward": "B",
    "Exclude": "",
}

INDEX_MARKETS = {
    "USHI",
    "USZI",
    "USTI",
    "UZZI",
    "UTII",
}
