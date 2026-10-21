import base64
import hashlib
import random
import struct

from .constants import CUSTOM_BASE64_ALPHABET, STANDARD_BASE64_ALPHABET

GBK = "gbk"


def gbk_encode(text):
    return text.encode(GBK)


def gbk_decode(data):
    return data.decode(GBK)


def encode_url(src):
    result = ""
    for char in src:
        if ("a" <= char <= "z") or ("A" <= char <= "Z") or ("0" <= char <= "9") or char in "-_":
            result += char
            continue
        if char == " ":
            result += "+"
            continue
        if char == "\x00":
            continue
        value = ord(char) & 0xFF
        hi = value // 16
        lo = value % 16
        result += "%" + _hex_digit(hi) + _hex_digit(lo)
    return result


def _hex_digit(value):
    if value < 10:
        return chr(ord("0") + value)
    return chr(ord("A") + value - 10)


def hexin_base64_encode(data):
    alphabet = gbk_encode(STANDARD_BASE64_ALPHABET)
    return _base64_encode(data, alphabet)


def self_stock_base64_encode(data):
    alphabet = gbk_encode(CUSTOM_BASE64_ALPHABET)
    return _base64_encode(data, alphabet)


def _base64_encode(data, alphabet):
    length = len(data)
    out = bytearray((length + 2) // 3 * 4)
    pos = 0
    offset = 0
    remaining = length
    while remaining > 2:
        out[pos] = alphabet[data[offset] >> 2]
        out[pos + 1] = alphabet[((data[offset] & 3) << 4) + (data[offset + 1] >> 4)]
        out[pos + 2] = alphabet[((data[offset + 1] & 0x0F) << 2) + (data[offset + 2] >> 6)]
        out[pos + 3] = alphabet[data[offset + 2] & 0x3F]
        pos += 4
        offset += 3
        remaining -= 3
    if remaining != 0:
        out[pos] = alphabet[data[offset] >> 2]
        if remaining > 1:
            out[pos + 1] = alphabet[((data[offset] & 3) << 4) + (data[offset + 1] >> 4)]
            out[pos + 2] = alphabet[(data[offset + 1] & 0x0F) << 2]
            out[pos + 3] = 61
        else:
            out[pos + 1] = alphabet[(data[offset] & 3) << 4]
            out[pos + 2] = 61
            out[pos + 3] = 61
    return gbk_decode(bytes(out))


def self_stock_base64_decode(text):
    data = gbk_encode(text)
    table = [-1] * 256
    alphabet = gbk_encode(CUSTOM_BASE64_ALPHABET)
    for index, value in enumerate(alphabet):
        if value < 256:
            table[value] = index
    out = bytearray(len(data) + 1)
    pos = 0
    offset = 0
    total = len(data)
    while offset < total and data[offset] != 0:
        value = 0
        bits = 0
        count = 0
        while count < 4 and offset < total:
            current = table[data[offset]]
            offset += 1
            if current == -1:
                continue
            value = (value << 6) | current
            bits += 6
            count += 1
        if count == 0:
            break
        value <<= 24 - bits
        for _ in range(bits // 8):
            if pos < len(out):
                out[pos] = (value >> 16) & 0xFF
                pos += 1
            value <<= 8
    return bytes(out[:pos])


def parse_key_value_string(text, ignore_no_value=True, separators=None):
    if separators is None:
        separators = ["&"]
    if isinstance(separators, str):
        separators = [separators]
    import re
    pattern = "|".join(re.escape(item) for item in separators)
    result = {}
    for part in re.split(pattern, text):
        if not part:
            continue
        index = part.find("=")
        if index > 0:
            result[part[:index]] = part[index + 1:]
        elif not ignore_no_value:
            result[part] = ""
    return result


def make_query_string(mapping, sorted_keys=False):
    items = list(mapping.items())
    if sorted_keys:
        items.sort(key=lambda item: item[0])
    result = ""
    for key, value in items:
        result += str(key) + "=" + str(value) + "&"
    if result and result[-1] == "&":
        result = result[:-1]
    return result


def dictionary_to_ini_string(dictionary, separator="\n"):
    result = ""
    for key, value in dictionary.items():
        result += str(key) + "=" + str(value) + separator
    return result


def encode_signature(source):
    if isinstance(source, str):
        source = gbk_encode(source)
    output = bytearray(len(source) // 2)
    for index in range(len(output)):
        left_index = 2 * index
        if left_index >= len(source) - 1:
            break
        first = source[left_index + 1] - 65
        second = source[left_index] - 65
        output[index] = ((first * 16) + second) & 0xFF
    return bytes(output)


def combine_bytes(*chunks):
    total = sum(len(chunk) for chunk in chunks)
    result = bytearray(total)
    offset = 0
    for chunk in chunks:
        result[offset:offset + len(chunk)] = chunk
        offset += len(chunk)
    return bytes(result)


def handle_xor(message, key):
    if message == "" or key == "":
        return ""
    result = []
    for index, char in enumerate(message):
        result.append(chr(ord(char) ^ ord(key[index % len(key)])))
    return "".join(result)


def get_cord():
    return "".join(str(random.randrange(i * 10, (i + 1) * 10)) for i in range(18))

EncodeUrl = encode_url
HexinBase64Encode = hexin_base64_encode
SelfStockBase64Encode = self_stock_base64_encode
SelfStockBase64Decode = self_stock_base64_decode
ParseKeyValueString = parse_key_value_string
MakeQueryString = make_query_string
DictionaryToIniString = dictionary_to_ini_string
EncodeSignature = encode_signature
CombineBytes = combine_bytes
HandleXOR = handle_xor
GetCord = get_cord
GbkEncode = gbk_encode
GbkDecode = gbk_decode
