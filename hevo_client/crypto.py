import base64
import hashlib
import hmac
import random
import struct

from Crypto.Cipher import AES

from .constants import AES_IV, SYMMETRIC_KEY
from .encoding import gbk_decode, gbk_encode


def md5_hex(text):
    if isinstance(text, str):
        text = gbk_encode(text)
    return hashlib.md5(text).hexdigest()


def sha256_hex(text):
    if isinstance(text, str):
        text = gbk_encode(text)
    return hashlib.sha256(text).hexdigest()


def hmac_sha256_hex(message, secret):
    if isinstance(message, str):
        message = gbk_encode(message)
    if isinstance(secret, str):
        secret = gbk_encode(secret)
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def rsa_encrypt_b64(message, modulus, exponent, block_size=128):
    if isinstance(message, str):
        message = gbk_encode(message)
    if isinstance(modulus, str):
        modulus = int(modulus, 16)
    if isinstance(exponent, str):
        exponent = int(exponent, 16)
    encrypted = rsa_encrypt_pkcs1_v15(message, modulus, exponent, block_size)
    return base64.b64encode(encrypted).decode("ascii")


def rsa_encrypt_pkcs1_v15(message, modulus, exponent, block_size=128):
    if isinstance(message, str):
        message = gbk_encode(message)
    if isinstance(modulus, str):
        modulus = int(modulus, 16)
    elif not isinstance(modulus, int):
        modulus = int.from_bytes(modulus, "big")
    if isinstance(exponent, str):
        exponent = int(exponent, 16)
    elif not isinstance(exponent, int):
        exponent = int.from_bytes(exponent, "big")
    key_size = (modulus.bit_length() + 7) // 8
    if len(message) > key_size - 11:
        raise ValueError("message too long")
    padding_length = key_size - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_length:
        byte = random.randrange(1, 256)
        if byte != 0:
            padding.append(byte)
    block = bytes([0, 2]) + bytes(padding) + bytes([0]) + message
    value = int.from_bytes(block, "big")
    encrypted = pow(value, exponent, modulus)
    return encrypted.to_bytes(key_size, "big")


def rsa_encrypt(data, params, oaep=False):
    if isinstance(data, str):
        data = gbk_encode(data)
    modulus, exponent = parse_rsa_params(params)
    if oaep:
        raise NotImplementedError("OAEP is not implemented")
    return rsa_encrypt_pkcs1_v15(data, modulus, exponent)


def parse_rsa_params(params):
    if hasattr(params, "n") and hasattr(params, "e"):
        modulus = params.n
        exponent = params.e
        if not isinstance(modulus, int):
            modulus = int(modulus, 16) if isinstance(modulus, str) else int.from_bytes(modulus, "big")
        if not isinstance(exponent, int):
            exponent = int(exponent, 16) if isinstance(exponent, str) else int.from_bytes(exponent, "big")
        return modulus, exponent
    if hasattr(params, "Modulus") and hasattr(params, "Exponent"):
        modulus = params.Modulus
        exponent = params.Exponent
        if isinstance(modulus, str):
            modulus = bytes.fromhex(modulus)
        if isinstance(exponent, str):
            exponent = bytes.fromhex(exponent)
        if not isinstance(modulus, int):
            modulus = int.from_bytes(modulus, "big") if isinstance(modulus, (bytes, bytearray)) else int(modulus, 16)
        if not isinstance(exponent, int):
            exponent = int.from_bytes(exponent, "big") if isinstance(exponent, (bytes, bytearray)) else int(exponent, 16)
        return modulus, exponent
    if hasattr(params, "Modulus") and hasattr(params, "Exponent"):
        modulus = params.Modulus
        exponent = params.Exponent
        if isinstance(modulus, str):
            modulus = bytes.fromhex(modulus)
        if isinstance(exponent, str):
            exponent = bytes.fromhex(exponent)
        if not isinstance(modulus, int):
            modulus = int.from_bytes(modulus, "big") if isinstance(modulus, (bytes, bytearray)) else int(modulus, 16)
        if not isinstance(exponent, int):
            exponent = int.from_bytes(exponent, "big") if isinstance(exponent, (bytes, bytearray)) else int(exponent, 16)
        return modulus, exponent
    if hasattr(params, "modulus") and hasattr(params, "public_exponent"):
        modulus = params.modulus
        exponent = params.public_exponent
        if not isinstance(modulus, int):
            modulus = int(modulus, 16) if isinstance(modulus, str) else int.from_bytes(modulus, "big")
        if not isinstance(exponent, int):
            exponent = int(exponent, 16) if isinstance(exponent, str) else int.from_bytes(exponent, "big")
        return modulus, exponent
    if isinstance(params, dict):
        if "modulus" in params:
            modulus_hex = params["modulus"]
            exponent_hex = params["publicExponent"] if "publicExponent" in params else params["exponent"]
            if not isinstance(modulus_hex, int):
                modulus = int(modulus_hex, 16) if isinstance(modulus_hex, str) else int.from_bytes(modulus_hex, "big")
            else:
                modulus = modulus_hex
            if not isinstance(exponent_hex, int):
                exponent = int(exponent_hex, 16) if isinstance(exponent_hex, str) else int.from_bytes(exponent_hex, "big")
            else:
                exponent = exponent_hex
            return modulus, exponent
        if "n" in params:
            n = params["n"]
            e = params["e"]
            if not isinstance(n, int):
                n = int(n, 16) if isinstance(n, str) else int.from_bytes(n, "big")
            if not isinstance(e, int):
                e = int(e, 16) if isinstance(e, str) else int.from_bytes(e, "big")
            return n, e
        if "modulus_bytes" in params:
            return int.from_bytes(params["modulus_bytes"], "big"), int.from_bytes(params["exponent_bytes"], "big")
    if isinstance(params, str):
        text = params.strip()
        if text.startswith("<"):
            import re
            modulus_hex = re.search(r"<Modulus>(.*?)</Modulus>", text, re.S).group(1)
            exponent_hex = re.search(r"<Exponent>(.*?)</Exponent>|<PublicExponent>(.*?)</PublicExponent>", text, re.S)
            exponent_hex = exponent_hex.group(1) or exponent_hex.group(2)
            return int(modulus_hex, 16), int(exponent_hex, 16)
        if "BEGIN" in text:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_pem_public_key(text.encode("ascii"))
            numbers = key.public_numbers()
            return numbers.n, numbers.e
    if isinstance(params, (bytes, bytearray)):
        try:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_der_public_key(bytes(params))
            numbers = key.public_numbers()
            return numbers.n, numbers.e
        except Exception:
            pass
    raise ValueError("unsupported RSA parameters")


def aes_encrypt_cbc(plaintext, key, iv=AES_IV):
    if isinstance(plaintext, str):
        plaintext = gbk_encode(plaintext)
    if isinstance(key, str):
        key = gbk_encode(key)
    if isinstance(iv, str):
        iv = gbk_encode(iv)
    key = key.ljust(32, b"0")[:32]
    iv = iv.encode(GBK) if isinstance(iv, str) else iv
    iv = iv.ljust(16, b"0")[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad] * pad)
    return base64.b64encode(cipher.encrypt(padded)).decode("ascii")


def aes_decrypt_cbc(ciphertext, key, iv=AES_IV):
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    if isinstance(key, str):
        key = gbk_encode(key)
    if isinstance(iv, str):
        iv = gbk_encode(iv)
    key = key.ljust(32, b"0")[:32]
    iv = iv.ljust(16, b"0")[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    pad = padded[-1]
    return gbk_decode(padded[:-pad])


def decrypt_symmetric_key():
    import base64 as _base64
    from .constants import ENCRYPTED_KEY
    encrypted = _base64.b64decode(ENCRYPTED_KEY)
    key = gbk_encode(SYMMETRIC_KEY).ljust(32, b"0")[:32]
    iv = gbk_encode(AES_IV).ljust(16, b"0")[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    pad = decrypted[-1]
    return gbk_decode(base64.b64decode(decrypted[:-pad]))


Md5Hex = md5_hex
Sha256Hex = sha256_hex
HmacSha256Hex = hmac_sha256_hex
RsaEncryptB64 = rsa_encrypt_b64
RsaEncryptPkcs1V15 = rsa_encrypt_pkcs1_v15
RsaEncrypt = rsa_encrypt
ParseRsaParams = parse_rsa_params
AesEncryptCbc = aes_encrypt_cbc
AesDecryptCbc = aes_decrypt_cbc
DecryptSymmetricKey = decrypt_symmetric_key
