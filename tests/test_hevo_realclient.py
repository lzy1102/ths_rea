import base64

# Fixture captured from the shipped Hevo client binaries
# (Normandy.Identity.Client.dll 2.0.7.8 + Hevo.Api.Quotes.dll 10.1.7.7)
# from cn.com.10jqka_kylin_2.9.1.2_amd64.deb. The pre-RSA plaintexts below
# are what the real client actually feeds into RSAEncrypt.

REAL_CLIENT_MODULUS = (
    "cb044d6a8804fae89463525c9f6f837167181fd68a550e5433c749c6c55e2a8c"
    "12f984c4d1215f0756d51f5eb1eaa7fcbd22a9bd75c4d53c3dd80d3a769c7b27"
    "2f8847ec8e71e12ce6c0badcbe44b3ae1356815f32efb5ec07b5eedf09615528"
    "e83f5952495f6523cbadf6d2f295645889db78655b60e0b458bfa5b84474e8f7"
)

REAL_CLIENT_EXPONENT = "10001"

REAL_CLIENT_PRIVATE_PEM = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDLBE1qiAT66JRjUlyfb4NxZxgf1opVDlQzx0nGxV4qjBL5hMTR
IV8HVtUfXrHqp/y9Iqm9dcTVPD3YDTp2nHsnL4hH7I5x4SzmwLrcvkSzrhNWgV8y
77XsB7Xu3wlhVSjoP1lSSV9lI8ut9tLylWRYidt4ZVtg4LRYv6W4RHTo9wIDAQAB
AoGAFqaUPJ6Qb64jYDGARAmdELn/5w14waSnoF9Ly/GZYAXg2BYIH40pnRgDD0zx
bMzxVejYJ1tMar4d6E0RiMpMsw+iT/xO8uTFQppvXaJ/rlo5cIz/CCQvqoJOxb40
2vcO9OYkPVVfxgHg/2YTJh7fjIyysLU4YsUT5/1I3sZHmQECQQDsuQqDN7vC8s7x
27kM5vZShiuNUsLXOHT6cHoCqidj4iJnwKK51wZhU7pSpRYCEjKBIaLSCOp4313U
Fn28vHq5AkEA24yXpd/7cxaLNv7JcHrWx2R1OzSXMfwcPABF6XHzgOTiO4w9gjCV
mVSdr9qHW6pBnTLsRATg7XrlCBkrb2jpLwJBAIQnbYoB1E2qVgPJ4Y4lZoB9rNSx
zlpuh0fFASh5q5HkjcaUUYQkWch+ALfgt9+iHxXeHFLbbWLbeDtN7xYttukCQFLY
eJj1LhM9nIbCGg1BrS5McBhJPgx0j8rsZ3UxtKscs2m4/7TS1ICpd19WXOFwG5ZQ
EuuP07iJOUeXB9bgha0CQBwZDEt0AnCEqTjKQQ/gu4ChMZ5WN6RgtFKXGZeWG1/Y
xe5bMNk31kpGcsiW5ddxzl2ts7hOr/Ij+1MGvyk6QVE=
-----END RSA PRIVATE KEY-----
"""

REAL_CLIENT_CASES = [
    {'kind': 'salt', 'crnd': '123456789012345678', 'dsk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'dsv': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'ssv': 'DQRFRkNERU8VREcXEBBARA==', 'password': 'pw0', 'pre_rsa_hex': '41415652427764525641315256316452426c5a5555414d4456313049553142515777514455465251427730475751594956314e584446454558464541426c7747415167474356494858315546553145444256785642513d3d'},
    {'kind': 'salt', 'crnd': '123456789012345678', 'dsk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'dsv': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'ssv': 'DQRFRkNERU8VREcXEBBARA==', 'password': 'pw1', 'pre_rsa_hex': '42314d48424156564267774841416451566c4a51556c414555516f4458515149423146534277494141313842436759465556734c576c63474156525244676b44586741424251454758415656564130454241384456413d3d'},
    {'kind': 'second', 'dsv': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'password': 'pw2-0', 'pre_rsa_hex': '524555485346513d'},
    {'kind': 'second', 'dsv': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'password': 'pw2-1', 'pre_rsa_hex': '524555485346553d'},
    {'kind': 'encstr', 'value': 'hello', 'pre_rsa_hex': '68656c6c6f'},
    {'kind': 'encstr', 'value': 'abc123', 'pre_rsa_hex': '616263313233'},
    {'kind': 'encstr', 'value': '中文密码', 'pre_rsa_hex': 'd6d0cec4c3dcc2eb'},
]


def _real_client_key():
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(
        REAL_CLIENT_PRIVATE_PEM.encode("ascii"), password=None)


def _real_client_public_key():
    from hevo_client.auth import AuthPublicKeyV1
    key = AuthPublicKeyV1()
    key.modulus = REAL_CLIENT_MODULUS
    key.public_exponent = REAL_CLIENT_EXPONENT
    key.rsa_version = "1"
    return key


def _url_decode(text):
    out = []
    index = 0
    while index < len(text):
        if text[index] == "%" and index + 2 < len(text):
            out.append(chr(int(text[index + 1:index + 3], 16)))
            index += 3
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def _pre_rsa_plaintext(encrypted):
    from cryptography.hazmat.primitives.asymmetric import padding
    raw = base64.b64decode(_url_decode(encrypted))
    return _real_client_key().decrypt(raw, padding.PKCS1v15())


def test_encrypt_string_matches_shipped_client_bytes():
    from hevo_client.salt import encrypt_string
    key = _real_client_public_key()
    for case in REAL_CLIENT_CASES:
        if case["kind"] != "encstr":
            continue
        got = _pre_rsa_plaintext(encrypt_string(case["value"], key))
        assert got.hex() == case["pre_rsa_hex"], case["value"]


def test_second_encrypt_password_width_salt_matches_shipped_client_bytes():
    from hevo_client.salt import second_encrypt_password_width_salt
    key = _real_client_public_key()
    for case in REAL_CLIENT_CASES:
        if case["kind"] != "second":
            continue
        got = _pre_rsa_plaintext(
            second_encrypt_password_width_salt(case["password"], case["dsv"], key))
        assert got.hex() == case["pre_rsa_hex"], case["password"]


def test_encrypt_password_width_salt_matches_shipped_client_bytes():
    from hevo_client.salt import AuthSaltResponse, SaltData, encrypt_password_width_salt
    key = _real_client_public_key()
    for case in REAL_CLIENT_CASES:
        if case["kind"] != "salt":
            continue
        response = AuthSaltResponse(
            code="0",
            result=SaltData(dsk=case["dsk"], dsv=case["dsv"], ssv=case["ssv"]),
        )
        got = _pre_rsa_plaintext(
            encrypt_password_width_salt(case["password"], case["crnd"], response, key))
        assert got.hex() == case["pre_rsa_hex"], case["password"]
