import base64
import struct

from hevo_client import HevoClient
from hevo_client.binarypack import BinaryPack, DataResponseV2, parameter_dictionary_to_binary_pack, string_to_parameter_dictionary
from hevo_client.encoding import (encode_signature, hexin_base64_encode, make_query_string, self_stock_base64_decode, self_stock_base64_encode)
from hevo_client.hxfile import HxFile, snappy_decompress


def make_hx_bytes():
    field_count = 2
    record_count = 1
    single_record_length = 8
    size_with_padding = 22
    total_length = 4 + size_with_padding + 8 * field_count + record_count * single_record_length
    head = struct.pack("<6sIIHHI", b"hx1.0\x00", record_count, size_with_padding, single_record_length, field_count, 0)
    fields = struct.pack("<IBBH", 1, 4, 0, 4) + struct.pack("<IBBH", 10, 2, 0, 4)
    record = struct.pack("<ii", 20240101, 12345)
    return struct.pack("<I", total_length) + head + fields + record


def test_hxfile_parse():
    hx = HxFile(make_hx_bytes(), 0, "AsResponse")
    assert not hx.is_bad
    rows = hx.as_list()
    assert len(rows) == 1
    assert rows[0][1] == 1704067200
    assert isinstance(rows[0][10], float)


def test_encoding_base64_roundtrip():
    data = b"abc"
    encoded = self_stock_base64_encode(data)
    decoded = self_stock_base64_decode(encoded)
    assert decoded[:len(data)] == data
    assert hexin_base64_encode(data) == base64.b64encode(data).decode("ascii").replace("+", "+").replace("/", "/")


def test_make_query_string():
    assert make_query_string({"a": "1", "b": "2"}, sorted_keys=True) == "a=1&b=2"


def test_encode_signature():
    source = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert encode_signature(source) == bytes.fromhex("1032547698badcfe20426486a8")


def test_binarypack_v2_as_list():
    hx = make_hx_bytes()[4:]
    response_info = struct.pack("<HiIHiB", len(hx) + 4, 1, 207, 1, len(hx) + 4, 1)
    segment = struct.pack("<I", len(hx)) + hx
    raw = BinaryPack.TEMPLATE[:13] + response_info + segment
    raw = raw[:4] + ("%08x" % len(raw[13:])).encode("ascii") + raw[12:]
    response = DataResponseV2(pack_bytes=raw)
    assert not response.is_bad
    rows = response.as_list_dictionary()
    assert len(rows) == 1
    assert rows[0][1] == 1704067200


def test_client_query():
    hx = make_hx_bytes()[4:]
    response_info = struct.pack("<HiIHiB", len(hx) + 4, 1, 207, 1, len(hx) + 4, 1)
    segment = struct.pack("<I", len(hx)) + hx
    payload = response_info + segment
    body_length = len(payload)
    head = BinaryPack.TEMPLATE[:4] + ("%08x" % body_length).encode("ascii") + BinaryPack.TEMPLATE[12:13]
    raw_response = head + payload

    def transport(data):
        return raw_response

    client = HevoClient(transport=transport)
    client.auth = {"auth_bytes": b""}
    client.auth_bytes = b""
    rows = client.query_intraday("600000")
    assert len(rows) == 1
    assert rows[0][1] == 1704067200


def test_snappy_roundtrip_not_required():
    assert snappy_decompress is not None


def test_salt_sign_key_from_encrypted_key():
    from hevo_client.salt import get_salt_sign_key
    key = get_salt_sign_key("Salt")
    assert key == "TUALD74SBVO6KZQ0"
    assert get_salt_sign_key("SaltTest", app_id="APP") == "APP"
    assert get_salt_sign_key("SaltDebug", encrypted_key="ENC") == "ENC"


def test_salt_sign_headers_shape():
    from hevo_client.salt import get_salt_sign_headers
    headers = get_salt_sign_headers("account=x&encoding=gbk", "KEY", app_id="APP", crnd="CRND")
    assert headers["X-Auth-AppId"] == "APP"
    assert headers["X-Auth-SignV"] == "3"
    assert headers["X-Auth-Crnd"] == "CRND"
    assert headers["X-Auth-Ext"] == "CRND"
    assert headers["X-Auth-Sign"] == headers["X-Auth-Sign"].upper()
    assert len(headers["X-Auth-Sign"]) == 64
    assert headers["X-Auth-Time"].isdigit()


def _rsa_keypair(bits=1024):
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _public_key_from(private):
    numbers = private.public_key().public_numbers()
    modulus = format(numbers.n, "x")
    if len(modulus) % 2:
        modulus = "0" + modulus
    exponent = format(numbers.e, "x")
    if len(exponent) % 2:
        exponent = "0" + exponent
    from hevo_client.auth import AuthPublicKeyV1
    key = AuthPublicKeyV1()
    key.modulus = modulus
    key.public_exponent = exponent
    return key


def _url_decode(text):
    out = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "%" and index + 2 < len(text):
            out.append(chr(int(text[index + 1:index + 3], 16)))
            index += 3
            continue
        if char == "+":
            out.append("+")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _decode_salt_payload(text, private):
    import base64 as _b64
    from cryptography.hazmat.primitives.asymmetric import padding
    raw = _b64.b64decode(_url_decode(text))
    plain = private.decrypt(raw, padding.PKCS1v15())
    return plain.decode("gbk")


def test_salt_password_chain_decrypts_to_expected():
    from hevo_client.crypto import hmac_sha256_hex, sha256_hex
    from hevo_client.encoding import handle_xor
    from hevo_client.salt import AuthSaltResponse, SaltData, encrypt_password_width_salt
    import base64 as _b64
    private = _rsa_keypair()
    public_key = _public_key_from(private)
    crnd = "123456789012345678"
    dsk = "A" * 32
    dsv = "B" * 32
    xor_key = sha256_hex(crnd + dsk)
    plain = "x=secretvalue"
    ssv = _b64.b64encode(handle_xor(plain, xor_key).encode("ascii")).decode("ascii")
    rsp = AuthSaltResponse(code="0", result=SaltData(dsk=dsk, dsv=dsv, ssv=ssv))
    payload = encrypt_password_width_salt("pwd", crnd, rsp, public_key)
    text = _decode_salt_payload(payload, private)
    expected_secret = plain.split("=")[1]
    expected = _b64.b64encode(handle_xor(hmac_sha256_hex("pwd", expected_secret), sha256_hex(dsv)).encode("ascii")).decode("ascii")
    assert text == expected
    other = encrypt_password_width_salt("pwd2", crnd, rsp, public_key)
    assert _decode_salt_payload(other, private) != expected


def test_salt_login_flow_offline():
    from hevo_client.crypto import sha256_hex
    from hevo_client.encoding import handle_xor
    from hevo_client.salt import login_salt
    import base64 as _b64
    mod = "00" + "C1" * 128
    pub = ("<root><ret code=\"0\" msg=\"ok\"/>"
           "<item rsa_version=\"1\" pubkey=\"\" modulus=\"%s\" publicExponent=\"010001\"/></root>") % mod
    dsk = "A" * 32
    dsv = "B" * 32
    ok_xml = "<root><ret code=\"0\" msg=\"ok\"/><item userid=\"U1\" sessionid=\"S1\" rsa_version=\"1\"/></root>"
    seen = []

    def http_get(url):
        return pub.encode("gbk")

    def http_post(url, data, headers):
        assert "X-Auth-Sign" in headers
        assert headers["X-Auth-SignV"] == "3"
        seen.append(url)
        if url.endswith("/verify3/gs"):
            crnd = headers["X-Auth-Crnd"]
            ssv = _b64.b64encode(handle_xor("x=secretvalue", sha256_hex(crnd + dsk)).encode("ascii")).decode("ascii")
            body = ("{\"code\":\"0\",\"msg\":\"ok\",\"result\":{\"dsk\":\"%s\",\"dsv\":\"%s\",\"ssv\":\"%s\"}}") % (
                dsk, dsv, ssv)
            return body.encode("gbk")
        if url.endswith("/verify3/pwd_login"):
            return ok_xml.encode("gbk")
        raise AssertionError(url)

    session = login_salt("user", "pass", http_get, http_post)
    assert session.user_id == "U1"
    assert session.session_id == "S1"
    assert session.is_bad is False
    assert seen == ["http://auth.10jqka.com.cn/verify3/gs",
                    "http://auth.10jqka.com.cn/verify3/pwd_login"]


def test_salt_second_login_on_minus_10002():
    from hevo_client.crypto import sha256_hex
    from hevo_client.encoding import handle_xor
    from hevo_client.salt import login_salt
    import base64 as _b64
    mod = "00" + "C1" * 128
    pub = ("<root><ret code=\"0\" msg=\"ok\"/>"
           "<item rsa_version=\"1\" pubkey=\"\" modulus=\"%s\" publicExponent=\"010001\"/></root>") % mod
    dsk = "A" * 32
    dsv = "B" * 32
    retry_xml = ("<root><ret code=\"-10002\" msg=\"retry\"/>"
                 "<item dsk=\"%s\" dsv=\"%s\"/></root>") % ("C" * 32, "D" * 32)
    ok_xml = "<root><ret code=\"0\" msg=\"ok\"/><item userid=\"U2\" sessionid=\"S2\" rsa_version=\"1\"/></root>"
    seen = []

    def http_get(url):
        return pub.encode("gbk")

    def http_post(url, data, headers):
        seen.append(url)
        if url.endswith("/verify3/gs"):
            crnd = headers["X-Auth-Crnd"]
            ssv = _b64.b64encode(handle_xor("x=secretvalue", sha256_hex(crnd + dsk)).encode("ascii")).decode("ascii")
            body = ("{\"code\":\"0\",\"msg\":\"ok\",\"result\":{\"dsk\":\"%s\",\"dsv\":\"%s\",\"ssv\":\"%s\"}}") % (
                dsk, dsv, ssv)
            return body.encode("gbk")
        if url.endswith("/verify3/pwd_login"):
            return retry_xml.encode("gbk")
        if url.endswith("/verify3/pwd_login_again"):
            return ok_xml.encode("gbk")
        raise AssertionError(url)

    session = login_salt("user", "pass", http_get, http_post)
    assert session.user_id == "U2"
    assert len(seen) == 3
    assert seen[-1].endswith("/verify3/pwd_login_again")
