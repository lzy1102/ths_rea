import base64
import struct

import pytest

from hevo_client.auth import AuthPassportV1, make_auth_bytes
from hevo_client.binarypack import DataResponseV2
from hevo_client.crypto import hmac_sha256_hex, md5_hex, sha256_hex
from hevo_client.encoding import dictionary_to_ini_string, encode_url, gbk_encode, handle_xor, make_query_string
from hevo_client.hxfile import HxFile, snappy_decompress


def test_md5_is_uppercase_ascii():
    assert md5_hex("abc") == "900150983CD24FB0D6963F7D28E17F72"


def test_sha256_is_utf8_lowercase():
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hmac_sha256_key_is_secret():
    import hmac
    import hashlib
    expected = hmac.new(b"secret", b"message", hashlib.sha256).hexdigest()
    assert hmac_sha256_hex("message", "secret") == expected


def test_encode_url_space_is_plus_and_nul_has_no_prefix():
    assert encode_url("a b") == "a+b"
    assert encode_url("a\x00b") == "a00b"
    assert encode_url("a+b/c=") == "a%2Bb%2Fc%3D"


def test_handle_xor_is_index_aligned_not_modulo():
    assert handle_xor("AB", "0123") == "qs"
    with pytest.raises(ValueError):
        handle_xor("ABCD", "AB")


def test_auth_pack_drops_trailing_newline_and_uses_gbk_byte_length():
    packet = make_auth_bytes("P64", "U1", "800", "AA-BB")
    assert packet.startswith(b"A\t\x00zh_CN.GBK")
    prefix_len = 1 + 2 + len("zh_CN.GBK")
    ini_len = struct.unpack("<H", packet[prefix_len:prefix_len + 2])[0]
    body = packet[prefix_len + 2:]
    assert len(body) == ini_len
    assert not body.endswith(b"\n")
    assert body.startswith(b"Ask=login\n")


def test_passport64_replaces_pipe_with_crlf():
    passport = AuthPassportV1()
    passport.passport_value_string = "M_hq=abc|M_wg=def|signlength=1"
    passport.signature = "ABCDEFGHIJKLMNOP"
    raw = base64.b64decode(passport.make_passport64_value())
    assert raw[0:5] == struct.pack("<hBh", len(raw), 6, 8)
    assert raw.endswith(b"\x00")
    assert b"M_hq=abc\r\nM_wg=def\r\n" in raw


def test_make_query_string_sorted_order():
    assert make_query_string({"b": "2", "a": "1"}, sorted_keys=True) == "a=1&b=2"


def test_dictionary_to_ini_string_uses_equals_and_newline():
    assert dictionary_to_ini_string({"a": "1", "b": "2"}) == "a=1\nb=2\n"


def _v2_pack(segments, fmt=1, comp=0, biz=207):
    body = b""
    for payload in segments:
        body += struct.pack("<I", len(payload)) + payload
    total = len(body)
    info = struct.pack("<HiIHiB", total, 7, biz, comp | fmt, total, len(segments))
    head = b"\xfd" * 4 + b"%08x" % (len(info) + len(body)) + b"\x09"
    return head + info + body


def test_v2_layout_fields():
    raw = _v2_pack([b"abc", b"defg"], fmt=2, comp=0x100)
    layout = DataResponseV2(pack_bytes=raw).pack_layout
    assert layout.rsp_data_length == 15
    assert layout.instance_id == 7
    assert layout.biz_rsp_type == 207
    assert layout.format_flag == 0x102
    assert layout.data_format == 2
    assert layout.compression_method == 0x100
    assert layout.data_start == 30
    assert layout.data_segment_offsets == [30, 37]


def test_v2_as_string_skips_4_byte_length_prefix():
    payload = "hello".encode("gbk")
    raw = _v2_pack([payload])
    response = DataResponseV2(pack_bytes=raw)
    assert response.as_string() == "hello"


def _snappy_literal(payload):
    def _varint(value):
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    if len(payload) - 1 < 60:
        tag = bytes([(len(payload) - 1) << 2])
    else:
        tag = bytes([60 << 2]) + struct.pack("<H", len(payload) - 1)
    return _varint(len(payload)) + tag + payload


def test_hxfile_head_read_from_source_for_compressed():
    version = b"hx1.2\x00"
    rest = struct.pack("<IIHHI", 1, 22, 8, 2, 0)
    fields = struct.pack("<IBBH", 1, 4, 0, 4) + struct.pack("<IBBH", 10, 2, 0, 4)
    record = struct.pack("<ii", 20240101, 12345)
    payload = rest + fields + record
    literal = _snappy_literal(payload)
    total = 4 + len(version) + len(literal)
    data = struct.pack("<I", total) + version + literal
    hx = HxFile(data, 0, "AsResponse")
    assert hx.version == "V1_2"
    assert hx.head.record_count == 1
    assert hx.head.data_field_count == 2
    rows = hx.as_list()
    assert len(rows) == 1
    assert rows[0][10] == 12345.0


def test_snappy_roundtrip_literal():
    payload = b"abcabcabc" * 4
    compressed = bytes([len(payload)]) + bytes([(len(payload) - 1) << 2]) + payload
    assert snappy_decompress(compressed) == payload


def test_unzip3sharp_returns_none_on_garbage():
    data = b"\xff\xff\xff\xff" + b"\x01\x02\x03"
    assert HxFile.unzip3sharp(data, 0) is None


def test_v2_zlib_payload_starts_at_data_start_plus_4():
    import zlib
    text = "hello world".encode("gbk")
    inner = struct.pack("<I", len(text)) + text
    comp = zlib.compress(inner)
    body = struct.pack("<I", len(inner)) + comp
    total = len(body)
    info = struct.pack("<HiIHiB", total, 7, 207, 0x200 | 1, total, 1)
    head = b"\xfd" * 4 + b"%08x" % (len(info) + len(body)) + b"\x09"
    response = DataResponseV2(pack_bytes=head + info + body)
    assert response.decompressed_bytes == inner
    assert response.as_string() == "hello world"


def test_salt_sign_key_matches_original():
    from hevo_client.constants import AES_IV, ENCRYPTED_KEY, SYMMETRIC_KEY
    from hevo_client.salt import get_salt_sign_key
    assert get_salt_sign_key("Salt") == "TUALD74SBVO6KZQ0"
    assert get_salt_sign_key("SaltTest", app_id="APP") == "APP"
    assert get_salt_sign_key("SaltDebug", encrypted_key="ENC") == "ENC"


def test_imei_fallback_is_plain_string_not_md5():
    import hevo_client.auth as auth_mod
    original = auth_mod.get_mac_address

    def boom():
        raise RuntimeError("no mac")

    try:
        auth_mod.get_mac_address = lambda: "AA-BB-CC-DD-EE-FF"
        assert auth_mod.get_imei_for_auth() == "6576F7FBC367D7A944D474074D276A2D"
        # C# only reaches the fallback when the MD5 call itself throws
        original_md5 = auth_mod.md5_hex
        try:
            def boom_md5(text):
                raise RuntimeError("md5 failed")
            auth_mod.md5_hex = boom_md5
            assert auth_mod.get_imei_for_auth() == "AABBCCDDEEFFAABBCCDDEEFFGGHHIIGG"
        finally:
            auth_mod.md5_hex = original_md5
    finally:
        auth_mod.get_mac_address = original


def test_empty_password_becomes_empty_string():
    from hevo_client.auth import convert_input_password_to_md5
    assert convert_input_password_to_md5("") == ""


def test_passport_request_includes_newwgflag():
    import inspect
    from hevo_client.auth import get_auth_passport
    assert '"newwgflag": "3"' in inspect.getsource(get_auth_passport)


def test_client_uses_single_persistent_socket():
    import socket as socket_mod
    import hevo_client.client as client_mod
    from hevo_client.client import HevoClient
    sent = []

    class FakeSock:
        def __init__(self):
            self.buf = b""

        def sendall(self, data):
            sent.append(data)

        def close(self):
            pass

    created = []

    def fake_connect(addr, timeout=None):
        created.append(addr)
        return FakeSock()

    v2_body = struct.pack("<HiIHiB", 0, 7, 207, 1, 0, 0)

    def fake_recv(sock, size):
        if size == 13:
            return bytes([0xfd]) * 4 + b"%08x" % len(v2_body) + bytes([9])
        return v2_body

    original_connect = socket_mod.create_connection
    original_recv = client_mod._recv_exact
    try:
        socket_mod.create_connection = fake_connect
        client_mod._recv_exact = fake_recv
        client = HevoClient(host="h", port=1)
        client.auth_bytes = b"AUTH"
        client._auth_sent = False
        client.query_intraday("600000")
        client.query_intraday("600001")
    finally:
        socket_mod.create_connection = original_connect
        client_mod._recv_exact = original_recv
    assert len(created) == 1
    assert sent[0] == b"AUTH"
    assert len(sent) == 3
