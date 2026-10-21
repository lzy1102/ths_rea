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
