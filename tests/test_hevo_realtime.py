import math
import struct

import pytest

from hevo_client import HevoClient
from hevo_client.binarypack import (BinaryPack, DataResponseV2, calculate_realtime_field, distribute_realtime_fields, merge_realtime_responses, normalize_realtime_fields, parse_selfstock_securities, realtime_rows_from_response, request_realtime_v2, string_to_parameter_dictionary)
from hevo_client.constants import REALTIME_FIELD_IDS
from hevo_client.errors import AuthError, ProtocolError


def _pack_value(data_type, value_length, value):
    if data_type == 1:
        raw = value.encode("gbk") if isinstance(value, str) else bytes(value)
        return raw[:value_length].ljust(value_length, b"\x00")
    if data_type == 2:
        return int(value).to_bytes(4, "little")
    if data_type == 3:
        return struct.pack("<d", float(value))
    if data_type == 4:
        return int(value).to_bytes(4, "little", signed=True)
    raise AssertionError("unsupported test field type: %r" % (data_type,))


def make_hx_bytes(field_specs, records):
    field_count = len(field_specs)
    record_length = sum(spec[2] for spec in field_specs)
    total_length = 4 + 22 + 8 * field_count + record_length * len(records)
    head = struct.pack("<6sIIHHI", b"hx1.0\x00", len(records), 22, record_length, field_count, 0)
    fields = b"".join(struct.pack("<IBBH", field_id, data_type, 0, value_length) for field_id, data_type, value_length in field_specs)
    payload = b"".join(_pack_value(data_type, value_length, value) for record in records for (field_id, data_type, value_length), value in zip(field_specs, record))
    return struct.pack("<I", total_length) + head + fields + payload


def make_pack(hx_payload, request_id=200):
    response_info = struct.pack("<HiIHiB", len(hx_payload), 1, request_id, 1, len(hx_payload), 1)
    return BinaryPack.from_body(response_info + hx_payload)


def _raw(pack):
    return pack.raw if isinstance(pack, BinaryPack) else pack


BASE_SPECS = [(5, 1, 10), (55, 1, 4), (10, 2, 4), (48, 2, 4), (19, 2, 4), (6, 2, 4)]
BASE_RECORDS = [
    ("USHA600000", "BANK", 223, 12, 123456, 220),
    ("USHA601398", "ICBC", 6, 3, 654321, 7),
]
DDE_SPECS = [(5, 1, 10), (592888, 2, 4), (592890, 2, 4)]
DDE_RECORDS = [
    ("USHA600000", 111, 2222),
    ("USHA601398", 33, 444),
]
BASE_PACK = make_pack(make_hx_bytes(BASE_SPECS, BASE_RECORDS), 200)
DDE_PACK = make_pack(make_hx_bytes(DDE_SPECS, DDE_RECORDS), 202)
EMPTY_PACK = make_pack(make_hx_bytes([(1, 4, 4)], []), 200)


class RecordingTransport:
    def __init__(self, responses=None, default=None):
        self.responses = {}
        for request_id, packs in (responses or {}).items():
            self.responses[request_id] = list(packs)
        self.default = default
        self.calls = []
        self.auth_calls = 0

    def __call__(self, data):
        if data == b"AUTH":
            self.auth_calls += 1
            return b""
        params = string_to_parameter_dictionary(BinaryPack.from_bytes(data).body.decode("gbk"))
        self.calls.append(params)
        request_id = int(params["id"])
        queued = self.responses.get(request_id)
        if queued:
            return _raw(queued.pop(0))
        return _raw(self.default if self.default is not None else EMPTY_PACK)


def test_normalize_realtime_fields():
    assert normalize_realtime_fields(None) == [5, 55, 199112, 10, 48, 264648, 592890, 592888, 19]
    assert normalize_realtime_fields("latest") == [10]
    assert normalize_realtime_fields("LATEST") == [10]
    assert normalize_realtime_fields("现价") == [10]
    assert normalize_realtime_fields("代码") == [5]
    assert normalize_realtime_fields([10, "latest", 10]) == [10]
    with pytest.raises(ProtocolError):
        normalize_realtime_fields(["nope"])


def test_distribute_realtime_fields():
    assert distribute_realtime_fields(["rise_percentage"]) == [(200, [6, 10])]
    assert distribute_realtime_fields(["rise_amount", "latest", "prev_close"]) == [(200, [6, 10])]
    assert distribute_realtime_fields(["DDE", "DDE_MONEY"]) == [(202, [592888, 592890])]
    assert distribute_realtime_fields(["DQLTG2"]) == [(201, [899])]
    assert distribute_realtime_fields(["full_code", "security_name", "latest", "DDE"]) == [
        (200, [5, 10, 55]),
        (202, [592888]),
    ]
    assert distribute_realtime_fields([]) == []


def test_request_realtime_v2():
    assert request_realtime_v2(200, "USHA", ["600000", "601398"], ["full_code", "prev_close"]) == "id=200&market=USHA&codelist=600000,601398&datatype=5,6"
    assert request_realtime_v2(202, "USHA", "600000", ["DDE", "DDE_MONEY"]) == "id=202&market=USHA&codelist=600000&datatype=592888,592890"


def test_realtime_rows_and_calculators():
    base_rows = realtime_rows_from_response(DataResponseV2(full_pack=BASE_PACK))
    dde_rows = realtime_rows_from_response(DataResponseV2(full_pack=DDE_PACK))
    assert len(base_rows) == 2
    assert base_rows[0][5] == "USHA600000"
    assert base_rows[0][10] == 223.0
    assert dde_rows[0][592890] == 2222.0
    merged = merge_realtime_responses([BASE_PACK, DDE_PACK])
    assert [row[5] for row in merged] == ["USHA600000", "USHA601398"]
    assert merged[0][592888] == 111.0
    assert merged[0][55] == "BANK"
    assert calculate_realtime_field(REALTIME_FIELD_IDS["rise_percentage"], merged[0]) == pytest.approx(3 / 220 * 100)
    assert calculate_realtime_field(REALTIME_FIELD_IDS["rise_amount"], merged[0]) == pytest.approx(3.0)
    assert math.isnan(calculate_realtime_field(REALTIME_FIELD_IDS["rise_amount"], {10: 0.0, 6: 220.0}))
    assert calculate_realtime_field(REALTIME_FIELD_IDS["rise_percentage"], {10: 0.0, 6: 0.0}) == 0.0


def test_query_quotes_merges_realtime_buckets():
    transport = RecordingTransport({200: [BASE_PACK], 202: [DDE_PACK]})
    client = HevoClient(transport=transport)
    client.auth = {}
    rows = client.query_watchlist(["600000", "601398"], market="USHA")
    assert transport.auth_calls == 0
    assert [call["id"] for call in transport.calls] == ["200", "202"]
    assert transport.calls[0]["codelist"] == "600000,601398"
    assert transport.calls[0]["datatype"] == "5,6,10,19,48,55"
    assert transport.calls[1]["datatype"] == "592888,592890"
    assert [row[5] for row in rows] == ["USHA600000", "USHA601398"]
    assert rows[0][55] == "BANK"
    assert rows[0][10] == 223.0
    assert rows[0][592890] == 2222.0
    assert rows[0][199112] == pytest.approx(3 / 220 * 100)
    assert rows[0][264648] == pytest.approx(3.0)
    assert rows[1][199112] == pytest.approx((6 - 7) / 7 * 100)
    assert rows[1][264648] == pytest.approx(-1.0)


def test_query_quotes_multi_market_and_order():
    ushi_base = make_pack(make_hx_bytes(BASE_SPECS, [("USHI1A0001", "INDEX", 3000, 5, 100, 2985)]), 200)
    ushi_dde = make_pack(make_hx_bytes(DDE_SPECS, [("USHI1A0001", 10, 20)]), 202)
    transport = RecordingTransport({200: [BASE_PACK, ushi_base], 202: [DDE_PACK, ushi_dde]})
    client = HevoClient(transport=transport)
    client.auth = {}
    rows = client.query_quotes([("USHA", "600000"), ("USHI", "1A0001"), ("USHA", "601398")])
    assert [call["market"] for call in transport.calls] == ["USHA", "USHA", "USHI", "USHI"]
    assert [row[5] for row in rows] == ["USHA600000", "USHI1A0001", "USHA601398"]
    assert rows[1][10] == 3000.0
    assert rows[1][199112] == pytest.approx((3000 - 2985) / 2985 * 100)


def test_query_quotes_requires_login():
    client = HevoClient(transport=RecordingTransport())
    with pytest.raises(AuthError):
        client.query_watchlist(["600000"])


def test_parse_selfstock_securities():
    assert parse_selfstock_securities("600000|000001,17|33") == [("USHA", "600000"), ("USZA", "000001")]
    assert parse_selfstock_securities("600000") == [("USHA", "600000")]
    assert parse_selfstock_securities("") == []
    assert parse_selfstock_securities("1A0001,16") == [("USHI", "1A0001")]
