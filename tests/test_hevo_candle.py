import struct
from datetime import date, datetime

import pytest

from hevo_client import HevoClient
from hevo_client.binarypack import (BinaryPack, DataResponseV2, candle_rows_from_response, distribute_candle_fields, format_candle_time, get_real_period_id, is_minute_period, is_second_period, normalize_candle_fields, request_candle_v2, resolve_period_id, right_to_protocol, string_to_parameter_dictionary)
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


def make_pack(hx_payload, request_id=210):
    response_info = struct.pack("<HiIHiB", len(hx_payload), 1, request_id, 1, len(hx_payload), 1)
    return BinaryPack.from_body(response_info + hx_payload)


def _raw(pack):
    return pack.raw if isinstance(pack, BinaryPack) else pack


EMPTY_PACK = make_pack(make_hx_bytes([(1, 4, 4)], []))


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


def test_period_resolution_and_predicates():
    assert resolve_period_id("day") == 5
    assert resolve_period_id("1M") == 12
    assert resolve_period_id("1m") == 15
    assert resolve_period_id(" 5m ") == 16
    assert resolve_period_id("20") == 20
    assert resolve_period_id(21) == 21
    assert resolve_period_id("DAILY") == 5
    with pytest.raises(ProtocolError):
        resolve_period_id("1min")
    with pytest.raises(ProtocolError):
        resolve_period_id(True)


def test_real_period_and_classification():
    assert get_real_period_id(5) == 16384
    assert get_real_period_id(15) == 12288
    assert get_real_period_id(50) == 16384
    assert get_real_period_id(-1) == 0
    assert get_real_period_id(12288) == 12288
    assert is_minute_period(15)
    assert not is_minute_period(5)
    assert is_second_period(21)
    assert not is_second_period(15)


def test_normalize_candle_fields():
    assert normalize_candle_fields(None) == [9, 8, 13, 7, 11, 19, 1968584, 6]
    assert normalize_candle_fields("open") == [7]
    assert normalize_candle_fields("OPEN") == [7]
    assert normalize_candle_fields("7") == [7]
    assert normalize_candle_fields([7, "open", 7]) == [7]
    with pytest.raises(ProtocolError):
        normalize_candle_fields(["nope"])


def test_distribute_candle_fields():
    assert distribute_candle_fields(["date_time"]) == [(210, [1])]
    assert distribute_candle_fields([]) == []
    assert distribute_candle_fields(["DQLTG2"]) == [(211, [1, 899])]
    assert distribute_candle_fields(["turnover_rate"]) == [(212, [1, 1968584])]
    assert distribute_candle_fields(["open", "transaction_amount", "DQLTG", "prev_close"]) == [
        (210, [1, 7, 19]),
        (211, [1, 2097453]),
        (213, [1, 6]),
    ]


def test_request_candle_v2_and_rights():
    assert request_candle_v2(210, "USHA", "600000", -100, 0, ["open", "high"], right="Forward", is_volume_exclude=True, period=5) == "id=210&market=USHA&code=600000&start=-100&end=0&datatype=7,8&period=16384&fuquan=Q&fuquanopt=V"
    assert request_candle_v2(213, "USHA", "600000", 20240101, 20240102, ["prev_close"], right="Exclude", period=5) == "id=213&market=USHA&code=600000&start=20240101&end=20240102&datatype=6&period=16384"
    assert right_to_protocol("Forward") == "Q"
    assert right_to_protocol("backward") == "B"
    assert right_to_protocol("Exclude") == ""
    assert right_to_protocol(None) == ""
    assert right_to_protocol("") == ""
    assert right_to_protocol("Q") == "Q"
    with pytest.raises(ProtocolError):
        right_to_protocol("sideways")


def test_format_candle_time():
    assert format_candle_time(datetime(2024, 1, 2, 3, 4), 15) == "130093252"
    assert format_candle_time(datetime(2024, 1, 2, 3, 4), 5) == "20240102"
    assert format_candle_time(date(2024, 1, 2), 15) == "20240102"
    assert format_candle_time(20240101, 5) == "20240101"


def test_candle_rows_from_response_normalizes_dates():
    hx = make_hx_bytes([(1, 4, 4), (7, 2, 4)], [(20240101, 12345)])
    response = DataResponseV2(full_pack=make_pack(hx))
    rows = candle_rows_from_response(response, 5)
    assert rows == [{1: "20240101", 7: 12345.0}]
    assert candle_rows_from_response(response, 15) == [{1: 1704067200, 7: 12345.0}]
    assert candle_rows_from_response(DataResponseV2(full_pack=EMPTY_PACK), 5) == []


def test_candle_rows_from_response_dedupes_within_response():
    hx = make_hx_bytes(
        [(1, 4, 4), (5, 1, 6), (7, 2, 4)],
        [
            (20240101, b"600000", 12345),
            (20240101, b"600000", 99),
            (20240102, b"600000", 5),
        ],
    )
    rows = candle_rows_from_response(DataResponseV2(full_pack=make_pack(hx)), 5)
    assert len(rows) == 2
    assert rows[0] == {1: "20240101", 5: "600000", 7: 12345.0}
    assert rows[1] == {1: "20240102", 5: "600000", 7: 5.0}


def test_query_kline_default_fields():
    transport = RecordingTransport()
    client = HevoClient(transport=transport)
    client.auth = {}
    assert client.query_kline("600000", count=10) == []
    assert [int(call["id"]) for call in transport.calls] == [210, 212, 213]
    assert [call["datatype"] for call in transport.calls] == ["1,9,8,13,7,11,19", "1,1968584", "1,6"]
    for call in transport.calls:
        assert call["market"] == "USHA"
        assert call["code"] == "600000"
        assert call["start"] == "-10"
        assert call["end"] == "0"
        assert call["period"] == "16384"
        assert call["fuquan"] == "Q"
        assert "fuquanopt" not in call
    assert transport.auth_calls == 0


def test_query_kline_period_and_right():
    transport = RecordingTransport()
    client = HevoClient(transport=transport)
    client.auth = {}
    rows = client.query_kline("600000", period=15, count=5, fields=["open"], right="Backward", is_volume_exclude=True)
    assert rows == []
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert int(call["id"]) == 210
    assert call["datatype"] == "1,7"
    assert call["period"] == "12288"
    assert call["start"] == "-5"
    assert call["end"] == "0"
    assert call["fuquan"] == "B"
    assert call["fuquanopt"] == "V"


def test_query_kline_sends_auth_once():
    transport = RecordingTransport()
    client = HevoClient(transport=transport)
    client.auth = {"auth_bytes": b"AUTH"}
    client.auth_bytes = b"AUTH"
    assert client.query_kline("600000", count=2, fields=["open"]) == []
    assert client.query_kline("600000", count=2, fields=["open"]) == []
    assert transport.auth_calls == 1
    assert len(transport.calls) == 2


def test_query_kline_index_drops_turnover_rate():
    transport = RecordingTransport()
    client = HevoClient(transport=transport)
    client.auth = {}
    assert client.query_kline("000001", market="USHI", fields=["open", "turnover_rate"]) == []
    assert len(transport.calls) == 1
    assert transport.calls[0]["datatype"] == "1,7"


def test_query_kline_index_with_only_turnover_rate_returns_empty():
    transport = RecordingTransport()
    client = HevoClient(transport=transport)
    client.auth = {}
    assert client.query_kline("000001", market="USHI", fields=["turnover_rate"]) == []
    assert transport.calls == []


def test_query_kline_requires_auth():
    with pytest.raises(AuthError):
        HevoClient(transport=RecordingTransport()).query_kline("600000")


def test_query_kline_merges_extra_fields():
    main_hx = make_hx_bytes([(1, 4, 4), (7, 2, 4)], [(20240101, 12345), (20240102, 1)])
    extra_hx = make_hx_bytes([(1, 4, 4), (6, 3, 8)], [(20240101, 100.0), (20240103, 200.0)])
    transport = RecordingTransport({210: [make_pack(main_hx, 210)], 213: [make_pack(extra_hx, 213)]})
    client = HevoClient(transport=transport)
    client.auth = {}
    rows = client.query_kline("600000", count=2, fields=["open", "prev_close"])
    assert rows == [
        {1: "20240101", 7: 12345.0, 6: 100.0},
        {1: "20240102", 7: 1.0},
    ]
