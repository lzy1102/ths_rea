import pytest

from xiadan_quote import parse_record
from xiadan_quote.records import FRAME_MAGIC, iter_quote_records

RECORD_179_SH = bytes.fromhex(
    "7bd00f7f7c0091065640599cb482838180808081019a7dffffe79f200011"
    "363031363538ae1500b0a41500b0c21500b0a41500b0b81500b020de3300"
    "7ae31f01b103000005000000ac6f2a00746e0900ae1500b0f42a0e00a415"
    "00b0084107009a1500b0ac441400b81500b0a4130200c21500b0f0ec0400"
    "cc1500b0b85b1400444a0800901500b074ec0d00d61500b0b0751b008615"
    "00b09c9c1c00e01500b084421b00690100b05431313100000000c5b07d"
)

RECORD_187_SH = bytes.fromhex(
    "7bd00f7f7c0091065640599ab48283818080808101a27dffffe79f2c0011"
    "363031363538ae1500b0a41500b0c21500b0a41500b0ae1500b0dc932b00"
    "9bd1f100ec0200000500000068252200746e0900ae1500b0f4e30400a415"
    "00b0503b06009a1500b01c621300b81500b090010000c21500b0d4950400"
    "cc1500b010ce1200f4b61800901500b090ad0d00d61500b064771a008615"
    "00b0fc5a1c00e01500b028fe1a00b50000b0000000000000000054313131"
    "00000000868e7d"
)

RECORD_183_SZ = bytes.fromhex(
    "7bd00f7f7c00a1065640599bb483838180808081019e7dffffe7bf200021"
    "30303030303138c101c038c101c09cc101c070c001c0d4c001c010861e00"
    "63f35e019402000001000000eac5070026c0160070c001c0ac9103000cc0"
    "01c06c6c0400a8bf01c044430500d4c001c03402010038c101c0a3060100"
    "9cc101c038890200bc0b0b0044bf01c0c0b0070000c201c0a8f10100e0be"
    "01c0cc05060064c201c0e868040030d900c0570000b85430202020202020"
    "74ea7d"
)


def test_parse_sh_full_record():
    record = parse_record(RECORD_179_SH)
    assert record.full_code == "sh601658"
    assert record.prev_close == 5.55
    assert record.open == 5.54
    assert record.high == 5.57
    assert record.low == 5.54
    assert record.latest == 5.56
    assert record.volume == 3399200
    assert record.amount == 18867066
    assert record.trades == 945
    assert record.outer_volume + record.inner_volume == record.volume
    assert record.change == pytest.approx(0.01)
    assert record.change_percent == pytest.approx(0.1802, abs=1e-4)
    assert record.average_price == pytest.approx(5.5504, abs=1e-4)
    assert len(record.cells) == 35
    assert record.extra_cells == ()


def test_parse_sh_record_with_extra_fields():
    record = parse_record(RECORD_187_SH)
    assert record.code == "601658"
    assert record.latest == 5.55
    assert record.volume == 2855900
    assert record.amount == 15847835
    assert len(record.cells) == 37
    assert record.extra_cells == (0, 0)


def test_parse_sz_record():
    record = parse_record(RECORD_183_SZ)
    assert record.full_code == "sz000001"
    assert record.prev_close == 11.5
    assert record.latest == 11.49
    assert record.high == 11.51
    assert record.low == 11.48
    assert record.volume == 2000400
    assert record.amount == 22999907
    assert record.outer_volume + record.inner_volume == record.volume
    assert record.change_percent == pytest.approx(-0.087, abs=1e-4)
    assert len(record.cells) == 36


def test_iter_quote_records_skips_non_quote_payloads():
    def frame(payload):
        return FRAME_MAGIC + f"{len(payload):08x}".encode("ascii") + b"\t" + payload

    stream = frame(b"text") + frame(RECORD_179_SH) + frame(b"\x00\x01")
    records = list(iter_quote_records(stream))
    assert len(records) == 1
    assert records[0].code == "601658"
