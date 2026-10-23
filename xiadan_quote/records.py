from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

MAGIC = b"\x7b\xd0\x0f\x7f"
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"
MARKET_BYTES = {0x11: "sh", 0x21: "sz", 0x31: "bj"}


def decode_price(value: int) -> float:
    kind = value >> 24
    if kind == 0xB0:
        return (value & 0xFFFF) / 1000.0
    if kind == 0xB8:
        raw = value & 0xFFFFFF
        if raw & 0x800000:
            raw -= 1 << 24
        return raw / 10000.0
    if kind == 0xC0:
        return (value & 0xFFFFFF) / 10000.0
    return float(value)


def _find_code(data: bytes) -> Optional[Tuple[int, str, str]]:
    for offset in range(24, min(44, len(data) - 6)):
        market = MARKET_BYTES.get(data[offset])
        if market is None:
            continue
        digits = data[offset + 1 : offset + 7]
        if all(0x30 <= value <= 0x39 for value in digits):
            return offset + 1, market, digits.decode("ascii")
    return None


@dataclass(frozen=True)
class QuoteRecord:
    market: str
    code: str
    prev_close: float
    open: float
    high: float
    low: float
    latest: float
    volume: int
    amount: int
    trades: int
    status: int
    outer_volume: int
    inner_volume: int
    cells: Tuple[int, ...]
    extra_cells: Tuple[int, ...]

    @property
    def full_code(self) -> str:
        return f"{self.market}{self.code}"

    @property
    def change(self) -> float:
        return round(self.latest - self.prev_close, 4)

    @property
    def change_percent(self) -> float:
        if not self.prev_close:
            return 0.0
        return round((self.latest / self.prev_close - 1.0) * 100.0, 4)

    @property
    def average_price(self) -> float:
        if not self.volume:
            return 0.0
        return round(self.amount / self.volume, 4)


def parse_record(data: bytes) -> QuoteRecord:
    if data[:4] != MAGIC:
        raise ValueError("not a 7bd0 quote record")
    found = _find_code(data)
    if found is None:
        raise ValueError("quote record has no stock code")
    code_offset, market, code = found
    body = data[code_offset + 6 : len(data) - 3]
    if len(body) < 44 or len(body) % 4:
        raise ValueError("unexpected quote record body length")
    cells = struct.unpack(f"<{len(body) // 4}I", body)
    if len(cells) < 11:
        raise ValueError("quote record has too few fields")
    extra = tuple(cells[33:35]) if len(cells) >= 37 else ()
    return QuoteRecord(
        market=market,
        code=code,
        prev_close=decode_price(cells[0]),
        open=decode_price(cells[1]),
        high=decode_price(cells[2]),
        low=decode_price(cells[3]),
        latest=decode_price(cells[4]),
        volume=cells[5],
        amount=cells[6],
        trades=cells[7],
        status=cells[8],
        outer_volume=cells[9],
        inner_volume=cells[10],
        cells=tuple(cells),
        extra_cells=extra,
    )


def iter_frame_payloads(stream: bytes) -> Iterator[bytes]:
    offset = 0
    while True:
        start = stream.find(FRAME_MAGIC, offset)
        if start < 0 or start + 13 > len(stream):
            return
        try:
            length = int(stream[start + 4 : start + 12], 16)
        except ValueError:
            offset = start + 1
            continue
        if length <= 0 or start + 13 + length > len(stream):
            offset = start + 1
            continue
        yield stream[start + 13 : start + 13 + length]
        offset = start + 13 + length


def iter_quote_records(stream: bytes) -> Iterator[QuoteRecord]:
    for payload in iter_frame_payloads(stream):
        if payload[:4] != MAGIC:
            continue
        try:
            yield parse_record(payload)
        except ValueError:
            continue
