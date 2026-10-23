from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = "https://d.10jqka.com.cn/v6/line/{prefix}/{adjust}/{kind}.js"
ADJUST_CODES = {"none": "00", "qfq": "01", "hfq": "02"}
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "https://stockpage.10jqka.com.cn/",
}


@dataclass(frozen=True)
class DailyBar:
    date: str
    open: float
    high: float
    low: float
    close: float
    volume: int
    amount: Optional[float] = None
    turnover: Optional[float] = None


def _number(value: object) -> Optional[float]:
    if value is None:
        return None
    text = str(value).replace(",", "").strip()
    if not text or text == "-":
        return None
    return float(text)


def _integer(value: object) -> int:
    number = _number(value)
    return int(number) if number is not None else 0


def _normalize_code(code: str) -> str:
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) < 6:
        raise ValueError(f"invalid stock code: {code!r}")
    return digits[-6:]


def _http_get(url: str, timeout: float) -> bytes:
    request = Request(url, headers=DEFAULT_HEADERS)
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def _load_jsonp(
    code: str,
    adjust: str,
    kind: str,
    timeout: float = 15.0,
    retries: int = 3,
) -> dict:
    url = BASE_URL.format(prefix=f"hs_{_normalize_code(code)}", adjust=adjust, kind=kind)
    last_error: Optional[BaseException] = None
    for attempt in range(retries):
        try:
            body = _http_get(url, timeout)
            text = body.decode("utf-8", errors="replace")
            match = re.match(r"^\s*[^(]*\((.*)\)\s*;?\s*$", text, re.S)
            if match is None:
                raise ValueError("unexpected js payload")
            return json.loads(match.group(1))
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            last_error = error
            if attempt + 1 < retries:
                time.sleep(0.3 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}: {last_error}") from last_error


def parse_last_payload(payload: dict) -> List[DailyBar]:
    bars: List[DailyBar] = []
    for row in str(payload.get("data", "")).split(";"):
        parts = row.split(",")
        if len(parts) < 8:
            continue
        open_price = _number(parts[1])
        high = _number(parts[2])
        low = _number(parts[3])
        close = _number(parts[4])
        if open_price is None or high is None or low is None or close is None:
            continue
        bars.append(
            DailyBar(
                date=parts[0],
                open=open_price,
                high=high,
                low=low,
                close=close,
                volume=_integer(parts[5]),
                amount=_number(parts[6]),
                turnover=_number(parts[7]),
            )
        )
    return bars


def parse_today_payload(payload: dict) -> Optional[DailyBar]:
    item = next((value for value in payload.values() if isinstance(value, dict)), None)
    if not item:
        return None
    date = str(item.get("1", ""))
    if not date:
        return None
    open_price = _number(item.get("7"))
    high = _number(item.get("8"))
    low = _number(item.get("9"))
    close = _number(item.get("11"))
    if open_price is None or high is None or low is None or close is None:
        return None
    return DailyBar(
        date=date,
        open=open_price,
        high=high,
        low=low,
        close=close,
        volume=_integer(item.get("13")),
        amount=_number(item.get("19")),
        turnover=_number(item.get("1968584")),
    )


def _all_dates(payload: dict) -> List[str]:
    dates = [value for value in str(payload.get("dates", "")).split(",") if value]
    sort_year = payload.get("sortYear", [])
    if isinstance(sort_year, str):
        sort_year = json.loads(sort_year)
    counts: Dict[int, int] = {int(year): int(count) for year, count in sort_year}
    start = str(payload.get("start", ""))
    if len(start) < 4 or not counts:
        raise ValueError("all payload has no year information")
    year = int(start[:4])
    remaining = counts.get(year, 0)
    result: List[str] = []
    for month_day in dates:
        while remaining <= 0:
            year += 1
            remaining = counts.get(year, 0)
            if year > 9999:
                raise ValueError("all payload year information is incomplete")
        result.append(f"{year:04d}{month_day}")
        remaining -= 1
    return result


def decode_all_payload(payload: dict) -> List[DailyBar]:
    dates = _all_dates(payload)
    prices = [int(value) for value in str(payload.get("price", "")).split(",") if value]
    volumes = [value for value in str(payload.get("volumn", "")).split(",") if value]
    factor = _number(payload.get("priceFactor")) or 100.0
    if len(prices) != len(dates) * 4:
        raise ValueError("all payload price length does not match dates")
    if len(volumes) != len(dates):
        raise ValueError("all payload volume length does not match dates")
    bars: List[DailyBar] = []
    for index, date in enumerate(dates):
        low = prices[index * 4] / factor
        open_price = low + prices[index * 4 + 1] / factor
        high = low + prices[index * 4 + 2] / factor
        close = low + prices[index * 4 + 3] / factor
        bars.append(
            DailyBar(
                date=date,
                open=round(open_price, 4),
                high=round(high, 4),
                low=round(low, 4),
                close=round(close, 4),
                volume=_integer(volumes[index]),
            )
        )
    return bars


def _merge_bars(bars: Sequence[DailyBar]) -> List[DailyBar]:
    merged: Dict[str, DailyBar] = {bar.date: bar for bar in bars}
    return [merged[date] for date in sorted(merged)]


def fetch_daily_bars(
    code: str,
    count: int = 140,
    adjust: str = "qfq",
    timeout: float = 15.0,
    retries: int = 3,
) -> List[DailyBar]:
    adjust_code = ADJUST_CODES.get(adjust, adjust)
    if adjust_code not in {"00", "01", "02"}:
        raise ValueError(f"unsupported adjust: {adjust!r}")
    if count is not None and count < 1:
        raise ValueError("count must be positive")
    bars: List[DailyBar] = []
    if count is None or count > 140:
        bars.extend(decode_all_payload(_load_jsonp(code, adjust_code, "all", timeout, retries)))
        bars.extend(parse_last_payload(_load_jsonp(code, adjust_code, "last", timeout, retries)))
    else:
        bars.extend(parse_last_payload(_load_jsonp(code, adjust_code, "last", timeout, retries)))
    today = parse_today_payload(_load_jsonp(code, adjust_code, "today", timeout, retries))
    if today is not None:
        bars.append(today)
    merged = _merge_bars(bars)
    return merged[-count:] if count is not None else merged
