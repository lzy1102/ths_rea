import pytest

from xiadan_quote import daily_kline as dk
from xiadan_quote.daily_kline import (
    DailyBar,
    decode_all_payload,
    fetch_daily_bars,
    parse_last_payload,
    parse_today_payload,
)


def test_parse_last_payload():
    payload = {
        "data": (
            "20261021,5.64,5.65,5.55,5.60,129346854,723515810.00,0.178,,108900.00,609840;"
            "20261022,5.61,5.62,5.51,5.56,155754090,867345650.00,0.215,,49900.00,277444;"
        )
    }
    bars = parse_last_payload(payload)
    assert len(bars) == 2
    assert bars[0] == DailyBar("20261021", 5.64, 5.65, 5.55, 5.60, 129346854, 723515810.0, 0.178)
    assert bars[1].close == 5.56
    assert bars[1].amount == 867345650.0


def test_parse_today_payload():
    payload = {
        "hs_601658": {
            "1": "20261023",
            "7": "5.59",
            "8": "5.60",
            "9": "5.43",
            "11": "5.48",
            "13": 224519050,
            "19": "1231398380.00",
            "1968584": "0.310",
        }
    }
    bar = parse_today_payload(payload)
    assert bar == DailyBar("20261023", 5.59, 5.60, 5.43, 5.48, 224519050, 1231398380.0, 0.310)


def test_decode_all_payload():
    payload = {
        "start": "20191210",
        "sortYear": [[2019, 2], [2020, 1]],
        "priceFactor": 100,
        "dates": "1210,1211,0102",
        "price": "387,7,12,8,389,3,9,8,390,4,5,4",
        "volumn": "100,200,300",
    }
    bars = decode_all_payload(payload)
    assert [bar.date for bar in bars] == ["20191210", "20191211", "20200102"]
    assert bars[0] == DailyBar("20191210", 3.94, 3.99, 3.87, 3.95, 100)
    assert bars[1].open == pytest.approx(3.92)
    assert bars[2].high == pytest.approx(3.95)


def test_fetch_daily_bars_merges_today(monkeypatch):
    payloads = {
        "last": {
            "data": (
                "20261021,5.64,5.65,5.55,5.60,129346854,723515810.00,0.178,,108900.00,609840;"
                "20261022,5.61,5.62,5.51,5.56,155754090,867345650.00,0.215,,49900.00,277444;"
                "20261023,5.59,5.60,5.45,5.53,107048892,589880400.00,0.148,,,0;"
            )
        },
        "today": {
            "hs_601658": {
                "1": "20261023",
                "7": "5.59",
                "8": "5.60",
                "9": "5.43",
                "11": "5.48",
                "13": 224519050,
                "19": "1231398380.00",
                "1968584": "0.310",
            }
        },
    }

    def fake_load(code, adjust, kind, timeout, retries):
        assert code == "sh601658"
        assert adjust == "01"
        return payloads[kind]

    monkeypatch.setattr(dk, "_load_jsonp", fake_load)
    bars = fetch_daily_bars("sh601658", count=2)
    assert [bar.date for bar in bars] == ["20261022", "20261023"]
    assert bars[-1].close == 5.48
    assert bars[-1].volume == 224519050
