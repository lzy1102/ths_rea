import os
import re
import xml.etree.ElementTree as ET

_MARKET_BY_OLD_ID = {}
_MARKET_BY_ID = {}
_MARKET_DATA_LOADED = False


def _load_market_data():
    global _MARKET_BY_OLD_ID, _MARKET_BY_ID, _MARKET_DATA_LOADED
    if _MARKET_DATA_LOADED:
        return
    _MARKET_DATA_LOADED = True
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "data", "MarketData.xml"),
        os.path.join(os.path.dirname(here), "docs", "MarketData.xml"),
    ]
    path = None
    for candidate in candidates:
        if os.path.exists(candidate):
            path = candidate
            break
    if path is None:
        return
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return
    for item in root.findall("Market"):
        market_id = item.get("id") or ""
        old_id = item.get("old_id")
        if not market_id or old_id is None:
            continue
        _MARKET_BY_ID[market_id] = market_id
        try:
            _MARKET_BY_OLD_ID[int(old_id)] = market_id
        except ValueError:
            continue


def parse_market(text):
    if not text:
        return ""
    if text == "SPECIAL":
        return text
    first = text[0]
    if first in ("U", "u"):
        return text.upper()
    try:
        old_id = int(text)
    except ValueError:
        return text
    return _MARKET_BY_OLD_ID.get(old_id, text)


def parse_market_from_old_id(old_id):
    _load_market_data()
    return _MARKET_BY_OLD_ID.get(old_id, "")


def is_new_parent_market(text):
    if not text:
        return False
    return len(text) == 4 and all("A" <= ch <= "Z" for ch in text)


def supported_markets(service_tags):
    _load_market_data()
    result = []
    for text in service_tags or []:
        if not text:
            continue
        try:
            stripped = text[1:] if text[0] == "-" else text
            if stripped.isdigit():
                result.append(parse_market_from_old_id(int(text)))
            elif is_new_parent_market(text):
                result.append(parse_market(text))
        except Exception:
            continue
    return result


def is_main_quote_server(supported):
    names = list(supported or [])
    if "USHI" in names and "USZI" in names:
        return True
    return "USH" in names or "USZ" in names
