# -*- coding: utf-8 -*-
"""查询接口演示（使用已保存会话）

准备: 先运行 ths_client_demo.py 用真实账号登录, 或复用已抓取的 session.json

用法:
    python query_demo.py selfstock     # 自选股
"""
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ths_client.session import ThsSession

SESSION_FILE = Path(__file__).resolve().parent / "session.json"
UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36"


def load_http() -> requests.Session:
    sess = ThsSession.load(SESSION_FILE)
    http = requests.Session()
    http.cookies.update(sess.cookies)
    http.headers["User-Agent"] = UA
    return http


def query_selfstock():
    http = load_http()
    r = http.get(
        "https://ugc.10jqka.com.cn/optdata/selfstock/open/api/v1/query"
        "?need_merge=0&from=thspc_main&support_all=1",
        timeout=20)
    j = r.json()
    field = j.get("data", {}).get("selfstock", "")
    parts = field.split(",")
    codes = [c for c in parts[0].split("|") if c]
    mkts = [m for m in parts[1].split("|") if m] if len(parts) > 1 else []
    items = list(zip(codes, mkts + [""] * (len(codes) - len(mkts))))
    print(f"[自选股] {len(items)} 只:")
    for code, mkt in items:
        print(f"    {code}  (market={mkt})")
    return items


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "selfstock"
    if what == "selfstock":
        query_selfstock()
    else:
        print("未知命令:", what)
