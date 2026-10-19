#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""示例 2 · 轮询策略骨架: 定时取参考价 -> 条件满足则下单 -> 记录结果。

    python ths_client/examples/polling_strategy.py --codes 601398,000001 --qty 100

取价用 `cli.quote()` 的盘中实时快照(最新价在行情推送的二进制区)。
注意: 最新价目前只在**主板沪深**验证可靠, 创业板/科创板会回退到当日开盘价。
需要 Level-2 / 五档 / 逐笔数据时, 自行接第三方行情源, 只替换 get_price() 即可。
"""
import argparse
import re
import sys
import time

from ths_client import TradeClient


def get_price(cli, code, market):
    """最新价。

    quote() 返回盘中实时快照(开/高/低/最新/量额)。最新价在行情推送的二进制区,
    仅**主板沪深**验证可靠; 创业板/科创板记录布局不同, last 可能为 None,
    此时回退到当日开盘价(仅够做粗条件判断)。收盘后无最新价。
    """
    try:
        q = cli.quote(code, market=market)
        if q.get('last'):
            return q['last']
        if q.get('open'):
            return q['open']
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description='轮询策略骨架')
    ap.add_argument('--codes', default='601398', help='逗号分隔股票代码')
    ap.add_argument('--qty', type=int, default=100)
    ap.add_argument('--below', type=float, default=None, help='价低于该值则买入')
    ap.add_argument('--interval', type=float, default=15.0)
    ap.add_argument('--times', type=int, default=0, help='轮询次数(0=不限)')
    ap.add_argument('--limit', action='store_true', help='用限价单而非市价单')
    ap.add_argument('--dry-run', action='store_true', help='只打印不下单')
    a = ap.parse_args()

    codes = [c.strip() for c in a.codes.split(',') if c.strip()]
    cli = TradeClient.from_profile()
    cli.start()
    print(f"已连接 {cli.host_used}  监控 {codes}  间隔 {a.interval}s  "
          f"{'限价' if a.limit else '市价'}  {'DRY-RUN' if a.dry_run else '实盘'}")

    done = set()
    n = 0
    try:
        while a.times <= 0 or n < a.times:
            n += 1
            for code in codes:
                if code in done:
                    continue
                market = None
                try:
                    px = get_price(cli, code, market)
                    if px is None:
                        print(f"[{time.strftime('%H:%M:%S')}] {code} 取价失败, 跳过")
                        continue
                    print(f"[{time.strftime('%H:%M:%S')}] {code} 参考价 {px}")
                    if a.below is None or px >= a.below:
                        continue
                    if a.dry_run:
                        print(f"        [DRY-RUN] 条件满足({px} < {a.below}), 跳过下单")
                        done.add(code)
                        continue
                    if a.limit:
                        r = cli.limit_order(code, a.qty, a.below, is_sell=False)
                    else:
                        r = cli.buy_market(code, a.qty)
                    txt = r['text']
                    print(f"        下单结果: {txt[:120]}")
                    done.add(code)
                except Exception as e:
                    print(f"[{time.strftime('%H:%M:%S')}] {code} 异常 {e!r}")
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print('\n退出')
    finally:
        cli.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())