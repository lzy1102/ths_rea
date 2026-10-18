#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""示例 2 · 轮询策略骨架: 定时取参考价 -> 条件满足则下单 -> 记录结果。

    python ths_client/examples/polling_strategy.py --codes 601398,000001 --qty 100

【重要】本包不提供行情源。示例用 `precheck()` 应答里的 `open=` 作为参考价,
这只能满足"参考价低于/高于某阈值"这类粗条件。真做策略请自行接行情源
(券商 Level-2 / 第三方 / 自建), 然后替换 get_price() 实现即可 —— 其余流程不变。
"""
import argparse
import re
import sys
import time

from ths_client import TradeClient


def get_price(cli, code, market):
    """参考价: 预检应答的 open=。真实策略请替换为行情源取价。"""
    try:
        r = cli.precheck(code, 100, market=market)
        m = re.search(r'open=([0-9.]+)', r['text'])
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description='轮询策略骨架')
    ap.add_argument('--codes', default='601398', help='逗号分隔股票代码')
    ap.add_argument('--qty', type=int, default=100)
    ap.add_argument('--interval', type=float, default=15.0)
    ap.add_argument('--times', type=int, default=0, help='轮询次数(0=不限)')
    ap.add_argument('--limit', action='store_true', help='用限价单而非市价单')
    ap.add_argument('--dry-run', action='store_true', help='只打印不下单')
    a = ap.parse_args()

    ap.add_argument('--below', type=float, default=None, help='价低于该值则买入')
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