#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""示例 1 · 账户监控: 定时轮询持仓/资金/委托, 变化即打印; 回调打印推送。

    python ths_client/examples/monitor.py --interval 30

不需要行情源, 纯柜台查询 —— 适合放在服务器上常驻, 做盯盘/风控/对账。
"""
import argparse
import sys
import time

from ths_client import TradeClient


def fmt_kv(d, keys):
    return ' '.join(f'{k}={d[k]}' for k in keys if k in d)


def main():
    ap = argparse.ArgumentParser(description='账户监控示例')
    ap.add_argument('--interval', type=float, default=30.0, help='轮询间隔秒')
    ap.add_argument('--times', type=int, default=0, help='轮询次数(0=直到 Ctrl-C)')
    ap.add_argument('--market', default='2', help="'2'=沪 '1'=深")
    ap.add_argument('--profile', default=None, help='local_profile.json 路径')
    a = ap.parse_args()

    pushes = []

    def on_push(p):
        kv = p['kv']
        pushes.append(p)
        print(f"  [推送] {fmt_kv(kv, ('zqdm', 'zqmc', 'cjje', 'cjl', 'ywzt', 'statusflag'))}")

    cli = TradeClient.from_profile(a.profile, on_push=on_push) if a.profile \
        else TradeClient.from_profile(on_push=on_push)
    cli.start()
    mkt = a.market
    print(f"已连接 {cli.host_used}  账户={cli.account_info()}")
    print(f"轮询间隔 {a.interval}s  市场 {mkt}  (Ctrl-C 退出)\n")

    last = {}
    n = 0
    try:
        while a.times <= 0 or n < a.times:
            n += 1
            row = {}
            try:
                b = cli.query_balance(market=mkt)
                row['资金列名'] = b['columns']
                row['资金字段数'] = len(b['fields'])
                p = cli.query_positions(market=mkt)
                row['持仓列名'] = p['columns']
                row['持仓字段数'] = len(p['fields'])
                o = cli.query_orders(market=mkt)
                row['委托列名'] = o['columns'][:6]
                row['委托字段数'] = len(o['fields'])
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] 查询异常 {e!r} (自动重连中)")
                try:
                    cli.reconnect()
                except Exception:
                    pass
                continue

            diff = {k: v for k, v in row.items() if last.get(k) != v}
            mark = '*' if diff else ' '
            print(f"[{time.strftime('%H:%M:%S')}]{mark} " +
                  ' | '.join(f'{k}:{v}' for k, v in row.items()))
            if diff:
                for k, v in diff.items():
                    print(f"        变化 {k}: {last.get(k)} -> {v}")
            last = row
            if pushes:
                print(f"        累计推送 {len(pushes)} 条")
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print('\n退出')
    finally:
        cli.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())