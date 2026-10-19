# -*- coding: utf-8 -*-
"""
同花顺 SuperMind 智能交易终端 —— 外部 Python 最小闭环示例
=========================================================
流程: 选股 -> 查账户 -> 下单 -> 轮询委托/成交 -> 输出结果

运行前提（官方）:
1. 安装并打开"同花顺智能交易 SuperMind"终端（本地 SDK 随终端提供）
2. 用同花顺账号登录终端，并在终端里登录你的【资金账号】（TradeAPI 连的就是它）
3. 模拟测试：官网下载仿真版创建模拟账户（zjcmpp.hexin.com.cn/dow），先跑通再上实盘

安装:
    按终端"本地SDK/帮助"页说明安装 tick_trade_api
    （SuperMind 量化版/量化标准版支持；研究环境内 Jupyter 也可直接 import）

免责声明: 本示例仅用于学习演示；程序化交易需遵守证监会及券商相关规定，
          造成的任何交易后果由使用者自行承担。首次务必用模拟账号验证。
"""

import time
import datetime as dt

# ============ 1. 配置区 ============
ACCOUNT_ID = "12345678"          # 资金账号（务必改成你自己的，勿硬编码后开源）

RISK = {
    "max_order_amount": 10000,   # 单笔最大金额（元）
    "max_price": 1000.0,         # 单股价格上限（元）
    "max_orders_per_run": 3,     # 单次运行最多下单笔数
    "poll_seconds": 5,           # 下单后轮询时长（秒）
}

# ============ 2. 选股（可替换为你的因子框架/数据源） ============
def pick_stocks():
    """
    最小选股示例：返回 [(symbol, name, target_amount_yuan), ...]
    symbol 格式: 代码.SZ / 代码.SH（按终端要求）
    实际使用时替换为: 你的量化框架信号 / thsdk 行情条件 / 问财选股结果
    """
    watch = [
        ("000001.SZ", "平安银行", 5000),
        ("600519.SH", "贵州茅台", 0),      # 金额为 0 表示本轮跳过
    ]
    return [(s, n, amt) for s, n, amt in watch if amt > 0]


# ============ 3. 连接与账户状态 ============
def connect():
    from tick_trade_api.api import TradeAPI
    api = TradeAPI(account_id=ACCOUNT_ID)   # 资金账号必须已在终端登录
    return api


def show_account(api):
    pf = api.portfolio
    print("== 账户资金 ==")
    for k in ("zzc", "kyje", "zjye"):       # 总资产/可用金额/资金余额（以SDK字段为准）
        try:
            print(f"  {k}: {getattr(pf, k)}")
        except Exception:
            pass
    positions = api.positions
    print("== 持仓 ==")
    try:
        for p in positions:
            print("  ", p)
    except Exception:
        print("  ", positions)


# ============ 4. 下单（带风控） ============
def place_order(api, symbol, amount_yuan, price_type="zxjg"):
    """
    最小实现：按参考价市价化下单。生产请自行换用限价+滑点保护。
    返回 order_id 或 None
    """
    if amount_yuan > RISK["max_order_amount"]:
        print(f"[风控] {symbol} 金额 {amount_yuan} 超限，跳过")
        return None

    # 参考价: 示例用最新价；可换成盘口/你的模型价
    price = None
    if price_type == "zxjg":
        # tick_trade_api 提供行情查询方法；此处为演示，用终端最新价下单
        # 如 SDK 支持 pricetype 参数可用智能下单（见官方教程第3节）
        price = None  # None -> 以行情最新价委托（按SDK行为）

    qty = None
    if price:
        qty = int(amount_yuan / price / 100) * 100   # A股整手
    else:
        qty = amount_yuan  # 演示: 直接把金额当股数占位，实际请按最新价换算

    if qty < 100:
        print(f"[跳过] {symbol} 数量不足一手")
        return None

    # 限价单: amount 为负数代表卖出，下单成功返回 order_id
    order_id = api.order(symbol=symbol, amount=int(qty), price=price)
    print(f"[已委托] {symbol} 数量={qty} order_id={order_id}")
    return order_id


# ============ 5. 查询委托/成交 ============
def query_orders(api, order_id=None):
    orders = api.get_orders(order_id=order_id) if order_id else api.get_orders()
    print("== 委托 ==")
    try:
        for o in orders:
            print("  ", o)
    except Exception:
        print("  ", orders)
    try:
        trades = api.get_tradelogs()
        print("== 成交 ==")
        for t in trades:
            print("  ", t)
    except Exception as e:
        print("  成交查询不可用:", e)


def cancel_order(api, order_id):
    try:
        api.cancel_order(order_id)          # 撤单（以实际SDK函数名为准）
        print(f"[已撤单] {order_id}")
    except Exception as e:
        print(f"[撤单失败] {order_id}: {e}")


# ============ 6. 最小闭环 ============
def main():
    print(f"运行时间: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
    api = connect()
    show_account(api)

    picks = pick_stocks()[: RISK["max_orders_per_run"]]
    if not picks:
        print("选股结果为空，退出")
        return

    order_ids = []
    for symbol, name, amount_yuan in picks:
        oid = place_order(api, symbol, amount_yuan)
        if oid is not None:
            order_ids.append(oid)

    # 轮询查询结果
    end = time.time() + RISK["poll_seconds"]
    while time.time() < end:
        time.sleep(1)
    for oid in order_ids:
        query_orders(api, oid)
    query_orders(api)   # 全量委托+成交

    # 撤单示例（按需开启）
    # for oid in order_ids:
    #     cancel_order(api, oid)


if __name__ == "__main__":
    main()
