# -*- coding: utf-8 -*-
"""
同花顺【Python 策略编辑器】(ths_api) 最小闭环示例
=================================================
在"同花顺下单客户端 xiadan.exe -> 策略 -> Python策略编辑器"中粘贴运行。

特点: 无需外部 SDK；行情/交易/持仓都在编辑器里直接可用；
      接口来自官方文档 showdoc.cc/THSPythonSE（本文件仅用文档确认过的函数）。

流程: 选股(自选股清单) -> 查持仓资金 -> 下单 -> 输出结果供核对
"""

from ths_api import *          # noqa: F403  官方包
import time

# ---------------- 配置 ----------------
ACCOUNT = None                 # None=当前默认账号；或填资金账号字符串（单账号时）
MAX_AMOUNT_YUAN = 10000        # 风控：单笔金额上限
BUY_LIST = [                   # 选股结果（可换成你的框架输出）
    ("000001", "平安银行"),
    ("600519", "贵州茅台"),
]


def log(msg):
    print(msg)                 # 编辑器下方日志窗口可见


def show_state():
    log("== 资金 ==")
    log("总资产 zzc = %s" % xd.g_money["zzc"])
    log("可用 kyje  ≈ %s" % xd.g_money.get("kyje", "见编辑器帮助"))
    log("== 持仓 ==")
    for code, pos in xd.g_position.items():
        log("  %s 数量=%s 成本=%s 市价=%s" % (
            code, pos.get("sjsl"), pos.get("cbj"), pos.get("sj")))


def buy(code, amount_yuan):
    """按最新价买入，金额受控；-notip 直接委托（无确认弹窗，演示用）"""
    if amount_yuan > MAX_AMOUNT_YUAN:
        log("[风控] %s 金额超限，跳过" % code)
        return
    # 按金额买入: -m 金额值；正常应保留确认弹窗, 此处为最小自动化演示用 -notip
    xd.cmd("buy %s zxjg -m %d -notip" % (code, amount_yuan))
    log("[已提交] buy %s -m %d" % (code, amount_yuan))


def main():
    log("运行时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    show_state()

    for code, name in BUY_LIST:
        # 简单条件示例: 已有持仓则不重复买（按需替换为你的信号）
        held = xd.g_position.get(code, {}).get("sjsl", 0)
        if held and held > 0:
            log("[跳过] %s 已持仓 %s" % (code, held))
            continue
        buy(code, 5000)

    time.sleep(3)               # 等回报刷新
    log("== 委托/持仓复查 ==")
    show_state()

    # 撤单示例（文档"如何撤单"一节的函数，如与你的版本不同请对照编辑器帮助）:
    # xd.cmd("cx 合同编号")     # 或编辑器提供的专用撤单接口


if __name__ == "__main__":
    main()
