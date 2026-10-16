# -*- coding: utf-8 -*-
# 注意: 本模块是早期逆向的文本包格式 (cmd=xd_mairu), 实际柜台走二进制帧协议。
# 新代码请用 trade_msg.py (明文构造) + trade_conn.py (连接/收发帧) + trade_crypt/body_codec.py (加解密)。
# 本模块仅保留作历史参考。
"""下单报文构建

来源: xiadan.exe 内存反汇编实测 (fcn 0x00F4AD00):
    cmd=xd_mairu\\ncode=%s\\nprice=%s\\namount=%s\\nlock=%s\\nrelmarket=%s\\n
    dzh=1\\nrelmarket=%d\\nuserkey=%s\\n

命令字:
    xd_mairu  买入    xd_maichu 卖出    xd_dmdm  代码下单(市价?)
    cmd_qu_zijin 查资金
    tjdd_upload_wt 提交委托 / tjdd_chedan 撤单 / tjdd_order 委托
    tjdd_cx_dd 查当日委托 / tjdd_cx_gpxx 查股票信息 / tjdd_extend 扩展

传输层说明 (待接线):
    该文本包由经典交易引擎发出 (xiadan.exe)。
    可用通道:
      1) 本机已登录客户端 (IPC / UI 桥, 开发中)
      2) 直接对交易站点 (如 114.141.180.27:8002) 的私有协议 (需抓包补全)
"""

BUY = "xd_mairu"
SELL = "xd_maichu"


def build_order_packet(cmd: str, code: str, price, amount, *,
                       lock: int = 0, relmarket: int = 0, dzh: int = 1,
                       userkey: str = "") -> str:
    return (
        f"cmd={cmd}\n"
        f"code={code}\n"
        f"price={price}\n"
        f"amount={amount}\n"
        f"lock={lock}\n"
        f"relmarket={relmarket}\n"
        f"dzh={dzh}\n"
        f"relmarket={relmarket}\n"
        f"userkey={userkey}\n"
    )


def build_buy(code: str, price, amount, **kw) -> str:
    return build_order_packet(BUY, code, price, amount, **kw)


def build_sell(code: str, price, amount, **kw) -> str:
    return build_order_packet(SELL, code, price, amount, **kw)
