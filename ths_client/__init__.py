# -*- coding: utf-8 -*-
"""同花顺柜台交易协议 —— 纯 Python 客户端.

主入口::

    from ths_client import TradeClient

    cli = TradeClient(zjzh='12345678', gdzh_sh='A123456789', gdzh_sz='0123456789')
    cli.connect()
    cli.login()
    cli.bootstrap(include_sh=True)
    print(cli.precheck('601398', qty=100)['text'])
    # print(cli.buy_market('601398', 100)['text'])   # 真实委托!

模块:
    client      - 高层 TradeClient API (推荐入口)
    trade_conn  - 柜台TCP连接: 问候/登录/会话/收发帧/启动序列回放
    trade_msg   - 报文构造: 登录/0124预检/0221市价买单 (模板+MD5签名)
    trade_crypt - 消息体编解码 (DES-CBC + zlib, 收发双向)
    machine     - 真实机器信息采集与注入 (MAC/CPU/序列号等)
    crypto      - RSA PKCS#1 v1.5 (type 02) 加密 (网页登录辅助)
    login       - 统一登录 (auth.10jqka.com.cn/verify2)
    session     - 会话对象与持久化
    xcs         - XCS 云交易服务查询 (实验)
    trade       - 早期下单报文构建 (已废弃, 见 trade_msg)

协议要点 (详见 docs/下单逆向进展-3.md):
    帧 = fdfdfdfd + 8字符hex长度 + mode + content
    C2S content = fdff + sess4 + cmd + 00001000 + len1 + len2 + body
    body = DES-CBC(zlib(明文), KEY, IV); 明文[8:24] = md5签名槽(清零后求md5)
    会话4字节登录时全零; 登录后回显服务器分配值
    市场: '2'=上海(A开头股东号), '1'=深圳(数字股东号)
"""
__version__ = "0.9.0"

from . import machine  # noqa: E402
from .client import TradeClient, load_profile, parse_kv  # noqa: E402

__all__ = ['TradeClient', 'load_profile', 'parse_kv', 'machine', '__version__']
