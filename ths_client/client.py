# -*- coding: utf-8 -*-
"""同花顺柜台交易 —— 高层客户端 API (供其他程序调用).

账号信息不进仓库: 通过参数或本地配置文件传入 (local_profile.json, 已gitignore).

用法::

    from ths_client import TradeClient

    # 方式1: 显式传参
    cli = TradeClient(zjzh='12345678',
                      gdzh_sh='A123456789',   # 上海股东号 (A开头)
                      gdzh_sz='0123456789')   # 深圳股东号 (数字)

    # 方式2: 本地配置文件 (推荐; 文件不提交)
    #   local_profile.json:
    #   {"zjzh": "...", "gdzh_sh": "...", "gdzh_sz": "...", "name": "..."}
    cli = TradeClient.from_profile()          # 或 from_profile('D:/my/ths.json')

    cli.connect()
    cli.login()                # 问候 + 登录 (自动会话/IV)
    cli.bootstrap(include_sh=True)  # 启动序列 (标准+沪市)

    r = cli.precheck('601398', qty=100)     # 0124 预检 (只读)
    print(r['text'])                        # 服务器应答文本
    r = cli.buy_market('601398', 100)       # 0221 市价买单 (真实委托!)
    print(r['text'])

流程顺序敏感 (实测): login -> bootstrap -> bootstrap_sh -> precheck -> buy/sell。
- 跳过 bootstrap: 业务消息回 "数据包无效：帐户无效"
- 沪市消息先于标准启动 / 顺序错误: 回错误甚至被服务端RST

风险提示: buy_market/sell_market 是真实委托指令, 会占用资金/成交。请自行控制风险。
"""
import json
import os
import re
from pathlib import Path
import socket
import struct
import time

from . import machine as _machine
from . import trade_conn as TC
from . import parse as _parse
from . import trade_msg as TM

__all__ = ['TradeClient', 'load_profile', 'parse_kv']


def load_profile(path: str = None) -> dict:
    """加载本地账号配置 (不提交仓库)。

    查找顺序: 显式path > 环境变量 THS_PROFILE > ./local_profile.json
              > ~/.ths_trade_profile.json
    返回 dict: zjzh / gdzh_sh / gdzh_sz / name (缺省键用占位值)。
    """
    cands = []
    if path:
        cands.append(path)
    if os.environ.get('THS_PROFILE'):
        cands.append(os.environ['THS_PROFILE'])
    cands.append('local_profile.json')
    cands.append(os.path.join(os.path.expanduser('~'), '.ths_trade_profile.json'))
    for c in cands:
        try:
            with open(c, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get('zjzh'):
                return data
        except (OSError, ValueError):
            continue
    return {}


class TradeClient:
    """柜台交易客户端。一个实例 = 一条柜台TCP连接。"""

    def __init__(self, zjzh: str, *, gdzh_sh: str = None, gdzh_sz: str = None,
                 name: str = '某某某', deptid=None, verinfo: str = None,
                 on_push=None, heartbeat: float = 30.0, push_handling: bool = True,
                 auto_reconnect: bool = True,
                 host: str = TC.COUNTER_HOST,
                 port: int = TC.COUNTER_PORT, timeout: float = 20.0,
                 hosts: list = None, machine_info: dict = None):
        """
        zjzh: 资金账号 (如 12345678)
        gdzh_sh/gdzh_sz: 沪/深股东号 (沪市A开头如A123456789; 深市数字如0123456789)
        name: 户名 (GBK, 须恰6字节)
        """
        self.zjzh = zjzh
        self.gdzh_sh = gdzh_sh
        self.gdzh_sz = gdzh_sz
        self.name = name
        self.deptid = deptid          # 营业部ID (None=模板默认1302)
        self.on_push = on_push            # 推送回调 fn(dict)
        self.heartbeat = heartbeat        # 心跳间隔秒 (0=关闭)
        self.push_handling = push_handling  # 是否启动读线程做应答/推送分流
        self.auto_reconnect = auto_reconnect
        self.verinfo = verinfo        # 券商标记 (None=模板默认gtja)
        self.hosts = hosts or []      # 备用站点 [{'ip','port'}...] 连接失败自动切换
        self.machine_info = machine_info  # 设备信息 (抓包提取; None=程序自行采集)
        if not (1 <= len(name.encode('gbk')) <= 6):
            raise ValueError('户名GBK须1~6字节: %r' % name)
        self.conn = TC.TradeConn(host=host, port=port, timeout=timeout)
        self.info = None          # login() 返回: {'sess','iv','s2c1'}
        self.startup_outs = []     # start() 启动应答缓存 (account_info/cached_query 用)
        self.seq = None           # 消息序号 (登录=1, 之后递增)
        self._tick_base = None    # (tick0, monotonic0)

    @classmethod
    def from_profile(cls, path: str = None, **kw):
        """从本地配置文件创建客户端 (文件不提交仓库)。

        local_profile.json 示例:
            {"zjzh": "12345678", "gdzh_sh": "A123456789",
             "gdzh_sz": "0123456789", "name": "某某某"}
        """
        prof = load_profile(path)
        if not prof.get('zjzh'):
            raise FileNotFoundError(
                '未找到账号配置: 请创建 local_profile.json 或用 TradeClient(zjzh=...) 传参')
        if prof.get('host'):
            kw.setdefault('host', prof['host'])
        if prof.get('port'):
            kw.setdefault('port', int(prof['port']))
        if prof.get('hosts'):
            kw.setdefault('hosts', prof['hosts'])
        if prof.get('machine'):
            kw.setdefault('machine_info', prof['machine'])
        return cls(zjzh=prof['zjzh'], gdzh_sh=prof.get('gdzh_sh'),
                   gdzh_sz=prof.get('gdzh_sz'), name=prof.get('name', '某某某'),
                   deptid=prof.get('deptid'), verinfo=prof.get('verinfo'), **kw)

    # ---------------- 连接/登录 ----------------
    def connect(self, bind_port: int = 0, dump_dir: str = None):
        """建立TCP连接 (按 host -> hosts 顺序尝试, 失败自动切换站点)。"""
        cands = [(self.conn.host, self.conn.port)]
        for h in self.hosts:
            ip, port = (h.get('ip'), h.get('port')) if isinstance(h, dict) else tuple(h)
            if ip and (ip, int(port)) not in cands:
                cands.append((ip, int(port)))
        last = None
        for ip, port in cands:
            self.conn.host, self.conn.port = ip, port
            try:
                self.conn.connect(bind_port=bind_port, dump_dir=dump_dir)
                self.host_used = (ip, port)
                return self
            except OSError as e:
                last = e
        raise last if last else OSError('无可用站点')

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def login(self) -> dict:
        """问候 + 登录。成功后 self.info/self.seq/tick 就绪。

        on_push 不为 None 时自动启动后台读线程 (推送/应答分流);
        heartbeat>0 时同时启动心跳 (默认30秒, 与真客户端一致)。
        """
        self.conn.greeting()                       # 包内 hello.bin 原样重放
        lip = self._local_ip()
        lport = self.conn.sock.getsockname()[1]
        pt = bytearray(TM.build_login(login_zh=self.zjzh, local_ip=lip, localport=lport,
                                       server_ip=self.conn.host, name=self.name,
                                       deptid=self.deptid, verinfo=self.verinfo))
        _machine.patch(pt, info=self.machine_info)   # 设备信息 (配置优先, 否则自采集)
        self.info = self.conn.login(bytes(pt))
        self.seq = TM.MsgSeq(2)                    # 登录已用 seq=1
        tick0 = struct.unpack('<I', pt[0x88:0x8c])[0]
        self._tick_base = (tick0, time.monotonic())
        if self.on_push is not None or self.push_handling:
            self.conn.start_reader(on_push=self.on_push)
        if self.heartbeat:
            self.conn.start_heartbeat(self.heartbeat)
        return self.info

    def start(self) -> dict:
        """一步到位: connect + login + bootstrap(标准+沪市)。返回 login info。

        推荐用法: cli = TradeClient.from_profile(); cli.start()
        之后即可 precheck/buy_market/sell_market。"""
        self.connect()
        info = self.login()
        self.startup_outs = self.bootstrap(include_sh=True)
        return info

    # ---------------- 推送/心跳/重连 ----------------
    def wait_pushes(self, timeout: float = 1.0) -> list:
        """等待并返回待处理推送列表 (成交回报/行情推送, 见 trade_conn 读线程)。

        推送为 zlib 明文 k=v, 常用键:
          zqdm 证券代码 / zqmc 证券名称 / zg j最高 / zdj最低 / open 开盘
          cjje 成交金额 / cjl 成交量 / ywzt 业务状态 / zrlx 转让类型 / statusflag 状态标志
        """
        return self.conn.wait_pushes(timeout)

    @property
    def pushes(self):
        """最近收到的推送 (deque, 最多 push_max 条)。"""
        return self.conn.pushes

    def alive(self) -> bool:
        """连接是否健康 (读线程未报错)。"""
        return not self.conn._reader_err

    def reconnect(self) -> dict:
        """断线重连: 重新 connect + login + bootstrap, 返回 login info。"""
        try:
            self.conn.stop_reader()
            self.conn.stop_heartbeat()
        except Exception:
            pass
        self.connect()
        info = self.login()
        self.startup_outs = self.bootstrap(include_sh=True)
        return info

    def request(self, fn, *args, **kw):
        """带自动重连的请求执行: 断线时重连一次并重试。

        用法: cli.request(cli.buy_market, '601398', 100)
        """
        try:
            return fn(*args, **kw)
        except (ConnectionError, OSError, TimeoutError, RuntimeError) as e:
            if not self.auto_reconnect:
                raise
            self.reconnect()
            return fn(*args, **kw)

    def _local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.conn.host, self.conn.port))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return socket.gethostbyname(socket.gethostname())

    def tick(self) -> int:
        """会话内单调毫秒 (延续登录帧 tick)。"""
        t0, m0 = self._tick_base
        return (t0 + int((time.monotonic() - m0) * 1000)) & 0xFFFFFFFF

    # ---------------- 启动序列 ----------------
    def bootstrap(self, include_sh: bool = False) -> list:
        """标准启动序列 (0030/0526/0126/0326/0226); include_sh=True 时追加沪市组。
        返回应答列表 [(wire_cmd, resp), ...]。"""
        outs = self.conn.bootstrap(self.info['iv'], seq=self.seq, tick=self.tick(),
                                   zjzh=self.zjzh, gdzh_sh=self.gdzh_sh,
                                   gdzh_sz=self.gdzh_sz,
                                   name_gbk=self.name.encode('gbk'),
                                   deptid=self.deptid, verinfo=self.verinfo,
                                   machine_info=self.machine_info)
        if include_sh:
            outs += self.bootstrap_sh()
        return outs

    def bootstrap_sh(self) -> list:
        """沪市扩展启动 (0029 get_wtcl_list / 0520 / 0126 / 0326 / 0226)。
        沪市下单前必须执行。"""
        return self.conn.bootstrap(self.info['iv'], seq=self.seq, tick=self.tick(),
                                   tpl_dir=TC.STARTUP_SH_DIR, zjzh=self.zjzh,
                                   gdzh_sh=self.gdzh_sh, gdzh_sz=self.gdzh_sz,
                                   name_gbk=self.name.encode('gbk'),
                                   deptid=self.deptid, verinfo=self.verinfo,
                                   machine_info=self.machine_info)

    # ---------------- 业务 ----------------
    def _gdzh_for(self, market: str) -> str:
        g = self.gdzh_sh if market == '2' else self.gdzh_sz
        if not g:
            raise ValueError('未配置股东号: market=%s (沪="2" 深="1")' % market)
        return g

    def _send_recv(self, wire_cmd: bytes, pt: bytes, accept_push: str = None) -> dict:
        self.conn.send_msg(wire_cmd, pt, self.info['iv'])
        r = self.conn.recv_msg(accept_push=accept_push)
        text = r['plaintext'].decode('gbk', 'replace').replace('\x00', '')
        out = {'type': r['type'], 'plaintext': r['plaintext'], 'text': text}
        if r.get('via_push'):
            # 盘中预检走 0x50 推送通道: 补上 kv 便于直接取行情
            out['via_push'] = True
            out['kv'] = parse_kv(r['plaintext'].decode('gbk', 'replace'))
        return out

    def precheck(self, code: str, qty: int = 100, market: str = None) -> dict:
        """0124 预检 (只读)。返回 {'type','plaintext','text'}。"""
        market = market or TM.guess_market(code)
        if market == '2':
            pt = TM.build_precheck_sh(code, qty, sess=self.info['sess'], zjzh=self.zjzh,
                                      gdzh=self._gdzh_for(market), seq=self.seq,
                                      tick=self.tick())
        else:
            pt = TM.build_precheck(code, sess=self.info['sess'], zjzh=self.zjzh,
                                   gdzh=self._gdzh_for(market), market=market,
                                   seq=self.seq, tick=self.tick())
        return self._send_recv(TM.WIRE_CMD['precheck'][1], pt, accept_push=code)

    def buy_market(self, code: str, qty: int, sjwt: int = None, market: str = None,
                   zxjg: float = None) -> dict:
        """0221 市价买单 (真实委托!)。支持沪市(市场'2')和深市(市场'1')。

        sjwt: 市价策略码 (缺省: 沪市4=五档即成剩撤 / 深市2=对手方最优, 均实测默认)
              沪: 见 trade_msg.SJWT_SH; 深: 见 trade_msg.SJWT_SZ
        zxjg: 盘口参考价 (缺省用 precheck 应答的 open, 再兜底模板值)
        """
        market = market or TM.guess_market(code)
        if sjwt is None:
            sjwt = 4 if market == '2' else 2
        if zxjg is None:
            try:
                r = self.precheck(code, qty, market=market)
                m = re.search(r'open=([0-9.]+)', r['text'])
                zxjg = float(m.group(1)) if m else None
            except Exception:
                zxjg = None
        if market == '2':
            pt = TM.build_buy_sh_sjwt(code, qty, sess=self.info['sess'], zjzh=self.zjzh,
                                      gdzh=self._gdzh_for(market), zxjg=zxjg or 10.0,
                                      sjwt=sjwt, name_gbk=self.name.encode('gbk'),
                                      seq=self.seq, tick=self.tick())
        elif market == '1':
            pt = TM.build_buy_sz_sjwt(code, qty, sess=self.info['sess'], zjzh=self.zjzh,
                                      gdzh=self._gdzh_for(market), zxjg=zxjg,
                                      sjwt=sjwt, name_gbk=self.name.encode('gbk'),
                                      seq=self.seq, tick=self.tick())
        else:
            raise ValueError("market 须为 '2'(沪) 或 '1'(深)")
        return self._send_recv(TM.WIRE_CMD['buy'][1], pt)

    def sell_market(self, code: str, qty: int, sjwt: int = None, market: str = None,
                    zxjg: float = None, bhjg: float = None) -> dict:
        """0321 市价卖单 (真实委托!)。支持沪市(市场'2')和深市(市场'1')。

        sjwt: 市价策略码 (缺省: 沪市4=五档即成剩撤 / 深市2=对手方最优, 均实测默认)
        zxjg: 盘口参考价 (缺省用 precheck 应答的 open, 再兜底模板值)
        bhjg: 保护限价 (仅沪市; 缺省=zxjg。深市模板固定 bhjg=-1, 忽略此参数)
        注: 卖出需账户持有该证券, 否则服务端回 "当前账户暂未持仓该证券！"
        """
        market = market or TM.guess_market(code)
        if sjwt is None:
            sjwt = 4 if market == '2' else 2
        if zxjg is None:
            try:
                r = self.precheck(code, qty, market=market)
                m = re.search(r'open=([0-9.]+)', r['text'])
                zxjg = float(m.group(1)) if m else None
            except Exception:
                zxjg = None
        if market == '2':
            pt = TM.build_sell_sh_sjwt(code, qty, sess=self.info['sess'], zjzh=self.zjzh,
                                       gdzh=self._gdzh_for(market), zxjg=zxjg or 10.0,
                                       bhjg=bhjg, sjwt=sjwt, name_gbk=self.name.encode('gbk'),
                                       seq=self.seq, tick=self.tick())
        elif market == '1':
            pt = TM.build_sell_sz_sjwt(code, qty, sess=self.info['sess'], zjzh=self.zjzh,
                                       gdzh=self._gdzh_for(market), zxjg=zxjg,
                                       sjwt=sjwt, name_gbk=self.name.encode('gbk'),
                                       seq=self.seq, tick=self.tick())
        else:
            raise ValueError("market 须为 '2'(沪) 或 '1'(深)")
        return self._send_recv(TM.WIRE_CMD['sell'][1], pt)

    def limit_order(self, code: str, qty: int, price: float, is_sell: bool = False,
                    market: str = None) -> dict:
        """限价委托 (真实委托!)。沪市/深市, 买/卖均支持 (四组合实测模板)。

        price: 限价 (>0)。挂单成功需资金/持仓足够, 否则柜台回"资金不足"/"暂未持仓"。
        """
        market = market or TM.guess_market(code)
        pt = TM.build_limit(code, qty, price, is_sell=is_sell, market=market,
                            sess=self.info['sess'], zjzh=self.zjzh,
                            gdzh=self._gdzh_for(market),
                            name_gbk=self.name.encode('gbk'),
                            seq=self.seq, tick=self.tick())
        cmd = TM.WIRE_CMD['sell'][1] if is_sell else TM.WIRE_CMD['buy'][1]
        return self._send_recv(cmd, pt)

    # ---------------- 查询 (持仓/委托/成交) ----------------
    def _parse_query_resp(self, r: dict) -> dict:
        """解析查询应答 (hd1.0 记录区 + 列名 + 行标签 + 会话统计)。"""
        d = _parse.parse_hd10(r['plaintext'])
        r = dict(r)
        r['columns'] = d['columns'] or _gbk_runs(r['plaintext'])
        r['rows'] = d['rows']
        r['fields'] = d['fields']
        r['count'] = d['count']
        r['stats'] = d['stats']
        r['ok'] = bool(r['fields'])
        return r

    def _send_query(self, pt: bytes, wire: bytes) -> dict:
        """发送查询报文并解析应答 (统一出口)。"""
        return self._parse_query_resp(self._send_recv(wire, pt))

    def _tpl_query(self, tpl_code: str, market: str, *, date: str = None,
                   page_roll: int = None, dataid: str = None, menuid: int = None,
                   tick: int = None) -> bytes:
        """构造查询报文 (基于启动序列模板; 可选补 date/page_roll/dataid/menuid 字段)。

        date: 交易日期 YYYYMMDD (补 jzrq/qsrq 两字段); page_roll: 分页号;
        dataid: 数据标识 (H=沪 S=深 等); menuid: 菜单号。
        """
        import glob
        tpl_dir = TC.STARTUP_SH_DIR if market == '2' else TC.STARTUP_DIR
        fs = glob.glob(str(Path(tpl_dir) / ('*_' + tpl_code + '_*.bin')))
        if not fs:
            raise FileNotFoundError('缺少查询模板 %s (market=%s)' % (tpl_code, market))
        pt = bytearray(Path(fs[0]).read_bytes())
        TM.patch_account(pt, zjzh=self.zjzh, gdzh_sh=self.gdzh_sh,
                         gdzh_sz=self.gdzh_sz, name_gbk=self.name.encode('gbk'))
        TM.patch_broker(pt, deptid=self.deptid, verinfo=self.verinfo)
        _machine.patch(pt, info=self.machine_info)
        pt[0x02:0x06] = self.info['sess']
        struct.pack_into('<I', pt, 0x88, tick if tick is not None else self.tick())
        struct.pack_into('<I', pt, 0x8c, self.seq.next())
        extra = {}
        if date:
            extra['jzrq'] = extra['qsrq'] = date
        if page_roll is not None:
            extra['page_roll'] = str(int(page_roll))
        if dataid:
            extra['dataid'] = dataid
        if menuid is not None:
            extra['menuid'] = str(int(menuid))
        if extra:
            tail = bytes(pt[0x12b:])
            pt = bytearray(bytes(pt[:0x12b]) + tail +
                           ''.join('%s=%s\n' % kv for kv in extra.items()).encode('gbk'))
        pt[8:24] = TM._sign(bytes(pt))
        return bytes(pt)

    def cached_query(self, kind: str) -> dict:
        """读取 start() 启动序列中已收到的同类应答 (不发请求)。

        kind: 'positions'(0126持仓) / 'orders'(0326委托) / 'trades'(0226成交) /
              'account'(0526账户) / 'menus'(0029菜单)
        背景: 柜台对 0326/0226 有会话状态限制, 单独重放会回"无效请求";
        但启动序列里的应答是完整数据 (如 0326 应答含委托序号/数量/价格列)。
        """
        prefix = {'positions': bytes([1, 0x26]), 'orders': bytes([3, 0x26]),
                  'trades': bytes([2, 0x26]), 'account': bytes([5, 0x26]),
                  'menus': bytes([0, 0x29])}.get(kind)
        if prefix is None:
            raise ValueError("kind 须为 positions/orders/trades/account/menus")
        for wire, r in (self.startup_outs or []):
            if not isinstance(r, dict) or 'plaintext' not in r:
                continue
            if bytes(r.get('wire', wire))[:2] == prefix:
                out = self._parse_query_resp(r)
                out['from_cache'] = True
                return out
        return {}

    def query_balance(self, market: str = None, date: str = None, menuid: int = 471,
                      dataid: str = None, page_roll: int = 1, both_markets: bool = False):
        """查询资金明细/余额 (0226 资金查询模板, 真客户端实测 552B)。

        market: '2'=沪 '1'=深 (缺省 '2'; both_markets=True 时查两市并合并)
        date: 交易日期 YYYYMMDD (缺省今天; 非交易日可传上一交易日)
        menuid / dataid / page_roll: 查询上下文 (dataid 缺省按 market 取 H=沪/S=深)
        返回: {'ok','columns','rows','fields','count','stats','plaintext','text','labels'};
              both_markets=True 时额外含 'markets': {'2': {...}, '1': {...}}
        """
        mkts = ['2', '1'] if both_markets else [market or '2']
        out = {}
        for mk in mkts:
            pt = TM.build_funds_query(sess=self.info['sess'], zjzh=self.zjzh,
                                      gdzh=self._gdzh_for(mk), market=mk, date=date,
                                      dataid=dataid, page_roll=page_roll, menuid=menuid,
                                      name_gbk=self.name.encode('gbk'),
                                      seq=self.seq, tick=self.tick())
            r = self._send_query(pt, TM.WIRE_CMD['qry_funds'][1])
            r['labels'] = [x for x in r['rows'] if x in (
                '可用', '可取', '可用金额', '可取金额', '市值', '冻结市值',
                '冻结金额', '总资产', '本币', '港币', '美币')]
            out[mk] = r
        if both_markets:
            first = out[mkts[0]]
            first['markets'] = out
            return first
        return out[mkts[0]]

    def query_positions(self, market: str = None, date: str = None, page_roll: int = None,
                        dataid: str = None, menuid: int = None) -> dict:
        """查询持仓/股票余额 (0126)。

        market: '2'=沪(默认, 需已 bootstrap_sh) '1'=深
        date / page_roll / dataid / menuid: 可选查询上下文 (缺省用启动模板原值)
        返回: {'ok','columns','rows','fields','count','stats','plaintext','text'}
        """
        market = market or '2'
        pt = self._tpl_query('0126', market, date=date, page_roll=page_roll,
                             dataid=dataid, menuid=menuid)
        r = self._send_query(pt, TM.WIRE_CMD['qry_positions'][1])
        if not r['ok']:
            c = self.cached_query('positions')
            if c:
                return c
        return r

    def query_orders(self, market: str = None, date: str = None, page_roll: int = None,
                     dataid: str = None, menuid: int = None) -> dict:
        """查询当日委托 (0326)。参数同 query_positions。

        柜台对 0326 有会话状态限制 (单独重放回"无效请求"), 失败时自动回退到
        start() 启动序列中已收到的完整应答 (结果带 from_cache=True)。
        """
        market = market or '2'
        pt = self._tpl_query('0326', market, date=date, page_roll=page_roll,
                             dataid=dataid, menuid=menuid)
        r = self._send_query(pt, TM.WIRE_CMD['qry_orders'][1])
        if not r['ok']:
            c = self.cached_query('orders')
            if c:
                return c
        return r

    def query_trades(self, market: str = None, date: str = None, page_roll: int = None,
                     dataid: str = None, menuid: int = None) -> dict:
        """查询当日成交 (0226)。参数同 query_positions; 失败时回退启动缓存。"""
        market = market or '2'
        pt = self._tpl_query('0226', market, date=date, page_roll=page_roll,
                             dataid=dataid, menuid=menuid)
        r = self._send_query(pt, TM.WIRE_CMD['qry_trades'][1])
        if not r['ok']:
            c = self.cached_query('trades')
            if c:
                return c
        return r

    def account_info(self) -> dict:
        """账户信息 (解析启动序列 0526 应答): 各市场股东号 + 资金账号。

        数据取自 start() 期间的 0526 应答缓存, 不发额外请求。
        例: {'上海A股': 'A****20202', '深圳A股': '0********4', 'zjzh': '1*******4'}
        """
        acct = {}
        for wire, r in (self.startup_outs or []):
            if not isinstance(r, dict) or 'plaintext' not in r:
                continue
            t = r['plaintext'].decode('gbk', 'replace')
            if '上海A股' not in t and '深圳A股' not in t:
                continue
            for mk in ('上海A股', '深圳A股'):
                for m in re.finditer(re.escape(mk), t):
                    seg = t[max(0, m.start() - 150):m.start()]
                    cands = re.findall(r'([0-9]{10}|[A-Z][0-9]{9})', seg)
                    if cands:
                        acct.setdefault(mk, cands[-1])
        acct['zjzh'] = self.zjzh
        return acct

    def market_options(self) -> dict:
        """柜台支持的委托类型选项 (解析 0526 应答)。

        返回 {'对手方最优': 出现次数, '五档即成剩撤': ..., ...}; 空 dict 表示未取到。
        """
        names = ('对手方最优', '本方最优', '五档即成剩撤', '五档即成剩转限', '即成剩撤',
                 '全额成交或撤', '盘后定价委托', '限价', '市价', '最优五档')
        out = {}
        for wire, r in (self.startup_outs or []):
            if not isinstance(r, dict) or 'plaintext' not in r:
                continue
            t = r['plaintext'].decode('gbk', 'replace')
            for n in names:
                c = t.count(n)
                if c:
                    out[n] = out.get(n, 0) + c
        return out

    def query_all(self, market: str = None, date: str = None) -> dict:
        """一次性拉取 持仓+委托+成交+资金 (同一市场), 返回分项 dict。

        单项失败不抛异常, 失败项为 {'ok': False, 'error': ...}。
        """
        market = market or '2'
        out = {}
        for name, fn in (('positions', self.query_positions), ('orders', self.query_orders),
                         ('trades', self.query_trades), ('balance', self.query_balance)):
            try:
                out[name] = fn(market=market, date=date)
            except Exception as e:
                out[name] = {'ok': False, 'error': repr(e)}
        return out

    # ---------------- 低层逃生口 ----------------
    def send(self, wire_cmd: bytes, plaintext: bytes) -> dict:
        """发送任意已构造明文 (需自行保证 md5签名/字段正确)。"""
        return self._send_recv(wire_cmd, plaintext)

    def recv(self) -> dict:
        """接收一帧 (不发送)。"""
        r = self.conn.recv_msg()
        return {'type': r['type'], 'plaintext': r['plaintext'],
                'text': r['plaintext'].decode('gbk', 'replace').replace('\x00', '')}


def _gbk_runs(pt: bytes, min_bytes: int = 4) -> list:
    """提取明文中的GBK文本串 (查询应答的列名表等)。"""
    out = []
    for m in re.finditer(rb'(?:[\xa1-\xfe]{2}){%d,}' % (min_bytes // 2), pt):
        try:
            out.append(m.group().decode('gbk'))
        except Exception:
            pass
    return out


def parse_kv(text: str) -> dict:
    """从应答文本提取 key=value (以 & 或换行分隔)。"""
    out = {}
    for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)=([^&\n]*)', text):
        out[m.group(1)] = m.group(2)
    return out
