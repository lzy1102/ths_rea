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
        self.verinfo = verinfo        # 券商标记 (None=模板默认gtja)
        self.hosts = hosts or []      # 备用站点 [{'ip','port'}...] 连接失败自动切换
        self.machine_info = machine_info  # 设备信息 (抓包提取; None=程序自行采集)
        if not (1 <= len(name.encode('gbk')) <= 6):
            raise ValueError('户名GBK须1~6字节: %r' % name)
        self.conn = TC.TradeConn(host=host, port=port, timeout=timeout)
        self.info = None          # login() 返回: {'sess','iv','s2c1'}
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
        """问候 + 登录。成功后 self.info/self.seq/tick 就绪。"""
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
        return self.info

    def start(self) -> dict:
        """一步到位: connect + login + bootstrap(标准+沪市)。返回 login info。

        推荐用法: cli = TradeClient.from_profile(); cli.start()
        之后即可 precheck/buy_market/sell_market。"""
        self.connect()
        info = self.login()
        self.bootstrap(include_sh=True)
        return info

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

    def _send_recv(self, wire_cmd: bytes, pt: bytes) -> dict:
        self.conn.send_msg(wire_cmd, pt, self.info['iv'])
        r = self.conn.recv_msg()
        text = r['plaintext'].decode('gbk', 'replace').replace('\x00', '')
        return {'type': r['type'], 'plaintext': r['plaintext'], 'text': text}

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
        return self._send_recv(TM.WIRE_CMD['precheck'][1], pt)

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
    def _query(self, tpl_code: str, market: str = None) -> dict:
        """发送查询模板(0126持仓/0326委托/0226成交)并返回应答。

        返回 {'type','plaintext','text'} + 'columns'(GBK列名) + 'stats'(SX=...统计)。
        注: 记录体为客户端 hd1.0 二进制格式, 结构化解码待后续版本。
        """
        import glob
        market = market or '2'
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
        struct.pack_into('<I', pt, 0x88, self.tick())
        struct.pack_into('<I', pt, 0x8c, self.seq.next())
        pt[8:24] = TM._sign(bytes(pt))
        wire = bytes([pt[6], pt[7] | 0x20])
        r = self._send_recv(wire, bytes(pt))
        r['columns'] = _gbk_runs(r['plaintext'])
        m = re.search(r'SX=[^&]*(?:&[A-Z_]+=[^&\n]*)+', r['text'])
        r['stats'] = parse_kv(m.group(0)) if m else {}
        return r

    def query_positions(self, market: str = None) -> dict:
        """查询持仓/股票余额 (0126)。market: '2'=沪(默认) '1'=深。"""
        return self._query('0126', market)

    def query_orders(self, market: str = None) -> dict:
        """查询当日委托 (0326)。market: '2'=沪(默认) '1'=深。"""
        return self._query('0326', market)

    def query_trades(self, market: str = None) -> dict:
        """查询当日成交 (0226)。market: '2'=沪(默认) '1'=深。"""
        return self._query('0226', market)

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
