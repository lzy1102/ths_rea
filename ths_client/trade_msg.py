# -*- coding: utf-8 -*-
"""交易明文构造器 (模板+补丁).

明文结构 (0221买单, ~570B):
  [0:2]=fd ff  [2:6]=sess4 (登录帧=00 00 00 00; 登录后=服务器分配4字节, 如 84 7a cf ff)
  [6:8]=内部cmd (买单 02 01; 线缆cmd = byte2|0x20 -> 02 21)
  [8:24]=MD5签名槽 = md5(明文整体, 其中[8:24]清零)  ← _sign(), 服务端"验证签名"校验
  [24:136]=0
  [0x88:0x8c]=u32 tick_ms (会话内单调, 延续登录帧tick)  [0x8c:0x90]=u32 msg_seq (登录=1)
  [0x90:0xa0]=zjzh(16B槽)  [0xa0:0xb0]="575566"(保留)
  [0xc0:0xd0]=zjzh(8B)  [0xdb:]="DP130"(保留)
  [0x100:0x106]=户名GBK(6B)  [0x106]=00
  [0x107:0x10b]=".16\\0"(保留)  [0x10b]=市场(1B)  [0x10c:0x112]=代码(6B)
  [0x112]=00  [0x113:0x117]=价格float32LE  [0x117:0x11b]=数量int32LE
  [0x11b:0x12b]=gdzh(16B槽, 10字符+零)
  [0x12b:]=换行分隔文本表 (ND/count/client/lxfs/sell1price/index/workid/
    req_start_tickcount/clientver/xd_djpp/zjzh/buy1price/interact/confirm/
    solicited/wtjg/name/kernelver/type/plwt/wtsl/menuid/scdm), 以 scdm=N换行结尾

0124预检 (483B): 头部内部cmd 01 04 (线缆 01 24); 二进制段布局与买单同构
  (market前缀字节恒00, 无价格/数量浮点, 其余同), 文本表字段:
  ND/client/czlb/sblx/zqdm/clientver/zjzh/risk_check/kyye/cdxx/wtjg/gdzh/kernelver/type/menuid/scdm
  (wtjg 恒 0.000 —— 预检不带价格)

登录帧 (1132B): 内部cmd 10 00; sess4=00000000; [8:24]为随机数(不用md5);
  文本表含 localip/publicip/localport (须与实际连接一致).

市场映射 (实测真客户端 600398 市价买单: '2'=上海 [gdzh A开头, 如A123456789];
  '1'=深圳 [gdzh 数字, 如0123456789]):
  代码 6/9/51/58 开头 -> '2'(沪); 0/3/2 开头 -> '1'(深); 其他需显式指定。
市价单 (SH实测): price float=-1.0, 文本 wtjg=-1 + sjwt=4(五档即成剩撤) + type=sjwt;
  zxjg/sell1price/buy1price/bhjg = 盘口参考价。
"""
import base64
import hashlib
import os
import re
import struct
import time

_TPL = {
'buy': '/f91ecD/AgHhRvfXMbv6e5dZKMc7x3RpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHx75wALAAAAMTIzNDU2NzgAAAAAAAAAADU3NTU2NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAAAAMSzxLPEswAuMTYAMTk5OTk5OAAAAMhCZAAAADAxMjM0NTY3ODkAAAAAAABORD0xLjAKY291bnQ9MQpjbGllbnQ9ZXhlCmx4ZnM9CnNlbGwxcHJpY2U9CmluZGV4PTEKd29ya2lkPTMKcmVxX3N0YXJ0X3RpY2tjb3VudD0zMTEyMDM0MwpjbGllbnR2ZXI9RTA2NS41OC4xNi4yODQKeGRfZGpwcD0wCnpqemg9MTIzNDU2NzgKYnV5MXByaWNlPQppbnRlcmFjdD0xCmNvbmZpcm09MApzb2xpY2l0ZWQ9MAp3dGpnPTEwMC4wMDAwMDAKbmFtZT0Ka2VybmVsdmVyPTUuNTguMTYuMjg0CnR5cGU9cHR3dApwbHd0PTAKd3RzbD0xMDAKbWVudWlkPTE2MQpzY2RtPTEK',
'chk': '/f91ecD/AQQQ98gQY5NdACEl0MoyYrS/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHB75wAKAAAAMTIzNDU2NzgAAAAAAAAAADU3NTU2NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAAgAMSzxLPEswAuMTYAADk5OTk5OAAAAAAAIQAAADAxMjM0NTY3ODkAAAAAAABORD0xLjAKY2xpZW50PWV4ZQpjemxiPUIKc2JseD0KenFkbT05OTk5OTgKY2xpZW50dmVyPUUwNjUuNTguMTYuMjg0Cnpqemg9MTIzNDU2NzgKcmlza19jaGVjaz0xCmt5eWU9CmNkeHg9MDAwMAp3dGpnPTAuMDAwCmdkemg9MDEyMzQ1Njc4OQprZXJuZWx2ZXI9NS41OC4xNi4yODQKdHlwZT0KbWVudWlkPTE2MQpzY2RtPTEK',
'login': '/f8AAAAAEAB44vHDrf9d3gtnxes485ViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK9T5gABAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAAgAEUwNjUuNTguMTYAIAAAAAAAAAAAAAAAAUBwgAAAAAAAAAAAAAAAAAAAAABORD0xLjAKY2xpZW50PWV4ZQpoYXJkd2FyZWNvZGU9QklPUzowMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCxIREQ6MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEsTUFDOjAwOjAwOjAwOjAwOjAwOjAwLFBJOkNeTlRGU14yMDBHLFZPTDowMDAwLTAwMDAsVk9MTkFNRTpMaW1pdHNPZkF1dGhvcml0eQpjcHVpbmZvPUludGVsKFIpIENvcmUoVE0pIGk1LTAwMDBVIENQVSBAIDIuMzBHSHoKbG9jYWxpcD0xOTJfMTY4XzBfMQpwdWJsaWNpcD0xOTJfMTY4XzBfMQpsb2dpbl96aD0xMjM0NTY3OApoZGRpbmZvPVlTWFhYWFhYWFhYWAptYWNpbmZvPTAwOjAwOjAwOjAwOjAwOjAwXjAwOjAwOjAwOjAwOjAwOjAzXjAwOjAwOjAwOjAwOjAwOjAxXjAwOjAwOjAwOjAwOjAwOjAyCmNvbXB1dGVybmFtZT1ERVNLVE9QLVhYWFhYWFgKbWVudV92ZXI9CmF1dGhjb2RlPTEKbG9jYWxwb3J0PTQ1NTE1CnZlcmluZm89Z3RqYQpjbGllbnR2ZXI9RTA2NS41OC4xNi4yODQKYmlvc19kYXRlPTIwMTUwNTIxCnNlcnZlcmlwPTExNC4xNDEuMTgwLjI3CmNfc3VwcG9ydD0xMTExMTExMTExMTExCmNyeXB0X25hbWU9QUMKY2xpZW50dmVyMj0KbWVudV9hbGw9Nzk5NTA2NDA0CnZpcnR1YWw9TEVOT1ZPCm1lbnVfYWRkPTMwNTA3MjkwNTYKY3B1aWQ9QkZFQkZCRkYwMDAzMDZENApkeW5wd2Q9Cmtlcm5lbHZlcj01LjU4LjE2LjI4NApkZXB0aWQ9MTMwMgpnZG1tPQpndWlkPXswMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDB9CmNsaWVudG5hbWU9zfjJz7270tfW97PM0PIKbWVudWlkPTAKc2NkbT0KbG9naW5fcGF0dGVybj0wCnZvbD0wMDAwLTAwMDAK',
'buy_sh': '/f9DhM//AgG+MY19mtrz/ERbVhfCyw4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJdd9gASAAAAMTIzNDU2NzgAAAAAAAAAADU3NTU2NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAARAMSzxLPEswAuMTYAMjYwMDM5OAAAAIC/ZAAAAEExMjM0NTY3ODkAAAAAAABORD0xLjAKY291bnQ9MQpjbGllbnQ9ZXhlCnp4amc9Ni41NTAKbHhmcz0Kc2VsbDFwcmljZT01Ljk5CmluZGV4PTEKY2RyX3R5cGU9MAp3b3JraWQ9MgpyZXFfc3RhcnRfdGlja2NvdW50PTEwOTk0NTQyMQpjbGllbnR2ZXI9RTA2NS41OC4xNi4yODQKeGRfZGpwcD0wCnpqemg9MTIzNDU2NzgKYnV5MXByaWNlPTUuOTkKYmhqZz02LjU1MDAwMAppbnRlcmFjdD0xCmNvbmZpcm09MApzb2xpY2l0ZWQ9MAp3dGpnPS0xCnNqd3Q9NApuYW1lPQprZXJuZWx2ZXI9NS41OC4xNi4yODQKdHlwZT1zand0CnBsd3Q9MAp3dHNsPTEwMAptZW51aWQ9NDcxCnNjZG09MgoAAA==',
'chk_sh': '/f9DhM//AQT/+7Xh5d8WYz2gpN8eRFFZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD1d9gANAAAAMTIzNDU2NzgAAAAAAAAAADU3NTU2NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAAgAMSzxLPEswAuMTYAADYwMDEzOQAAAAAALQAAAEExMjM0NTY3ODkAAAAAAABORD0xLjAKY2xpZW50PWV4ZQpjemxiPUIKc2JseD0KenFkbT02MDAxMzkKY2xpZW50dmVyPUUwNjUuNTguMTYuMjg0Cnpqemg9MTIzNDU2NzgKa3l5ZT0KY2R4eD0wMDAwCnNqd3Q9Tk9UX1NVUFBPUlQKd3RqZz0wLjAwMApnZHpoPUExMjM0NTY3ODkKa2VybmVsdmVyPTUuNTguMTYuMjg0CnR5cGU9Cm1lbnVpZD00NzEKc2NkbT0yCgA=',
'sell_sh': '/f8Dic//AwF9/X5h6P7f0o+72pCCBgp8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALWY9gAIAAAAMTIzNDU2NzgAAAAAAAAAADU3NTU2NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTIzNDU2NzgAAAAAAAAAAAAAAAAAAAAAAAAARFAxMzAAAAAAAAAAAAAAADIAAAAAAAAAAAAAAAAAAAAAAAARAMSzxLPEswAuMTYAMjYwMTM5OAAAAIC/ZAAAAEExMjM0NTY3ODkAAAAAAABORD0xLjAKY291bnQ9MQpjbGllbnQ9ZXhlCmx4ZnM9Cnp4amc9Ny42MzAKc2VsbDFwcmljZT04LjQ5CmluZGV4PTEKY2RyX3R5cGU9MAp3b3JraWQ9OQpyZXFfc3RhcnRfdGlja2NvdW50PTExNDI0MDIxOApjbGllbnR2ZXI9RTA2NS41OC4xNi4yODQKeGRfZGpwcD0wCnpqemg9MTIzNDU2NzgKYnV5MXByaWNlPTguNDgKYmhqZz03LjY1MDAwMAppbnRlcmFjdD0xCmNvbmZpcm09MApzb2xpY2l0ZWQ9MAp3dGpnPTcuNjUwMDAwCnNqd3Q9NApuYW1lPQprZXJuZWx2ZXI9NS41OC4xNi4yODQKdHlwZT1zand0CnBsd3Q9MAp3dHNsPTEwMAptZW51aWQ9NDcyCnNjZG09MgoAAAAA',

}

MARKET_SH = '2'   # 实测真客户端: 上海=2 (600398买单scdm=2+市场字节'2')
MARKET_SZ = '1'   # 深圳=1


def _tpl(name: str) -> bytearray:
    return bytearray(base64.b64decode(_TPL[name]))


def guess_market(code: str) -> str:
    """按代码前缀推断市场 (启发式; 不确定时显式传 market)。"""
    c = code.strip()
    if c[:1] in ('6', '9') or c[:2] in ('51', '58'):
        return MARKET_SH
    if c[:1] in ('0', '3', '2'):
        return MARKET_SZ
    raise ValueError("无法推断代码 %r 的市场, 请显式传入 market='1'(沪)/'2'(深)" % code)


def _patch(buf: bytearray, off: int, slot: int, val: bytes, name: str):
    if len(val) > slot:
        raise ValueError("%s过长: %d > 槽%d" % (name, len(val), slot))
    for i in range(slot):
        buf[off + i] = 0
    buf[off:off + len(val)] = val


def _retable(text: bytes, updates: dict) -> bytes:
    """按行 k=v 重建文本表 (保持原顺序, 未知键追加)。"""
    lines = text.decode('gbk').split('\n')
    out = []
    seen = set()
    for ln in lines:
        if not ln:
            continue
        k = ln.split('=', 1)[0]
        if k in updates:
            out.append(k + '=' + updates[k])
            seen.add(k)
        else:
            out.append(ln)
    for k, v in updates.items():
        if k not in seen:
            out.append(k + '=' + v)
    return ('\n'.join(out) + '\n').encode('gbk')


def _tick_ms() -> int:
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


def _sign(pt: bytes) -> bytes:
    """签名槽 [8:24] = md5(明文整体, 其中 [8:24] 清零)。
    实测: 新鲜会话 0030/0526/0126/0326/0226 五帧 + v3_0124 模板全部吻合。
    登录帧不用此签名 (登录时槽内为随机数, 服务端不校验)。"""
    return hashlib.md5(pt[:8] + bytes(16) + pt[24:]).digest()


# 模板内嵌的占位账号 (仓库脱敏): 运行时用真实配置值替换
PH_ZJZH = '12345678'
PH_GDZH_SH = 'A123456789'
PH_GDZH_SZ = '0123456789'
PH_NAME = '某某某'


def patch_broker(pt: bytearray, deptid=None, verinfo: str = None) -> bytearray:
    """替换券商/营业部级字段 (登录+0030模板内; 换券商/营业部时配置)。

    deptid: 营业部ID (默认1302); verinfo: 券商标记 (默认gtja=国泰君安/国泰海通)。
    换其他券商时需按该券商重新抓包确认取值。
    """
    if len(pt) <= 0x12b:
        return pt
    tail = bytes(pt[0x12b:])
    if deptid:
        tail = re.sub(rb'deptid=[^\n\x00]*', b'deptid=' + str(deptid).encode(), tail)
    if verinfo:
        tail = re.sub(rb'verinfo=[^\n\x00]*', b'verinfo=' + str(verinfo).encode(), tail)
    pt[0x12b:] = tail
    return pt


def patch_account(pt: bytearray, zjzh: str = None, gdzh_sh: str = None,
                  gdzh_sz: str = None, name_gbk: bytes = None) -> bytearray:
    """把模板中的占位账号字段替换为真实值 (原地修改, 返回同一对象)。

    - 二进制槽: zjzh@0x90/@0xc0(16B) 户名@0x100(6B) gdzh@0x11b(16B)
      (仅当槽内是占位符时才替换; 沪/深占位分别替换)
    - 文本区(0x12b起): zjzh=/gdxm=/gdzh=/login_zh= 等行
    - 须在 _sign() 之前调用 (签名覆盖最终内容)
    """
    if zjzh:
        z = zjzh.encode('gbk')
        for off in (0x90, 0xc0):
            if bytes(pt[off:off + 8]) == PH_ZJZH.encode():
                _patch(pt, off, 16, z, 'zjzh')
    if name_gbk:
        if bytes(pt[0x100:0x106]) == PH_NAME.encode('gbk'):
            _patch(pt, 0x100, 6, name_gbk, '户名')
    slot = bytes(pt[0x11b:0x11b + 10])
    if gdzh_sh and slot == PH_GDZH_SH.encode():
        _patch(pt, 0x11b, 16, gdzh_sh.encode(), 'gdzh_sh')
    elif gdzh_sz and slot == PH_GDZH_SZ.encode():
        _patch(pt, 0x11b, 16, gdzh_sz.encode(), 'gdzh_sz')
    if len(pt) > 0x12b:
        tail = bytes(pt[0x12b:])
        if zjzh:
            tail = tail.replace(b'zjzh=' + PH_ZJZH.encode(), b'zjzh=' + zjzh.encode('gbk'))
            tail = tail.replace(b'login_zh=' + PH_ZJZH.encode(), b'login_zh=' + zjzh.encode('gbk'))
        if name_gbk:
            tail = tail.replace(b'gdxm=' + PH_NAME.encode('gbk'), b'gdxm=' + name_gbk)
            tail = tail.replace(b'clientname=' + PH_NAME.encode('gbk'), b'clientname=' + name_gbk)
        if gdzh_sh:
            tail = tail.replace(b'gdzh=' + PH_GDZH_SH.encode(), b'gdzh=' + gdzh_sh.encode())
        if gdzh_sz:
            tail = tail.replace(b'gdzh=' + PH_GDZH_SZ.encode(), b'gdzh=' + gdzh_sz.encode())
        pt[0x12b:] = tail
    return pt


class MsgSeq:
    """消息序号 (二进制+0x8c)。实测会话内递增; 新连接从1开始。"""
    def __init__(self, start: int = 1):
        self.n = start

    def next(self) -> int:
        v = self.n
        self.n += 1
        return v


def build_buy(code: str, price: float, qty: int, *, sess: bytes, zjzh: str,
              gdzh: str, name_gbk: bytes = None, tick: int = None,
              market: str = None, seq: MsgSeq = None,
              wt_type: str = None) -> bytes:
    """构造 0221 买单明文 (内部cmd 02 01)。code=6位数字串; market 缺省按前缀推断。
    wt_type: 委托类型文本 (None=模板默认'ptwt'普通; 'sjwt'=市价, 价格传0)。"""
    if name_gbk is None:
        name_gbk = '某某某'.encode('gbk')
    if len(code) != 6 or not code.isdigit():
        raise ValueError("code 须为6位数字串")
    if len(name_gbk) != 6:
        raise ValueError("户名GBK须恰6字节")
    if market is None:
        market = guess_market(code)
    if len(gdzh) > 16 or len(zjzh) > 16:
        raise ValueError("gdzh/zjzh 超出16B槽")
    b = _tpl('buy')
    b[0x02:0x06] = sess
    b[0x08:0x18] = os.urandom(16)
    struct.pack_into('<I', b, 0x88, tick if tick is not None else _tick_ms())
    struct.pack_into('<I', b, 0x8c, seq.next() if seq else 1)
    _patch(b, 0x90, 16, zjzh.encode(), 'zjzh')
    _patch(b, 0xc0, 16, zjzh.encode(), 'zjzh2')
    _patch(b, 0x100, 6, name_gbk, '户名')
    b[0x10b:0x10c] = market.encode()
    b[0x10c:0x112] = code.encode()
    struct.pack_into('<f', b, 0x113, float(price))
    struct.pack_into('<i', b, 0x117, int(qty))
    _patch(b, 0x11b, 16, gdzh.encode(), 'gdzh')
    upd = {
        'req_start_tickcount': str(_tick_ms()),
        'zjzh': zjzh,
        'wtjg': "%.6f" % float(price),
        'wtsl': str(int(qty)),
        'scdm': market,
    }
    if wt_type:
        upd['type'] = wt_type
    text = _retable(bytes(b[0x12b:]), upd)
    pt = bytearray(bytes(b[:0x12b]) + text)
    pt[8:24] = _sign(bytes(pt))
    return bytes(pt)


def build_precheck(code: str, *, sess: bytes, zjzh: str, gdzh: str, tick: int = None,
                   market: str = None, seq: MsgSeq = None) -> bytes:
    """构造 0124 预检明文 (内部cmd 01 04; wtjg恒0.000, 不带价格)。"""
    if len(code) != 6 or not code.isdigit():
        raise ValueError("code 须为6位数字串")
    if market is None:
        market = guess_market(code)
    b = _tpl('chk')
    b[0x02:0x06] = sess
    b[0x08:0x18] = os.urandom(16)
    struct.pack_into('<I', b, 0x88, tick if tick is not None else _tick_ms())
    struct.pack_into('<I', b, 0x8c, seq.next() if seq else 1)
    _patch(b, 0x90, 16, zjzh.encode(), 'zjzh')
    _patch(b, 0xc0, 16, zjzh.encode(), 'zjzh2')
    b[0x10c:0x112] = code.encode()
    _patch(b, 0x11b, 16, gdzh.encode(), 'gdzh')
    text = _retable(bytes(b[0x12b:]), {
        'zqdm': code,
        'zjzh': zjzh,
        'gdzh': gdzh,
        'scdm': market,
    })
    pt = bytearray(bytes(b[:0x12b]) + text)
    pt[8:24] = _sign(bytes(pt))
    return bytes(pt)


def build_login(*, login_zh: str, local_ip: str, localport: int,
                server_ip: str, name: str = None, deptid=None,
                verinfo: str = None) -> bytes:
    """构造 C2S#1 登录明文 (1132B模板+补丁)。

    模板内账号/姓名/硬件指纹为脱敏占位符; login_zh 必传,
    name (户名) 可选传入以替换模板占位名。
    实测: 硬件指纹(MAC/CPU/序列号/GUID)与 localip/localport 服务端均不校验
    (故意填错 IP 10.0.0.99:12345 登录照常成功), 仅账号/股东号必须正确。"""
    b = _tpl('login')
    name_gbk = name.encode('gbk') if name else None
    if name_gbk is not None and len(name_gbk) != 6:
        raise ValueError('户名GBK须恰6字节: %r' % name)
    patch_account(b, zjzh=login_zh, name_gbk=name_gbk)
    patch_broker(b, deptid=deptid, verinfo=verinfo)
    text = _retable(bytes(b[0x12b:]), {
        'login_zh': login_zh,
        'localip': local_ip.replace('.', '_'),
        'publicip': local_ip.replace('.', '_'),
        'localport': str(localport),
        'serverip': server_ip,
    })
    return bytes(b[:0x12b]) + text


def build_precheck_sh(code: str, qty: int, *, sess: bytes, zjzh: str, gdzh: str,
                      tick: int = None, seq: MsgSeq = None) -> bytes:
    """上海(市场2) 0124 预检 (真客户端实测模板 488B, scdm=2, gdzh=A3..)。"""
    if len(code) != 6 or not code.isdigit():
        raise ValueError("code 须为6位数字串")
    b = _tpl('chk_sh')
    b[0x02:0x06] = sess
    b[0x08:0x18] = os.urandom(16)
    struct.pack_into('<I', b, 0x88, tick if tick is not None else _tick_ms())
    struct.pack_into('<I', b, 0x8c, seq.next() if seq else 1)
    _patch(b, 0x90, 16, zjzh.encode(), 'zjzh')
    _patch(b, 0xc0, 16, zjzh.encode(), 'zjzh2')
    b[0x10c:0x112] = code.encode()
    struct.pack_into('<i', b, 0x117, int(qty))
    _patch(b, 0x11b, 16, gdzh.encode(), 'gdzh')
    text = _retable(bytes(b[0x12b:]), {
        'zqdm': code,
        'zjzh': zjzh,
        'gdzh': gdzh,
        'sjwt': '4',
    })
    pt = bytearray(bytes(b[:0x12b]) + text)
    pt[8:24] = _sign(bytes(pt))
    return bytes(pt)


# 市价委托策略编码 (来自服务器 0526 账户应答的权威表):
#   上海A股: 1#4|1-五档即成剩撤|5|2-五档即成剩转限|2|3-对手方最优|3|4-本方最优
#   深圳A股: 1#2|1-对手方最优|3|2-本方最优|6|3-即成剩撤|4|4-五档即成剩撤|7|5-全额成交或撤
#   (格式: 默认#码 | 码|界面序号-名称 ...; 实测真客户端沪市买单 sjwt=4=五档即成剩撤)
SJWT_SH = {'五档即成剩撤': 4, '五档即成剩转限': 5, '对手方最优': 2, '本方最优': 3}
SJWT_SZ = {'对手方最优': 2, '本方最优': 3, '即成剩撤': 6, '五档即成剩撤': 4, '全额成交或撤': 7}


def build_buy_sh_sjwt(code: str, qty: int, *, sess: bytes, zjzh: str, gdzh: str,
                      zxjg: float, sjwt: int = 4, name_gbk: bytes = None, tick: int = None,
                      seq: MsgSeq = None) -> bytes:
    """上海(市场2) 0221 市价买单 (真客户端实测模板 616B)。

    sjwt: 市价策略码 (默认4=五档即成剩撤, 见 SJWT_SH; 沪市界面顺序:
          1-五档即成剩撤(4) 2-五档即成剩转限(5) 3-对手方最优(2) 4-本方最优(3))
    关键字段 (实测 600398 市价买单):
      市场字节[0x10b]='2' 价格float[0x113]=-1.0 (市价)
      文本: wtjg=-1  sjwt=策略码  type=sjwt  scdm=2  menuid=471
            zxjg/sell1price/buy1price/bhjg = 盘口参考价 (zxjg参数填入; 保护限价=bhjg)
    """
    if len(code) != 6 or not code.isdigit():
        raise ValueError("code 须为6位数字串")
    if name_gbk is None:
        name_gbk = '某某某'.encode('gbk')
    b = _tpl('buy_sh')
    b[0x02:0x06] = sess
    b[0x08:0x18] = os.urandom(16)
    struct.pack_into('<I', b, 0x88, tick if tick is not None else _tick_ms())
    struct.pack_into('<I', b, 0x8c, seq.next() if seq else 1)
    _patch(b, 0x90, 16, zjzh.encode(), 'zjzh')
    _patch(b, 0xc0, 16, zjzh.encode(), 'zjzh2')
    _patch(b, 0x100, 6, name_gbk, '户名')
    b[0x10c:0x112] = code.encode()
    struct.pack_into('<i', b, 0x117, int(qty))
    _patch(b, 0x11b, 16, gdzh.encode(), 'gdzh')
    text = _retable(bytes(b[0x12b:]), {
        'req_start_tickcount': str(_tick_ms()),
        'zjzh': zjzh,
        'zxjg': "%.3f" % float(zxjg),
        'sell1price': "%.2f" % float(zxjg),
        'buy1price': "%.2f" % float(zxjg),
        'bhjg': "%.6f" % float(zxjg),
        'sjwt': str(int(sjwt)),
        'wtsl': str(int(qty)),
    })
    pt = bytearray(bytes(b[:0x12b]) + text)
    pt[8:24] = _sign(bytes(pt))
    return bytes(pt)


def build_sell_sh_sjwt(code: str, qty: int, *, sess: bytes, zjzh: str, gdzh: str,
                       zxjg: float, bhjg: float = None, sjwt: int = 4,
                       name_gbk: bytes = None, tick: int = None,
                       seq: MsgSeq = None) -> bytes:
    """上海(市场2) 0321 市价卖单 (真客户端实测模板 624B, 内部cmd 03 01)。

    与买单(0221)差异 (实测): 线缆cmd=03 21; 文本 wtjg=<保护限价>(买单为-1)、
    workid=9(买2)、menuid=472(买471); 二进制价格float同样=-1.0。
    bhjg: 保护限价 (缺省=zxjg); wtjg 与 bhjg 同值 (按实测样本)。
    """
    if len(code) != 6 or not code.isdigit():
        raise ValueError("code 须为6位数字串")
    if name_gbk is None:
        name_gbk = '某某某'.encode('gbk')
    if bhjg is None:
        bhjg = zxjg
    b = _tpl('sell_sh')
    b[0x02:0x06] = sess
    b[0x08:0x18] = os.urandom(16)
    struct.pack_into('<I', b, 0x88, tick if tick is not None else _tick_ms())
    struct.pack_into('<I', b, 0x8c, seq.next() if seq else 1)
    _patch(b, 0x90, 16, zjzh.encode(), 'zjzh')
    _patch(b, 0xc0, 16, zjzh.encode(), 'zjzh2')
    _patch(b, 0x100, 6, name_gbk, '户名')
    b[0x10c:0x112] = code.encode()
    struct.pack_into('<i', b, 0x117, int(qty))
    _patch(b, 0x11b, 16, gdzh.encode(), 'gdzh')
    text = _retable(bytes(b[0x12b:]), {
        'req_start_tickcount': str(_tick_ms()),
        'zjzh': zjzh,
        'zxjg': "%.3f" % float(zxjg),
        'sell1price': "%.2f" % float(zxjg),
        'buy1price': "%.2f" % float(zxjg),
        'bhjg': "%.6f" % float(bhjg),
        'wtjg': "%.6f" % float(bhjg),
        'sjwt': str(int(sjwt)),
        'wtsl': str(int(qty)),
    })
    pt = bytearray(bytes(b[:0x12b]) + text)
    pt[8:24] = _sign(bytes(pt))
    return bytes(pt)


# 内部cmd -> 线缆cmd (byte2 | 0x20)
WIRE_CMD = {
    'buy': (bytes([2, 1]), bytes([2, 0x21])),
    'sell': (bytes([3, 1]), bytes([3, 0x21])),
    'precheck': (bytes([1, 4]), bytes([1, 0x24])),
    'login': (bytes([0x10, 0]), bytes([0x10, 0x20])),
}
