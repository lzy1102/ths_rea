# -*- coding: utf-8 -*-
"""查询应答解析 (0126 持仓 / 0326 委托 / 0226 资金明细 / 0526 账户)。

应答明文结构 (实测 825B~1006B, 逆向下单进展-3):
    fdff + sess4 + cmd86 + ... + 账户字段(0x90起) + gb=2*16 + gdzh(0x11b)
    + 二进制记录区: "hd1.0" + 00*5 + u16 len_a + u16 len_b + u16 字段数
                    + 4字节标记 + 字段数×4字节字段[tag u16][a][b]
    + 列名表(GBK)   + 会话统计 "SX=2.0&SXL=...&"
"""
import re

import struct

MAGIC = b'hd1.0'
STATS_RE = re.compile(r'SX=[0-9.]+&SXL=\d+(?:&[A-Z_0-9]+=[^&\x00\n]*)+&?')


def gbk_runs(pt: bytes, min_chars: int = 2) -> list:
    """提取明文中的 GBK 文本串 (列名表 / 行标签等)。"""
    out = []
    for m in re.finditer(rb'(?:[\xa1-\xfe]{2}){%d,}' % min_chars, pt):
        try:
            out.append(m.group().decode('gbk'))
        except UnicodeDecodeError:
            pass
    return out


def parse_stats(text: str) -> dict:
    """解析尾部会话统计 SX=2.0&SXL=00088&T_WR=.. 。"""
    m = STATS_RE.search(text)
    if not m:
        return {}
    d = {}
    for kv in m.group(0).strip('&').split('&'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            d[k] = v
    return d


def parse_hd10(pt: bytes) -> dict:
    """解析 hd1.0 记录区: 返回 {len_a, len_b, count, fields, columns, rows, stats}。

    - fields: [(tag, a, b), ...] —— 4字节字段原始值 (数值语义待有数据样本确认)
    - columns: 列名表 (GBK)
    - rows: 行标签 (如 ['沪A股','本币','可用','可取','冻结市值','市值'])
    - stats: 会话统计 dict
    数值字段语义确认方法: 账户有资金/持仓后, 连查两次并对比 fields 差异即可定位
    (同一 tag 值变化的即为该字段)。
    """
    out = {'len_a': None, 'len_b': None, 'count': None, 'fields': [],
           'marker': None, 'columns': [], 'rows': [], 'stats': {}, 'text': ''}
    try:
        out['text'] = pt.decode('gbk', 'replace')
    except Exception:
        pass
    out['stats'] = parse_stats(out['text'])

    i = pt.find(MAGIC)
    if i < 0 or i + 20 > len(pt):
        return out
    out['len_a'], out['len_b'], out['count'] = struct.unpack('<HHH', pt[i + 10:i + 16])
    out['marker'] = pt[i + 16:i + 20].hex()

    ent = i + 20
    limit = min(out['count'] or 0, (len(pt) - ent) // 4)
    fields = []
    for k in range(limit):
        tag, a, b = struct.unpack('<HBB', pt[ent + k * 4:ent + k * 4 + 4])
        # 记录区末尾与文本区相接: 4字节若能解成可打印GBK即判定为文本, 停止
        if 0x20 <= a < 0x7f and 0x20 <= b < 0x7f:
            break
        try:
            s = bytes([a, b]).decode('gbk')
            if s.isprintable() and (0xa1 <= a <= 0xfe or 0xb0 <= a <= 0xf7):
                break
        except UnicodeDecodeError:
            pass
        fields.append((tag, a, b))
    out['fields'] = fields

    # 列名表 = 尾部连续的短 GBK 串 (>=2字), 行标签 = 记录区之后的标签串
    tail = pt[ent + len(fields) * 4:]
    runs = gbk_runs(tail, 2)
    # 列名通常是"两字/多字"表格头; 行标签多为 市场名/币种/项目名
    out['columns'] = [r for r in runs if len(r) <= 12]
    out['rows'] = [r for r in runs if r not in out['columns']]
    return out
