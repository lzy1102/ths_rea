# -*- coding: utf-8 -*-
"""离线回归测试 (不需要网络/柜台)。

    python tests/test_offline.py        # 直接跑
    pytest tests/test_offline.py        # 或用 pytest

覆盖: 帧组帧/拆帧、DES-CBC+zlib 加解密、md5 签名槽、模板构建(限价/市价 沪深)、
应答解析 (hd1.0 记录区/列名/统计)、市场推断、字段补丁。

fixtures/ 里是从真客户端抓包脱敏而来的黄金样本 (golden fixtures):
  limit_buy_sh_592.bin    沪市限价买单明文 (真客户端抓包逐字节复现)
  market_sell_sh_624.bin  沪市市价卖单明文
  market_buy_sz_616.bin   深市市价买单明文
  limit_buy_body.bin      上述限价单的 zlib+DES 密文
  s2c_funds_1006.bin      资金明细应答明文 (真柜台返回)
"""
import collections
import re
import struct
import sys
import zlib
from pathlib import Path

# Windows 控制台默认 cp1252/cp936, 编不了中文测试名 -> 强制 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ths_client import parse as P                      # noqa: E402
from ths_client import trade_msg as TM                 # noqa: E402
from ths_client.trade_crypt.body_codec import (       # noqa: E402
    DES_KEY, body_decrypt, body_encrypt, des_cbc_encrypt, s2c_decrypt, _des_cbc)
from ths_client.trade_conn import (                    # noqa: E402
    TradeConn, build_frame, build_content, parse_frame, parse_s2c)

FIX = Path(__file__).resolve().parent / 'fixtures'


def fx(name):
    return (FIX / name).read_bytes()


def test_frame_roundtrip():
    content = b'\xfd\xff\x43\x84\xcf\xff\x02\x21' + bytes(range(64))
    raw = build_frame(content)
    assert raw[:4] == b'\xfd\xfd\xfd\xfd'
    assert raw[4:12] == b'%08x' % len(content)
    fr, rest = parse_frame(raw)
    assert rest == b''
    assert fr['len'] == len(content)
    assert fr['content'] == content


def test_parse_s2c_types():
    # 0x10: fdff+sess4+ffff00+10+body
    c = b'\xfd\xff' + bytes.fromhex('4384cfff') + b'\xff\xff\x00\x10' + bytes(range(40))
    info = parse_s2c(c)
    assert info['type'] == 0x10 and info['sess'] == bytes.fromhex('4384cfff')
    # 0x50: +psize(4)+zlib
    body = zlib.compress(b'hello', 6)
    c = b'\xfd\xff' + bytes.fromhex('4384cfff') + b'\xff\xff\x00\x50' + struct.pack('<I', len(body)) + body
    info = parse_s2c(c)
    assert info['type'] == 0x50
    assert zlib.decompress(info['body']) == b'hello'


def test_crypto_roundtrip():
    iv = bytes.fromhex('01b0b1701cd32c96')
    pt = fx('limit_buy_sh_592.bin')
    body, zlen = body_encrypt(pt, iv)
    assert zlen == len(zlib.compress(pt, 6))
    assert body_decrypt(body, iv)[:len(pt)] == pt          # 解密+zlib == 原明文
    # S2C: [u32 len][zlib]
    s2c_body = struct.pack('<I', len(pt)) + zlib.compress(pt, 6)
    pad = des_cbc_encrypt(s2c_body, iv)
    assert s2c_decrypt(pad, iv) == pt


def test_cipher_fixture():
    """密文 fixture 用固定 IV 解回明文 (验证 DES key/IV 链路未漂移)。"""
    key, iv = [l.strip() for l in fx('key_iv.txt').decode().splitlines()
               if l.strip() and not l.strip().startswith('#')][:2]
    assert key == DES_KEY.hex()
    iv = bytes.fromhex(iv)
    body = fx('limit_buy_body.bin')
    z = _des_cbc(body, iv, encrypt=False)
    pt = zlib.decompressobj().decompress(z)
    assert pt[:8] == fx('limit_buy_sh_592.bin')[:8]
    assert len(pt) == len(fx('limit_buy_sh_592.bin'))


def test_sign_slot():
    """md5 签名槽 [8:24] = md5(明文, 槽清零); 改动任一字节签名即变化。"""
    pt = bytearray(fx('limit_buy_sh_592.bin'))
    assert pt[8:24] == TM._sign(bytes(pt))
    pt[0x12b] ^= 0x01
    assert pt[8:24] != TM._sign(bytes(pt))


def test_limit_template_reproducible():
    """build_limit 重建 == fixture (逐字节)。"""
    want = fx('limit_buy_sh_592.bin')
    got = TM.build_limit('600398', 100, 6.0, is_sell=False, market='2',
                         sess=bytes.fromhex('4384cfff'), zjzh='12345678',
                         gdzh='A123456789', name_gbk='某某某'.encode('gbk'), tick=116000000)
    got = re.sub(rb'req_start_tickcount=\d+', b'req_start_tickcount=116000000', got)
    assert len(got) == len(want) == 592
    # 随机槽与签名在末尾统一比对前先重算
    a = bytearray(got)
    a[8:24] = want[8:24]
    assert bytes(a) == want


def test_market_templates():
    for name, fn, kw in (
            ('market_sell_sh_624.bin',
             TM.build_sell_sh_sjwt,
             dict(code='600398', qty=100, sess=bytes.fromhex('4384cfff'), zjzh='12345678',
                  gdzh='A123456789', zxjg=6.55, sjwt=4, name_gbk='某某某'.encode('gbk'),
                  tick=116000000)),
            ('market_buy_sz_616.bin',
             TM.build_buy_sz_sjwt,
             dict(code='000001', qty=100, sess=bytes.fromhex('c07bdeff'), zjzh='12345678',
                  gdzh='0123456789', zxjg=None, sjwt=2, name_gbk='某某某'.encode('gbk'),
                  tick=116000000))):
        want = fx(name)
        got = fn(**kw)
        got = re.sub(rb'req_start_tickcount=\d+', b'req_start_tickcount=116000000', got)
        a = bytearray(got)
        a[8:24] = want[8:24]
        assert bytes(a) == want, name
        # 关键业务字段
        t = got.decode('gbk', 'replace')
        assert 'wtjg=' in t and 'wtsl=100' in t
        assert ('scdm=2' in t) if 'sh' in name else ('scdm=1' in t)


def test_order_field_semantics():
    """市价/限价的关键差异字段 (逆向结论, 防回归)。"""
    buy_mkt = fx('market_buy_sz_616.bin').decode('gbk', 'replace')
    buy_lmt = fx('limit_buy_sh_592.bin').decode('gbk', 'replace')
    assert 'type=sjwt' in buy_mkt and 'sjwt=2' in buy_mkt
    assert 'type=ptwt' in buy_lmt and 'wtjg=6.000000' in buy_lmt
    assert 'sjwt=' not in buy_lmt          # 限价无 sjwt 行
    assert buy_mkt.count('sjwt=') == 1


def test_response_parse():
    pt = fx('s2c_funds_1006.bin')
    d = P.parse_hd10(pt)
    assert d['count'] and len(d['fields']) > 20
    assert '市场名称' in d['columns']
    assert d['stats'].get('SX') == '2.0'
    # 列名/行标签均可读
    assert P.parse_stats(pt.decode('gbk', 'replace'))['SX'] == '2.0'
    assert P.gbk_runs(pt, 2)


def test_patch_account_placeholder():
    tpl = bytearray(fx('market_buy_sz_616.bin'))
    TM.patch_account(tpl, zjzh='11111111', gdzh_sh='A111111111',
                     gdzh_sz='0111111111', name_gbk='测试'.encode('gbk'))
    assert b'11111111' in bytes(tpl) and b'0111111111' in bytes(tpl)
    assert b'12345678' not in bytes(tpl)


def test_guess_market():
    assert TM.guess_market('600398') == '2'
    assert TM.guess_market('000001') == '1'
    assert TM.guess_market('300750') == '1'
    for bad in ('920002', '833171', '430047'):        # 北交所/三板明确拒绝
        try:
            TM.guess_market(bad)
            raise AssertionError('应拒绝 %s' % bad)
        except ValueError:
            pass


def test_build_content_len_fields():
    """组帧头: len1=zlib长, len2=明文长。"""
    pt = fx('market_buy_sz_616.bin')
    body, zlen = body_encrypt(pt, bytes(8))
    c = build_content(b'\x02\x21', bytes.fromhex('c07bdeff'), body, zlen, len(pt))
    assert c[6:8] == b'\x02\x21'
    assert struct.unpack('<HH', c[12:16]) == (zlen, len(pt))
    assert c[8:12] == b'\x00\x00\x10\x00'


def test_recv_msg_accept_push():
    """盘中 0124 预检的应答走 0x50 推送通道: recv_msg(accept_push=..) 应命中该股票的推送。

    2026-10-19 盘中实测发现: 收盘时柜台回 0x10, 盘中改为 0x50 行情推送。
    若无此回落逻辑, precheck() 会一直等到超时。
    """
    import queue as _q
    conn = TradeConn.__new__(TradeConn)          # 不建连, 只测队列逻辑
    conn._resp_q = _q.Queue()
    conn._push_q = _q.Queue()
    conn._reader_on = True
    conn.pushes = collections.deque(maxlen=50)
    mk = lambda code, name: {'type': 0x50, 'sess': b'\x00\x00\x00\x00',
                             'plaintext': ('zqdm=%s&zqmc=%s&zgj=8.6300' % (code, name)).encode('gbk'),
                             'text': 'zqdm=%s' % code,
                             'kv': {'zqdm': code, 'zqmc': name, 'zgj': '8.6300'}}
    conn._push_q.put(mk('000001', '平安银行'))    # 其它股票在前, 不应被误取
    conn._push_q.put(mk('601398', '工商银行'))

    r = conn.recv_msg(timeout=3, accept_push='601398')
    assert r['via_push'] is True
    assert r['type'] == 0x50
    assert b'601398' in r['plaintext'] and '工商银行'.encode('gbk') in r['plaintext']

    # 非目标代码: 应超时而不是返回别人的行情
    try:
        conn.recv_msg(timeout=1, accept_push='600000')
        raise AssertionError('应超时')
    except TimeoutError:
        pass


def test_parse_quote():
    """quote(): k=v 给开高低量额, 最新价在二进制区 float32(off=194)。"""
    import struct as _s
    from ths_client.client import TradeClient as _TC
    NUL = bytes([0])
    head = bytearray(NUL * 260)
    _s.pack_into('<f', head, 194, 8.48)                 # 最新价
    kv = (b'zqdm=601398&zqmc=INDUSTRY&open=8.4700&zgj=8.6500&zdj=8.4400'
          b'&cjje=1126497399.8720&cjl=290458330&T_JS=1509560775')
    r = {'plaintext': bytes(head) + NUL + NUL + kv, 'via_push': True}
    q = _TC.parse_quote(r, '601398')
    assert q['code'] == '601398' and q['name'] == 'INDUSTRY'
    assert (q['open'], q['high'], q['low']) == (8.47, 8.65, 8.44)
    assert q['last'] == 8.48
    assert q['amount'] == 1126497399.872 and q['volume'] == 290458330
    assert q['time'] == '1509560775' and q['via_push'] is True

    # 最新价越界(创业板/科创板情形)必须返回 None, 不能返回未经验证的值
    head2 = bytearray(NUL * 260)
    _s.pack_into('<f', head2, 194, 277.0)               # 高=275 低=268 -> 277 越界
    kv2 = (b'zqdm=300750&zqmc=CYB&open=275.0000&zgj=275.0000&zdj=268.0000'
           b'&cjje=1.0&cjl=1&T_JS=1')
    q2 = _TC.parse_quote({'plaintext': bytes(head2) + kv2, 'via_push': True}, '300750')
    assert q2['last'] is None, '越界时不应猜值'


def test_recv_msg_resp_priority():
    """有 0x10 应答时优先返回应答, 不被推送抢走。"""
    import queue as _q
    conn = TradeConn.__new__(TradeConn)
    conn._resp_q = _q.Queue()
    conn._push_q = _q.Queue()
    conn._reader_on = True
    conn.pushes = collections.deque(maxlen=50)
    conn.iv = bytes(8)
    conn.sess = None
    conn._dump = lambda *a, **k: None
    conn._push_q.put({'type': 0x50, 'plaintext': b'zqdm=601398', 'kv': {'zqdm': '601398'}})

    # 造一个合法的 0x10 应答帧: body = DES-CBC([u32 明文长][zlib(明文)])
    # (协议里长度头 == 解压后明文长度, 见 s2c_decrypt)
    pt = fx('s2c_funds_1006.bin')
    z = zlib.compress(pt, 6)
    body = des_cbc_encrypt(struct.pack('<I', len(pt)) + z, bytes(8))
    content = b'\xfd\xff' + b'\x00\x00\x00\x00' + b'\x00\x00\x00' + bytes([0x10]) + body
    conn._resp_q.put({'content': content})

    r = conn.recv_msg(timeout=3, accept_push='601398')
    assert r.get('via_push') is None, '不应回落到推送'
    assert r['type'] == 0x10
    assert r['plaintext'] == pt          # 解密解压后与原文一致


if __name__ == '__main__':
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith('test_') and callable(f)]
    bad = 0
    for n, f in fns:
        try:
            f()
            print('  PASS %s' % n)
        except Exception as e:
            bad += 1
            print('  FAIL %s: %r' % (n, e))
    print('\n%d/%d 通过' % (len(fns) - bad, len(fns)))
    sys.exit(1 if bad else 0)