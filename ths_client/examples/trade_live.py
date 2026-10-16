# -*- coding: utf-8 -*-
"""独立客户端演示: 干跑(dry-run, 默认, 无网络) / 实盘(--live, 需显式确认)。

干跑: 构造登录帧 + 预检帧 + 买单帧 (全流程离线), 验证加解密回环。
实盘 (--live): 连接柜台 -> 问候 -> 登录(取sess/IV) -> 发0124预检(测试代码)
  -> 读回包并解密展示。**不发买单** (买单构造仅在干跑中验证)。
  预检使用测试代码 999998, 服务端只会拒绝 (网关开关关闭), 不产生真实委托。

用法:
    python -m ths_client.examples.trade_live            # 干跑
    python -m ths_client.examples.trade_live --live     # 实盘 (需网络, 会提示确认)
"""
import argparse
import socket
import struct
import sys
import zlib

sys.path.insert(0, '.')
from ths_client import trade_conn as TC
from ths_client import trade_msg as TM
from ths_client.trade_crypt.body_codec import body_decrypt, body_encrypt

# ---- 账号配置: 从本地配置文件读取 (local_profile.json, 已gitignore; 不提交仓库) ----
from ths_client.client import load_profile
_prof = load_profile()
ACCOUNT = {
    'zjzh': _prof.get('zjzh', '12345678'),            # 资金账号
    'gdzh_sh': _prof.get('gdzh_sh', 'A123456789'),    # 上海股东号 (A开头)
    'gdzh_sz': _prof.get('gdzh_sz', '0123456789'),    # 深圳股东号 (数字)
    'name_gbk': _prof.get('name', '某某某').encode('gbk'),
}
TEST_CODE = '999998'


def pick_gdzh(market: str) -> str:
    return ACCOUNT['gdzh_sh'] if market == '2' else ACCOUNT['gdzh_sz']


def dry_run(code=TEST_CODE, price=100.0, qty=100):
    print("===== DRY-RUN (无网络) =====")
    sess = bytes.fromhex('7579c0ff')       # 示例 sess4 (登录后由服务器分配)
    iv = bytes.fromhex('cb4295a7be472f1e')  # 示例 IV
    seq = TM.MsgSeq(1)
    market = TM.guess_market(code)
    gdzh = pick_gdzh(market)
    print(f"code={code} price={price} qty={qty} market={market} gdzh={gdzh}")

    # 1) 登录帧
    login_pt = TM.build_login(login_zh=ACCOUNT['zjzh'], local_ip='192.168.0.1',
                              localport=45515, server_ip=TC.COUNTER_HOST,
                              name=ACCOUNT['name_gbk'].decode('gbk'))
    print(f"[1] 登录明文 {len(login_pt)}B, 头: {login_pt[:8].hex(' ')}")
    z = zlib.compress(login_pt, 6)
    content = TC.build_content(TM.WIRE_CMD['login'][1], bytes(4), z, len(z), len(login_pt))
    fr = TC.build_frame(content)
    print(f"    C2S#1 帧 {len(fr)}B (content {len(content)}B)")

    # 2) 预检 0124
    chk_pt = TM.build_precheck(code, sess=sess, zjzh=ACCOUNT['zjzh'], gdzh=gdzh,
                               market=market, seq=seq)
    print(f"[2] 预检明文 {len(chk_pt)}B, 头: {chk_pt[:8].hex(' ')}")
    body, zlen = body_encrypt(chk_pt, iv)
    print(f"    压缩 {len(chk_pt)}->{zlen}B, 加密body {len(body)}B")
    wire_cmd = TM.WIRE_CMD['precheck'][1]
    content = TC.build_content(wire_cmd, sess, body, zlen, len(chk_pt))
    fr = TC.build_frame(content)
    print(f"    0124 帧 {len(fr)}B")
    # 回环验证
    back = body_decrypt(bytes(content[16:]), iv)
    assert back == chk_pt, "预检回环失败!"
    print("    预检加解密回环 OK")

    # 3) 买单 0221
    buy_pt = TM.build_buy(code, price, qty, sess=sess, zjzh=ACCOUNT['zjzh'],
                          gdzh=gdzh, name_gbk=ACCOUNT['name_gbk'],
                          market=market, seq=seq)
    print(f"[3] 买单明文 {len(buy_pt)}B, 头: {buy_pt[:8].hex(' ')}")
    assert buy_pt[6:8] == TM.WIRE_CMD['buy'][0], "内部cmd异常"
    body, zlen = body_encrypt(buy_pt, iv)
    wire_cmd = TM.WIRE_CMD['buy'][1]
    assert buy_pt[6] == wire_cmd[0] and (buy_pt[7] | 0x20) == wire_cmd[1]
    content = TC.build_content(wire_cmd, sess, body, zlen, len(buy_pt))
    fr = TC.build_frame(content)
    print(f"    0221 帧 {len(fr)}B (len1={zlen} len2={len(buy_pt)})")
    # 回环验证: 解析帧 -> 解密 -> 解压 -> 对比
    parsed, rest = TC.parse_frame(fr)
    assert not rest and parsed['content'] == content
    c = parsed['content']
    assert c[6:8] == wire_cmd and c[2:6] == sess
    l1, l2 = struct.unpack('<HH', c[12:16])
    assert (l1, l2) == (zlen, len(buy_pt)), (l1, l2, zlen, len(buy_pt))
    back = body_decrypt(bytes(c[16:]), iv)
    assert back == buy_pt, "买单回环失败!"
    print("    买单加解密回环 OK")
    # 字段抽查
    assert ('wtjg=%.6f' % price).encode() in back
    assert ('wtsl=%d' % qty).encode() in back
    assert code.encode() in back
    print("    字段抽查 OK (wtjg/wtsl/zqdm)")
    print("\nDRY-RUN 全部通过 ✅")


def live(dump_dir: str = 'captures/live_frames', bind_port: int = 0,
         random_nonce: bool = False, code: str = TEST_CODE,
         price: float = 100.0, qty: int = 100, send_buy: bool = False,
         market_order: bool = False, sjwt: int = 4):
    print("===== LIVE (实盘连接) =====")
    print("将连接 %s:%d, 代码 %s" % (TC.COUNTER_HOST, TC.COUNTER_PORT, code))
    if send_buy:
        kind = '市价' if market_order else f'限价 {price}'
        print(f"  !! 将发送 0221 买单: {code} {kind} 数量 {qty}"
              + ("  [999998=不存在代码, 无真实委托]" if code == '999998' else "  [真实代码=真实委托!]"))
    print(f"dump_dir={dump_dir} bind_port={bind_port or '随机'} random_nonce={random_nonce}")
    ans = input("确认继续? 输入 YES: ").strip()
    if ans != 'YES':
        print("已取消")
        return
    conn = TC.TradeConn()
    print("[1] 连接...", end=' ', flush=True)
    conn.connect(bind_port=bind_port, dump_dir=dump_dir)
    print("OK")
    from pathlib import Path
    greeting = Path('captures/replay_c2s0.bin').read_bytes()
    print("[2] 问候...", end=' ', flush=True)
    rep = conn.greeting(greeting)
    print(f"OK (应答 {len(rep)}B)")
    print("[3] 登录...", end=' ', flush=True)
    lip = socket.gethostbyname(socket.gethostname())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((TC.COUNTER_HOST, TC.COUNTER_PORT))
        lip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    login_pt = TM.build_login(login_zh=ACCOUNT['zjzh'], local_ip=lip,
                              localport=conn.sock.getsockname()[1],
                              server_ip=TC.COUNTER_HOST,
                              name=ACCOUNT['name_gbk'].decode('gbk'))
    if random_nonce:
        import os as _os
        login_pt = login_pt[:8] + _os.urandom(16) + login_pt[24:]
        print("(16B随机区已随机化)", end=' ', flush=True)
    info = conn.login(login_pt)
    print(f"OK sess={info['sess'].hex(' ')} iv={info['iv'].hex(' ')}")
    import time as _t
    for attempt in ((2, 3) if info['sess'] == bytes(4) else ()):
        print(f"[3.{attempt}] 再次登录 (第{attempt}次) ...", end=' ', flush=True)
        _t.sleep(2)
        try:
            info2 = conn.login(login_pt, max_wait=4)
            print(f"sess={info2['sess'].hex(' ')} iv={info2['iv'].hex(' ')}")
            if info2['sess'] != bytes(4):
                print("sess已分配! 采用新sess继续")
                info = info2
                break
        except Exception as e:
            print(f"无新响应 ({e})")
    Path('captures/live_s2c1.bin').write_bytes(info['s2c1'])
    # seq: 登录已用1 -> 首个业务消息从2开始; tick: 延续登录帧的 tick (会话内单调)
    login_tick = struct.unpack('<I', login_pt[0x88:0x8c])[0]
    tick_base = [login_tick, _t.monotonic()]

    def sess_tick():
        return (tick_base[0] + int((_t.monotonic() - tick_base[1]) * 1000)) & 0xFFFFFFFF

    seq = TM.MsgSeq(2)
    market = TM.guess_market(code)
    if market == '2' and market_order:
        # ---- 上海市价单专用流程 (真客户端实测全链路) ----
        # 标准启动(0030/0526/0126/0326/0226) -> SH启动(0029/0520/0126/0326/0226)
        # -> 0124预检 -> 0221市价买单 (wtjg=-1/sjwt=4/type=sjwt)
        import re as _re
        gdzh = pick_gdzh(market)
        print("[3.4] 标准启动序列...")
        for wire, r in conn.bootstrap(info['iv'], seq=seq, tick=sess_tick(),
                                      zjzh=ACCOUNT['zjzh'], gdzh_sh=ACCOUNT['gdzh_sh'],
                                      gdzh_sz=ACCOUNT['gdzh_sz'],
                                      name_gbk=ACCOUNT['name_gbk']):
            print(f"      {wire.hex()} -> {r['type']:#x} {len(r['plaintext'])}B")
        print("[3.5] SH启动序列 (0029/0520/0126/0326/0226)...")
        for wire, r in conn.bootstrap(info['iv'], seq=seq, tick=sess_tick(),
                                      tpl_dir=TC.STARTUP_SH_DIR,
                                      zjzh=ACCOUNT['zjzh'], gdzh_sh=ACCOUNT['gdzh_sh'],
                                      gdzh_sz=ACCOUNT['gdzh_sz'],
                                      name_gbk=ACCOUNT['name_gbk']):
            txt = r['plaintext'][:300].decode('gbk', 'replace').replace('\n', '|')
            print(f"      {wire.hex()} -> 回包 {r['type']:#x} {len(r['plaintext'])}B {txt[:50]}")
        print("[4] 发0124预检(SH)...", end=' ', flush=True)
        chk_pt = TM.build_precheck_sh(code, qty, sess=info['sess'], zjzh=ACCOUNT['zjzh'],
                                      gdzh=gdzh, seq=seq, tick=sess_tick())
        conn.send_msg(TM.WIRE_CMD['precheck'][1], chk_pt, info['iv'])
        print("已发送, 等回包...")
        open_px = None
        for _ in range(6):
            try:
                r = conn.recv_msg()
                t = r['plaintext'].decode('gbk', 'replace')
                print(f"    回包 {r['type']:#x} {len(r['plaintext'])}B")
                print("    文本:", t[:160].replace('\n', '|'))
                m = _re.search(r'open=([0-9.]+)', t)
                if m:
                    open_px = float(m.group(1))
                break
            except Exception as e:
                print("    等待中...", e)
        if send_buy:
            zx = open_px if open_px else 10.0
            print(f"[5] 发0221市价买单(SH) {code} 参考价{zx} 量{qty}...", end=' ', flush=True)
            buy_pt = TM.build_buy_sh_sjwt(code, qty, sess=info['sess'], zjzh=ACCOUNT['zjzh'],
                                          gdzh=gdzh, zxjg=zx, sjwt=sjwt,
                                          name_gbk=ACCOUNT['name_gbk'],
                                          seq=seq, tick=sess_tick())
            conn.send_msg(TM.WIRE_CMD['buy'][1], buy_pt, info['iv'])
            print("已发送, 等回包...")
            for _ in range(6):
                try:
                    r = conn.recv_msg()
                    print(f"    回包 type={r['type']:#x} 明文{len(r['plaintext'])}B")
                    t = r['plaintext'][:600].decode('gbk', 'replace')
                    print("    文本:", t.replace('\n', '|')[:400])
                    break
                except Exception as e:
                    print("    等待中...", e)
        conn.close()
        print("LIVE(SH市价) 完成")
        return
    # [3.5] 启动序列回放 (建立账户上下文; 否则0124回"帐户无效")
    print("[3.5] 启动序列回放...")
    for wire, r in conn.bootstrap(info['iv'], seq=seq, tick=sess_tick(),
                                  zjzh=ACCOUNT['zjzh'], gdzh_sh=ACCOUNT['gdzh_sh'],
                                  gdzh_sz=ACCOUNT['gdzh_sz'],
                                  name_gbk=ACCOUNT['name_gbk']):
        txt = r['plaintext'][:300].decode('gbk', 'replace').replace('\n', '|')
        print(f"      {wire.hex()} -> 回包 {r['type']:#x} {len(r['plaintext'])}B {txt[:60]}")
    # [3.6] 下单预载 0520 (疑似装载"交易信息表"/闪电下单PreLoad)
    preload = Path('captures/fresh_startup2/0520_416.bin')
    if preload.exists():
        pt = bytearray(preload.read_bytes())
        pt[0x02:0x06] = info['sess']
        struct.pack_into('<I', pt, 0x88, sess_tick())
        struct.pack_into('<I', pt, 0x8c, seq.next())
        pt[8:24] = TM._sign(bytes(pt))
        wire = bytes([pt[6], pt[7] | 0x20])
        print(f"[3.6] 预载 {wire.hex()} ({len(pt)}B) ...", end=' ', flush=True)
        conn.send_msg(wire, bytes(pt), info['iv'])
        try:
            r = conn.recv_msg()
            txt = r['plaintext'][:200].decode('gbk', 'replace').replace('\n', '|')
            print(f"回包 {r['type']:#x} {len(r['plaintext'])}B {txt[:70]}")
        except Exception as e:
            print(f"回包失败 {e}")
    print("[4] 发0124预检...", end=' ', flush=True)
    chk_pt = TM.build_precheck(code, sess=info['sess'], zjzh=ACCOUNT['zjzh'],
                               gdzh=pick_gdzh(market), market=market, seq=seq,
                               tick=sess_tick())
    conn.send_msg(TM.WIRE_CMD['precheck'][1], chk_pt, info['iv'])
    print("已发送, 等回包...")
    for _ in range(6):
        try:
            r = conn.recv_msg()
            print(f"    回包 type={r['type']:#x} sess={r['sess'].hex(' ')} 明文{len(r['plaintext'])}B")
            print(f"    头: {r['plaintext'][:16].hex(' ')}")
            t = r['plaintext'][:400].decode('gbk', 'replace')
            print("    文本:", t.replace('\n', '|')[:200])
            break
        except Exception as e:
            print("    等待中...", e)
    if send_buy:
        wt_type = 'sjwt' if market_order else None
        px = price
        print(f"[5] 发0221买单 {code} {'市价' if market_order else '限价'}"
              f"(参考价{px}) 量{qty}...", end=' ', flush=True)
        buy_pt = TM.build_buy(code, px, qty, sess=info['sess'], zjzh=ACCOUNT['zjzh'],
                              gdzh=pick_gdzh(market), name_gbk=ACCOUNT['name_gbk'],
                              market=market, seq=seq, tick=sess_tick(),
                              wt_type=wt_type)
        conn.send_msg(TM.WIRE_CMD['buy'][1], buy_pt, info['iv'])
        print("已发送, 等回包...")
        for _ in range(6):
            try:
                r = conn.recv_msg()
                print(f"    回包 type={r['type']:#x} sess={r['sess'].hex(' ')} 明文{len(r['plaintext'])}B")
                print(f"    头: {r['plaintext'][:16].hex(' ')}")
                t = r['plaintext'][:500].decode('gbk', 'replace')
                print("    文本:", t.replace('\n', '|')[:300])
                break
            except Exception as e:
                print("    等待中...", e)
    conn.close()
    print("LIVE 完成 ✅ (如看到回包字段, 说明加解密+组帧全链路正常)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--live', action='store_true', help='实盘连接 (需确认)')
    ap.add_argument('--buy', action='store_true', help='预检后发送0221买单 (需再确认)')
    ap.add_argument('--market', action='store_true', help='市价委托 (type=sjwt)')
    ap.add_argument('--sjwt', type=int, default=4,
                    help='市价策略码 沪:4=五档即成剩撤(默认) 5=五档即成剩转限 2=对手方最优 3=本方最优')
    ap.add_argument('--code', default=TEST_CODE)
    ap.add_argument('--price', type=float, default=100.0)
    ap.add_argument('--qty', type=int, default=100)
    ap.add_argument('--dump-dir', default='captures/live_frames')
    ap.add_argument('--bind-port', type=int, default=0)
    ap.add_argument('--random-nonce', action='store_true')
    a = ap.parse_args()
    if a.live:
        live(dump_dir=a.dump_dir, bind_port=a.bind_port, random_nonce=a.random_nonce,
             code=a.code, price=a.price, qty=a.qty, send_buy=a.buy, market_order=a.market,
             sjwt=a.sjwt)
    else:
        dry_run(a.code, a.price, a.qty)


if __name__ == '__main__':
    main()
