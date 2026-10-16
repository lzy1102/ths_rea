"""会话探测器: 重放抓包的真登录帧(V1) / 修补版(V3), 观察服务端是否分配 session。

用法:
  python tools/session_probe.py            # V1 原样重放 + V3 修补重放
  python tools/session_probe.py v1         # 只测 V1
"""
import sys, os, re, zlib, struct, time, socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
from ths_client import trade_conn as TC

WANT = b'\xfd\xff\x00\x00\x00\xff\x10\x20'


def extract_fresh_login() -> bytes:
    d = Path('captures/login_watch_raw.bin').read_bytes()
    c2s = bytearray()
    i = 0
    while i + 5 <= len(d):
        n = struct.unpack('<I', d[i:i + 4])[0]
        j = d.find(b'\x00', i + 4)
        if d[i + 4:j] == b'C2S':
            c2s.extend(d[j + 1:j + 1 + n])
        i = j + 1 + n
    s = bytes(c2s)
    pos = 0
    while True:
        k = s.find(WANT, pos)
        if k < 0:
            raise SystemExit('未在抓包流中找到登录帧')
        st = k - 13
        if st >= 0 and s[st:st + 4] == b'\xfd\xfd\xfd\xfd':
            try:
                ln = int(s[st + 4:st + 12], 16)
            except ValueError:
                ln = -1
            if ln > 0 and st + 13 + ln <= len(s):
                return s[st:st + 13 + ln]
        pos = k + 1


def local_ip(host: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 8002))
        return s.getsockname()[0]
    finally:
        s.close()


def probe(build, label: str, wait: float = 30.0):
    """build(lip, lport) -> frame bytes"""
    conn = TC.TradeConn(timeout=wait)
    try:
        conn.connect()
        lip = local_ip(TC.COUNTER_HOST)
        lport = conn.sock.getsockname()[1]
        rep = conn.greeting(Path('captures/replay_c2s0.bin').read_bytes())
        print(f"  [{label}] 问候应答 {len(rep)}B: {rep[:20].hex(' ')}  local={lip}:{lport}")
        frame = build(lip, lport)
        t0 = time.time()
        conn.sock.sendall(frame)
        while True:
            fr = conn.recv_frame()
            c = fr['content']
            if len(c) >= 8 and c[:2] == b'\xfd\xff':
                sess = bytes(c[2:6])
                print(f"  [{label}] >>> sess={sess.hex(' ')}  (frame len={fr['len']}, "
                      f"{time.time() - t0:.1f}s) {'*** 已分配! ***' if sess != bytes(4) else ''}")
                return sess
    except Exception as e:
        print(f"  [{label}] 失败: {e!r}")
        return None
    finally:
        conn.close()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    v1 = extract_fresh_login()
    Path('captures/fresh_login_frame.bin').write_bytes(v1)
    print(f"V1 抓包原帧: {len(v1)}B")

    if mode in ('all', 'v1'):
        probe(lambda lip, lport: v1, 'V1 原样直放')

    if mode == 'all':
        content = v1[13:]
        pt = zlib.decompress(content[16:])

        def build_v3(lip, lport):
            pt2 = pt[:8] + os.urandom(16) + pt[24:]
            txt = pt2[0x12b:]
            txt = re.sub(rb'localip=[0-9A-Za-z_]+', f'localip={lip.replace(".", "_")}'.encode(), txt)
            txt = re.sub(rb'publicip=[0-9A-Za-z_]+', f'publicip={lip.replace(".", "_")}'.encode(), txt)
            txt = re.sub(rb'localport=\d+', f'localport={lport}'.encode(), txt)
            pt2 = pt2[:0x12b] + txt
            zc = zlib.compress(pt2, 6)
            body2 = zc + bytes((-len(zc)) % 8)
            c2 = bytearray(content)
            c2[16:] = body2
            struct.pack_into('<H', c2, 12, len(zc))
            return TC.build_frame(bytes(c2), mode=v1[12])

        probe(build_v3, 'V3 修补(随机nonce+本机IP/端口)')


if __name__ == '__main__':
    main()
