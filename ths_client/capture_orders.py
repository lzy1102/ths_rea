# -*- coding: utf-8 -*-
"""委托报文抓包 (买卖/撤单/查询通用): 挂 xiadan.exe 的 ws2_32, 全量落盘收发帧 (供离线解密提取模板)。

用法:
    ths-capture-orders [--pid N] [--out captures/sz_cap] [--timeout 600]
    python -m ths_client.capture_orders [--pid N] [--out ...] [--timeout ...]

流程: 启动本工具 -> 重新打开下单窗口(产生新连接+登录) -> 做深市委托操作。
落盘: out/NNN_C2S.bin / NNN_S2C.bin + _meta.jsonl (sock/长度/时间戳)。
命令探测: C2S 帧明文命令行(content[6:8]) 出现 0221/0321 等时打印标记。
"""
import argparse
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

JS = r"""
function dump(tag, sock, ptrIn, len) {
    var n = Math.min(len, 65536);
    try { send({ev: 'io', tag: tag, sock: sock, len: len}, ptrIn.readByteArray(n)); } catch (e) {}
}
try {
    var ws = Process.getModuleByName('ws2_32.dll');
    Interceptor.attach(ws.getExportByName('connect'), {
        onEnter: function (args) {
            try {
                var p = args[1];
                var port = p.add(2).readU16();
                var ipb = new Uint8Array(p.add(4).readByteArray(4));
                send({ev: 'connect', sock: args[0].toString(),
                      ip: ipb[0]+'.'+ipb[1]+'.'+ipb[2]+'.'+ipb[3],
                      port: ((port & 0xff) << 8) | ((port >> 8) & 0xff)});
            } catch (e) {}
        }
    });
    Interceptor.attach(ws.getExportByName('send'), {
        onEnter: function (args) {
            var len = -1; try { len = args[2].toInt32(); } catch (e) {}
            if (len > 0 && len < 0x100000) dump('C2S', args[0].toString(), args[1], len);
        }
    });
    Interceptor.attach(ws.getExportByName('recv'), {
        onEnter: function (args) { this.sock = args[0].toString(); this.buf = args[1]; },
        onLeave: function (retval) {
            var n = -1; try { n = retval.toInt32(); } catch (e) {}
            if (n > 0 && n < 0x100000) dump('S2C', this.sock, this.buf, n);
        }
    });
    try { send({ev: 'module', path: Process.mainModule.path}); } catch (e) {}
    send({ev: 'ready'});
} catch (e) { send({ev: 'fatal', err: e.toString()}); }
"""

MAGIC = b'\xfd\xfd\xfd\xfd'
CMDS = {b'0221': '买入委托', b'0321': '卖出委托', b'0222': '撤单', b'0126': '持仓查询',
        b'0326': '委托查询', b'0226': '成交查询', b'0029': '预检', b'0520': 'SH股票列表'}


def find_xiadan_pid():
    try:
        out = subprocess.check_output('tasklist /FI "IMAGENAME eq xiadan.exe" /FO CSV /NH',
                                      shell=True).decode('gbk', 'replace')
        m = re.search(r'xiadan\.exe","(\d+)"', out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def scan_cmds(buf: bytes):
    """扫描缓冲区内的帧, 返回命令标记列表。"""
    hits = []
    i = 0
    while True:
        i = buf.find(MAGIC, i)
        if i < 0 or i + 13 > len(buf):
            break
        try:
            flen = int(buf[i + 4:i + 12], 16)
        except ValueError:
            i += 4
            continue
        if i + 13 + flen > len(buf):
            i += 4
            continue
        c = buf[i + 13:i + 13 + flen]
        if len(c) >= 8 and c[:2] == b'\xfd\xff':
            cmd = c[6:8]
            if cmd in CMDS:
                hits.append(CMDS[cmd])
        i += 13 + flen
    return hits


def main():
    ap = argparse.ArgumentParser(description='委托报文抓包 (ws2_32全量落盘 + 抓后自动扫IV解密)')
    ap.add_argument('--pid', type=int, help='xiadan.exe PID (缺省自动查找)')
    ap.add_argument('--out', default='captures/sz_cap', help='输出目录')
    ap.add_argument('--timeout', type=int, default=600, help='抓包窗口秒数')
    a = ap.parse_args()

    try:
        import frida
    except ImportError:
        print('缺少 frida: pip install "ths-trade-client[capture]"', file=sys.stderr)
        return 2

    pid = a.pid or find_xiadan_pid()
    if not pid:
        print('未找到 xiadan.exe, 等待启动 (最多120s)... 现在可以打开同花顺下单程序')
        t0 = time.time()
        while time.time() - t0 < 120:
            time.sleep(2)
            pid = find_xiadan_pid()
            if pid:
                break
        if not pid:
            print('超时: 请先打开下单程序或用 --pid 指定', file=sys.stderr)
            return 2

    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    meta = open(outdir / '_meta.jsonl', 'a', encoding='utf-8')
    print(f'挂载 xiadan.exe PID={pid} -> {outdir}/  (窗口 {a.timeout}s)')

    session = frida.attach(pid)
    script = session.create_script(JS)
    n = {'C2S': 0, 'S2C': 0}
    got = set()
    pre_ivs = {'list': [], 'done': False}

    def _prescan():
        try:
            pre_ivs['list'] = _scan_memory_ivs(pid)
            print(f'  [IV预扫] {len(pre_ivs["list"])} 个候选: {pre_ivs["list"]}')
        except Exception as e:
            print(f'  [IV预扫] 失败({e}) (不影响: 结束时还会再扫)')
        pre_ivs['done'] = True

    def on_message(msg, data):
        if msg.get('type') != 'send':
            return
        p = msg['payload']
        ev = p.get('ev')
        if ev == 'ready':
            print('已挂载 ws2_32。请重新打开下单窗口并登录, 然后做委托操作。')
        elif ev == 'fatal':
            print('挂钩失败:', p.get('err'), file=sys.stderr)
        elif ev == 'connect':
            print(f'  [连接] {p["ip"]}:{p["port"]} (sock {p["sock"]})')
        elif ev == 'io' and data is not None:
            tag = p['tag']
            n[tag] += 1
            f = outdir / f'{n[tag]:03d}_{tag}.bin'
            f.write_bytes(bytes(data))
            meta.write(json.dumps({'file': f.name, 'tag': tag, 'sock': p['sock'],
                                   'len': p['len'], 't': round(time.time(), 3)}) + '\n')
            meta.flush()
            if tag == 'C2S':
                if not pre_ivs['done'] and b'\xfd\xff' in bytes(data):
                    threading.Thread(target=_prescan, daemon=True).start()
                for h in scan_cmds(bytes(data)):
                    if h not in got:
                        got.add(h)
                        print(f'  ★ 捕获到 {h} 报文 ({n[tag]:03d}_C2S.bin)')

    script.on('message', on_message)
    script.load()
    t0 = time.time()
    try:
        while time.time() - t0 < a.timeout:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    try:
        script.unload()
    except Exception:
        pass
    session.detach()
    meta.close()
    print(f'抓包结束: C2S {n["C2S"]} 帧, S2C {n["S2C"]} 帧 -> {outdir}/')
    print('捕获命令:', ', '.join(sorted(got)) if got else '(无)')

    # 后处理: 用预扫IV + 再扫一次, 解密全部柜台帧
    scan_and_decrypt(outdir, pid, extra_ivs=pre_ivs['list'])
    return 0


SCAN_JS = r"""
var pat = 'b1 81 83 80 83 88 8d 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00';
var out = [];
Process.enumerateRanges('rw-').forEach(function(r) {
  try {
    Memory.scanSync(r.base, r.size, pat).forEach(function(h) {
      try {
        var b = new Uint8Array(h.address.add(24).readByteArray(8));
        var s = ''; for (var i = 0; i < 8; i++) s += ('0' + b[i].toString(16)).slice(-2);
        out.push(s);
      } catch (e) {}
    });
  } catch (e) {}
});
send({ivs: out});
"""


def _scan_memory_ivs(pid: int) -> list:
    """扫描 xiadan 内存中的密钥描述符(KEY特征码+IV槽), 返回 IV 候选列表。"""
    import frida
    session = frida.attach(pid)
    try:
        script = session.create_script(SCAN_JS)
        res = {}
        script.on('message', lambda m, d: res.update(m['payload']) if m.get('type') == 'send' else None)
        script.load()
        time.sleep(1)
        script.unload()
    finally:
        session.detach()
    return list(dict.fromkeys(res.get('ivs', [])))


def scan_and_decrypt(outdir: Path, pid: int, extra_ivs: list = None):
    """扫描 xiadan 内存中的密钥描述符(KEY特征码+IV槽), 用候选IV解密抓到的柜台帧。

    原理: 客户端把 (KEY=b181838083888d81, IV) 存在连接的密钥描述符里;
    即使抓包时错过了问候帧(无IV), 也能从运行中的进程内存恢复IV。
    extra_ivs: 抓包期间预扫得到的IV(客户端已退出时仍可用)。
    """
    try:
        import zlib
        from .trade_crypt.body_codec import _des_cbc
    except ImportError as e:
        print(f'  [后处理] 缺少依赖({e}), 跳过解密')
        return
    ivs = list(extra_ivs or [])
    try:
        ivs = _scan_memory_ivs(pid) + ivs
    except Exception as e:
        if ivs:
            print(f'  [后处理] 客户端已退出(用预扫IV): {len(ivs)} 个候选')
        else:
            print(f'  [后处理] IV扫描失败({e})且无预扫IV, 跳过解密')
            return
    ivs = list(dict.fromkeys(ivs))
    if not ivs:
        print('  [后处理] 未找到IV候选')
        return
    print(f'  [后处理] IV候选 {len(ivs)} 个, 尝试解密...')

    meta = [json.loads(l) for l in (outdir / '_meta.jsonl').read_text(encoding='utf-8').splitlines()]
    streams = {}
    for m in meta:
        f = outdir / m['file']
        if not f.exists():
            continue
        k = (m['sock'], m['tag'])
        streams.setdefault(k, bytearray())
        streams[k] += f.read_bytes()

    def _frames(buf):
        out, i = [], 0
        while True:
            i = buf.find(MAGIC, i)
            if i < 0 or i + 13 > len(buf):
                break
            try:
                flen = int(buf[i + 4:i + 12], 16)
            except ValueError:
                i += 4
                continue
            if flen < 0 or i + 13 + flen > len(buf):
                i += 4
                continue
            out.append(bytes(buf[i + 13:i + 13 + flen]))
            i += 13 + flen
        return out

    # 柜台连接 = 含 fdff 帧的流
    counters = {}
    for (sock, tag), buf in streams.items():
        frs = [c for c in _frames(buf) if len(c) >= 16 and c[:2] == b'\xfd\xff']
        if frs:
            counters[(sock, tag)] = frs

    done = False
    for ivhex in ivs:
        iv = bytes.fromhex(ivhex)
        ok_any = False
        for (sock, tag), frs in counters.items():
            if tag != 'C2S':
                continue
            for k, c in enumerate(frs):
                if len(c) < 16 or c[8:12] != b'\x00\x00\x10\x00':
                    continue
                try:
                    pt = zlib.decompressobj().decompress(_des_cbc(bytes(c[16:]), iv, encrypt=False))
                except Exception:
                    continue
                ok_any = True
                f = outdir / f'dec_{sock}_{k:02d}_{c[6:8].hex()}.bin'
                f.write_bytes(pt)
                print(f'  ★ IV={ivhex} 解出 {c[6:8].hex()} {len(pt)}B -> {f.name}')
        if ok_any:
            (outdir / 'session_iv.txt').write_text(ivhex)
            print(f'  [后处理] 会话IV = {ivhex} (已写 session_iv.txt)')
            done = True
            break
    if not done:
        print('  [后处理] 所有IV候选均未解出 (帧可能不属于该进程)')


if __name__ == '__main__':
    sys.exit(main())
