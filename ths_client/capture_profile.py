# -*- coding: utf-8 -*-
"""字段提取工具: 从真实 xiadan 客户端流量中提取账号配置。

用法 (需先 pip install 'ths-trade-client[capture]'):

    ths-capture-profile                 # 自动找 xiadan.exe 并挂载
    ths-capture-profile --pid 1234      # 指定进程
    ths-capture-profile --out my.json --timeout 180

流程: 启动工具 -> 在 xiadan 里登录/打开交易界面 -> 工具自动抓取并解密,
输出 local_profile.json (zjzh/gdzh_sh/gdzh_sz/name/deptid/verinfo/host)。

原理: 只挂 ws2_32 的 send/recv/connect (与客户端版本无关), 捕获柜台连接
(fdff帧) 的登录帧(zlib明文)与后续加密帧(用S2C#1的IV解密), 提取字段。
"""
import argparse
import json
import re
import struct
import sys
import time
from pathlib import Path

FRAME_MAGIC = b'\xfd\xfd\xfd\xfd'

JS = r"""
var seq = 0;
function dump(tag, sock, ptrIn, len) {
    var n = Math.min(len, 8192);
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
    send({ev: 'ready'});
} catch (e) { send({ev: 'fatal', err: e.toString()}); }
"""


# ---------------- 帧解析 (轻量, 不依赖包内模块以便独立排错) ----------------
def parse_frame(buf):
    i = buf.find(FRAME_MAGIC)
    if i < 0:
        return None, b''
    buf = buf[i:]
    if len(buf) < 13:
        return None, buf
    try:
        ln = int(buf[4:12].decode('ascii'), 16)
    except ValueError:
        return None, buf[1:]
    if ln <= 0 or ln > 0x1000000:
        return None, buf[1:]
    if len(buf) < 13 + ln:
        return None, buf
    return {'len': ln, 'content': bytes(buf[13:13 + ln])}, buf[13 + ln:]


def _frames(stream):
    buf = bytes(stream)
    while True:
        fr, buf = parse_frame(buf)
        if fr is None:
            return
        yield fr


def _kv(text, key):
    m = re.search(re.escape(key) + r'=([^\n\x00]*)', text)
    return m.group(1).strip() if m else ''


def extract_from_streams(c2s: dict, s2c: dict, conns: dict):
    """从按socket分流的字节流中提取字段。返回 (profile, notes)。"""
    import zlib
    prof, notes = {}, []

    # 1) 找柜台连接: 端口8002 且流含 fdff 帧
    counter_socks = [s for s, d in c2s.items() if FRAME_MAGIC in d]
    counter_socks += [s for s, d in s2c.items() if FRAME_MAGIC in d]
    counter_socks = list(dict.fromkeys(counter_socks))
    if not counter_socks:
        return None, ['未发现柜台连接(fdff帧)']
    for s in counter_socks:
        if conns.get(s, {}).get('port') == 8002:
            prof['host'] = conns[s]['ip']
            prof['port'] = conns[s]['port']
            break

    # 2) 登录帧 (zlib明文): zjzh/户名/营业部/券商标记
    login_pt = None
    for s in counter_socks:
        for fr in _frames(c2s.get(s, b'')):
            c = fr['content']
            if len(c) >= 16 and c[:2] == b'\xfd\xff' and c[6:8] == b'\x10\x20':
                try:
                    login_pt = zlib.decompress(bytes(c[16:]))
                except Exception:
                    continue
                break
        if login_pt:
            break
    if not login_pt:
        notes.append('未捕获登录帧')
    else:
        t = login_pt.decode('gbk', 'replace')
        prof['zjzh'] = _kv(t, 'login_zh')
        d = _kv(t, 'deptid')
        v = _kv(t, 'verinfo')
        if d:
            prof['deptid'] = d
        if v:
            prof['verinfo'] = v

    # 3) 会话IV (S2C#1: type0x50 含 WTServer-DES)
    iv = None
    for s in counter_socks:
        for fr in _frames(s2c.get(s, b'')):
            c = fr['content']
            if len(c) >= 14 and c[:2] == b'\xfd\xff' and c[9] == 0x50:
                try:
                    pt = zlib.decompress(bytes(c[14:]))
                except Exception:
                    continue
                if b'WTServer-DES' in pt:
                    i = pt.find(b'E154.59.68\x00')
                    if i >= 0 and len(pt) >= i + 19:
                        iv = bytes(pt[i + 11:i + 19])
                    break
        if iv:
            break
    if not iv:
        notes.append('未提取到会话IV(股东号可能缺失)')

    # 4) 股东号: 解密C2S加密帧的 gdzh= ; 并解析0526应答账户表
    gdzhs = set()
    if iv:
        from .trade_crypt.body_codec import _des_cbc, s2c_decrypt
        for s in counter_socks:
            for fr in _frames(c2s.get(s, b'')):
                c = fr['content']
                # C2S: fdff+sess4+cmd+00001000+len1+len2+body@16 (登录帧除外, 不加密)
                if (len(c) >= 16 and c[:2] == b'\xfd\xff' and c[8:12] == b'\x00\x00\x10\x00'
                        and c[6:8] != b'\x10\x20'):
                    try:
                        pt = _des_cbc(bytes(c[16:]), iv, encrypt=False)
                        pt = zlib.decompressobj().decompress(pt)
                    except Exception:
                        continue
                    for m in re.finditer(rb'gdzh=([A-Za-z0-9]{10})', pt):
                        gdzhs.add(m.group(1).decode())
                    if 'name' not in prof:
                        mg = re.search(rb'gdxm=([^\n\x00]{2,12})', pt)
                        if mg:
                            try:
                                nm = mg.group(1).decode('gbk')
                                if 2 <= len(nm) <= 4:
                                    prof['name'] = nm
                            except Exception:
                                pass
            # 0526应答账户表 (权威): 市场名前的10位股东号
            for fr in _frames(s2c.get(s, b'')):
                c = fr['content']
                if len(c) >= 12 and c[:2] == b'\xfd\xff' and c[9] == 0x10:
                    try:
                        rpt = s2c_decrypt(bytes(c[10:]), iv)
                    except Exception:
                        continue
                    if b'\xc9\xcf\xba\xa3A\xb9\xc9' in rpt or b'\xc9\xee\xdb\xdaA\xb9\xc9' in rpt:
                        txt = rpt.decode('gbk', 'replace')
                        for mk in ('上海A股', '深圳A股'):
                            for m in re.finditer(re.escape(mk), txt):
                                seg = txt[max(0, m.start() - 150):m.start()]
                                cands = re.findall(r'([0-9]{10}|[A-Z][0-9]{9})', seg)
                                if cands:
                                    gdzhs.add(cands[-1])   # 最近的(同一行)
    for g in gdzhs:
        if g.startswith('A'):
            prof.setdefault('gdzh_sh', g)
        else:
            prof.setdefault('gdzh_sz', g)
    if not prof.get('gdzh_sh'):
        notes.append('未提取到上海股东号')
    if not prof.get('gdzh_sz'):
        notes.append('未提取到深圳股东号')
    return prof, notes


def _find_xiadan_pid():
    import subprocess
    try:
        out = subprocess.check_output('tasklist /FI "IMAGENAME eq xiadan.exe" /FO CSV /NH',
                                      shell=True).decode('gbk', 'replace')
        m = re.search(r'xiadan\.exe","(\d+)"', out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description='从 xiadan 客户端流量提取账号配置')
    ap.add_argument('--pid', type=int, help='xiadan.exe 进程ID (缺省自动查找)')
    ap.add_argument('--out', default='local_profile.json', help='输出配置文件路径')
    ap.add_argument('--timeout', type=int, default=180, help='最长等待秒数')
    a = ap.parse_args(argv)

    try:
        import frida
    except ImportError:
        print('缺少 frida: 请先 pip install "ths-trade-client[capture]"', file=sys.stderr)
        return 2

    pid = a.pid or _find_xiadan_pid()
    if not pid:
        print('未找到 xiadan.exe, 请先启动客户端或用 --pid 指定', file=sys.stderr)
        return 2
    print(f'挂载 xiadan.exe PID={pid} ...')
    session = frida.attach(pid)
    script = session.create_script(JS)

    conns, c2s, s2c = {}, {}, {}
    state = {'ready': False}

    def on_message(msg, data):
        if msg.get('type') != 'send':
            return
        p = msg['payload']
        ev = p.get('ev')
        if ev == 'ready':
            state['ready'] = True
            print('已挂载。请在客户端完成登录并打开交易界面 (工具会自动抓取)...')
        elif ev == 'fatal':
            print('挂钩失败:', p.get('err'), file=sys.stderr)
        elif ev == 'connect':
            conns[p['sock']] = {'ip': p['ip'], 'port': p['port']}
        elif ev == 'io' and data is not None:
            (c2s if p['tag'] == 'C2S' else s2c).setdefault(p['sock'], bytearray()).extend(data)

    script.on('message', on_message)
    script.load()
    t0 = time.time()
    prof = None
    while time.time() - t0 < a.timeout:
        time.sleep(1.0)
        prof, notes = extract_from_streams(c2s, s2c, conns)
        if prof and prof.get('zjzh') and prof.get('gdzh_sh') and prof.get('gdzh_sz'):
            break
    try:
        script.unload()
    except Exception:
        pass
    session.detach()

    if not prof or not prof.get('zjzh'):
        print('超时未提取到完整配置。已提取:', prof, notes, file=sys.stderr)
        return 1

    out = {k: v for k, v in prof.items() if v}
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\n===== 提取结果 (已写入 %s) =====' % a.out)
    for k in ('zjzh', 'gdzh_sh', 'gdzh_sz', 'name', 'deptid', 'verinfo', 'host', 'port'):
        if out.get(k):
            print(f'  {k:8} = {out[k]}')
    for n in notes:
        print(f'  [提示] {n}')
    print('\n使用方法: TradeClient.from_profile()  (或把该文件放到程序工作目录)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
