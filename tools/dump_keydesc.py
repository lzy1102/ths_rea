# -*- coding: utf-8 -*-
"""抓 xiadan 的完整密钥描述符(32B) + send 时的套接字, 落盘 JSONL。

    python tools/dump_keydesc.py --pid 13628 --out captures/keydesc.jsonl --timeout 600

用途: 判断模拟盘连接用的 KEY 是否仍是 b181838083888d81(只是 IV 变),
      还是整把 KEY 都换了。事件字段:
      keydesc  - 0xa35230 装载的 32 字节描述符
      send     - 该连接发送的帧(含 socket 指针与前若干字节)
"""
import argparse
import json
import subprocess
import sys
import time

JS = r"""
var _delta = null;
var RVA = 0xa35230;
var PROLOGUE = [0x50,0x51,0x83,0xec,0x14,0x53,0x56,0x57];
function prologueHex() { return PROLOGUE.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function hx(p, n) {
    try {
        var b = new Uint8Array(p.readByteArray(n));
        var s = ''; for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return null; }
}
function findDelta() {
    var base = Process.mainModule.base;
    if (hx(base.add(RVA), 8) === prologueHex()) { _delta = base; return _delta; }
    return null;
}
function A(x) { return ptr(x).add(_delta === null ? ptr(0) : _delta); }
if (findDelta() === null) { send({ev: 'fatal'}); }
else {
    Interceptor.attach(A(RVA), {
        onEnter: function (args) {
            try {
                send({ev: 'keydesc', t: Date.now(), dst: args[0].toString(),
                      desc32: hx(args[2], 32)});
            } catch (e) {}
        }
    });
    send({ev: 'ready', delta: _delta.toString()});
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--out', default='captures/keydesc.jsonl')
    ap.add_argument('--timeout', type=int, default=600)
    a = ap.parse_args()
    try:
        import frida
    except ImportError:
        print('缺少 frida', file=sys.stderr)
        return 2
    pid = a.pid
    if not pid:
        out = subprocess.check_output('tasklist /FI "IMAGENAME eq xiadan.exe" /FO CSV /NH',
                                      shell=True).decode('gbk', 'replace')
        import re
        m = re.search(r'xiadan\.exe","(\d+)"', out)
        pid = int(m.group(1)) if m else 0
    if not pid:
        print('未找到 xiadan.exe', file=sys.stderr)
        return 1
    sess = frida.attach(pid)
    script = sess.create_script(JS)
    with open(a.out, 'w', encoding='utf-8') as fh:
        def on_message(msg, data):
            if msg.get('type') == 'send':
                rec = msg['payload']
                rec['wall'] = time.strftime('%H:%M:%S')
                fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
                fh.flush()
                if rec.get('ev') == 'keydesc':
                    print(f"[{rec['wall']}] 描述符32B = {rec.get('desc32')}", flush=True)
                elif rec.get('ev') == 'ready':
                    print('已挂钩', flush=True)
                elif rec.get('ev') == 'fatal':
                    print('定位失败', flush=True)
        script.on('message', on_message)
        script.load()
        t0 = time.time()
        while time.time() - t0 < a.timeout:
            time.sleep(1)
    return 0


if __name__ == '__main__':
    sys.exit(main())
