# -*- coding: utf-8 -*-
"""密钥嗅探: 挂钩 xiadan.exe 的 DES 密钥装载函数 (0xe35230), 收齐所有连接通道的
密钥/IV, 用于解开非交易通道 (资讯/资产服务) 的密文。

用法 (需 pip install "ths-trade-client[capture]"):
    python tools/keysniff.py --timeout 120
    # 之后在同花顺里打开交易窗口(触发各通道建连), 工具会把每次密钥装载打印出来

原理 (逆向结论, 见 docs/下单逆向进展-3.md):
    0xe35230(dst, len, src) —— src 指向 32B 密钥描述符副本, 前 8B = 该通道的
    IV (KEY 固定为 b181838083888d81, 编译在 exe 内, 各通道共用)。
    挂钩该函数即可拿到"每个连接各自的 IV"。
"""
import argparse
import re
import subprocess
import sys
import time

JS = r"""
var _delta = null;
var ANCHOR = ptr('0x2c13450');
var A1 = '558bec6aff68c22a540364a1';
function hexAt(p, n) {
    try {
        var b = new Uint8Array(p.readByteArray(n));
        var s = ''; for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return null; }
}
function tryDelta(d) {
    try {
        if (hexAt(ANCHOR.add(d), 12) !== A1) return;
        _delta = d;
    } catch (e) {}
}
function findDelta() {
    var m = Process.mainModule;
    tryDelta(m.base.sub(ptr('0xe30000')));
    if (_delta === null) tryDelta(ptr(0));
    if (_delta === null) {
        try {
            var hits = Memory.scanSync(m.base, m.size, '55 8b ec 6a ff 68 c2 2a 54 03 64 a1');
            for (var i = 0; i < hits.length && _delta === null; i++) tryDelta(hits[i].address.sub(ANCHOR));
        } catch (e) {}
    }
    return _delta;
}
function A(x) { return ptr(x).add(_delta === null ? ptr(0) : _delta); }
function hookKeyLoad() {
    Interceptor.attach(A('0xe35230'), {
        onEnter: function (args) {
            try {
                var dst = args[0], src = args[2];
                send({ev: 'keyload', dst: dst.toString(), src8: hexAt(src, 8), src16: hexAt(src, 16),
                      t: Date.now()});
            } catch (e) {}
        }
    });
}
if (findDelta() !== null) {
    hookKeyLoad();
    send({ev: 'ready', delta: _delta.toString()});
} else {
    send({ev: 'fatal', err: '未定位模块基址'});
}
"""


def find_xiadan_pid():
    try:
        out = subprocess.check_output('tasklist /FI "IMAGENAME eq xiadan.exe" /FO CSV /NH',
                                      shell=True).decode('gbk', 'replace')
        m = re.search(r'xiadan\.exe","(\d+)"', out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description='嗅探 xiadan 各连接通道的 DES IV (密钥装载钩子)')
    ap.add_argument('--pid', type=int)
    ap.add_argument('--timeout', type=int, default=120, help='监听秒数')
    ap.add_argument('--wait', type=int, default=120, help='xiadan 未运行时等待其启动的秒数')
    a = ap.parse_args()
    try:
        import frida
    except ImportError:
        print('缺少 frida: pip install "ths-trade-client[capture]"', file=sys.stderr)
        return 2

    pid = a.pid or find_xiadan_pid()
    if not pid:
        print(f'未找到 xiadan.exe, 等待其启动 (最多{a.wait}s)...')
        t0 = time.time()
        while time.time() - t0 < a.wait:
            time.sleep(2)
            pid = find_xiadan_pid()
            if pid:
                break
        if not pid:
            print('等待超时', file=sys.stderr)
            return 2
    print(f'挂载 xiadan.exe PID={pid} ...')
    session = frida.attach(pid)
    script = session.create_script(JS)
    events = []

    def on_message(msg, data):
        if msg.get('type') != 'send':
            return
        p = msg['payload']
        if p.get('ev') == 'ready':
            print(f'已挂钩密钥装载函数 (delta={p["delta"]})。现在在同花顺里打开交易窗口。')
        elif p.get('ev') == 'fatal':
            print('挂钩失败:', p.get('err'), file=sys.stderr)
        elif p.get('ev') == 'keyload':
            t = time.strftime('%H:%M:%S')
            print(f'  [{t}] IV={p["src8"]}  (16B={p["src16"]})')
            events.append(p)

    script.on('message', on_message)
    script.load()
    t0 = time.time()
    try:
        while time.time() - t0 < a.timeout:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    script.unload()
    session.detach()
    ivs = list(dict.fromkeys(e['src8'] for e in events))
    print(f'\n共捕获 {len(events)} 次密钥装载, {len(ivs)} 个不同 IV:')
    for v in ivs:
        print('  ', v)
    if ivs:
        print('\n用法: 用这些 IV 分别尝试解密各通道:')
        print('  from ths_client.trade_crypt.body_codec import s2c_decrypt')
        print('  s2c_decrypt(body, bytes.fromhex("<IV>"))')
    return 0


if __name__ == '__main__':
    sys.exit(main())