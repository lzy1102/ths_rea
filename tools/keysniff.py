# -*- coding: utf-8 -*-
"""密钥嗅探: 挂钩 xiadan.exe 的 DES 密钥装载函数 (RVA 0xa35230), 收齐所有连接通道的
密钥/IV, 用于解开非交易通道 (资讯/资产服务) 的密文。

用法 (需 pip install "ths-trade-client[capture]"):
    python tools/keysniff.py --timeout 120
    # 之后在同花顺里打开交易窗口(触发各通道建连), 工具会把每次密钥装载打印出来

原理 (逆向结论, 见 docs/下单逆向进展-3.md):
    0xa35230(dst, len, src) —— src 指向 32B 密钥描述符副本, 前 8B = 该通道的
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
var KEYLOAD_RVA = 0xa35230;   // RVA(不是VA); 绝对地址 = 模块基址 + RVA
                             // (实测本版本 xiadan.exe: 序言 50 51 83 ec 14 53 56 57 @base+0xa35230)
var PROLOGUE = [0x50,0x51,0x83,0xec,0x14,0x53,0x56,0x57];  // push eax; push ecx; sub esp,0x14; push ebx/esi/edi
function prologueHex() { return PROLOGUE.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function hexAt(p, n) {
    try {
        var b = new Uint8Array(p.readByteArray(n));
        var s = ''; for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return null; }
}
function findDelta() {
    // PE ImageBase = 0x400000, 这里的地址都是 RVA -> delta 就是模块基址
    var base = Process.mainModule.base;
    try {
        if (hexAt(base.add(KEYLOAD_RVA), 8) === prologueHex()) { _delta = base; return _delta; }
        // 基址推导不对时, 全模块扫特征序言反推
        var hits = Memory.scanSync(base, base.readU32(), PROLOGUE.slice(0, 6).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));
        for (var i = 0; i < hits.length; i++) {
            var cand = hits[i].address.sub(KEYLOAD_RVA);
            if (hexAt(cand.add(KEYLOAD_RVA), 8) === prologueHex()) { _delta = cand; return _delta; }
        }
    } catch (e) {}
    return null;
}
function A(x) { return ptr(x).add(_delta === null ? ptr(0) : _delta); }
function hookKeyLoad() {
    Interceptor.attach(A(KEYLOAD_RVA), {
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