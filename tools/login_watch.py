# -*- coding: utf-8 -*-
"""登录对照抓包: 记录 xiadan.exe 的原始收发 (send/recv) + connect 顺序.
用于: 新鲜 C2S#1 的 16B 与 S2C#0 材料的关系; sess 分配条件; 连接顺序.
用法: python tools/login_watch.py [pid] [seconds]"""
import sys
import time
import frida

pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
if pid is None:
    print("用法: python tools/login_watch.py <pid> [seconds]")
    sys.exit(1)

LOG = open("captures/login_watch.log", "w", encoding="utf-8")
FOUT = open("captures/login_watch_raw.bin", "wb")

def log(s):
    print(s, flush=True)
    LOG.write(s + "\n")
    LOG.flush()

JS = r"""
var seq = 0;
function dump(tag, ptrIn, len, extra) {
    var n = Math.min(len, 2048);
    try {
        var b = ptrIn.readByteArray(n);
        send({ev: 'io', tag: tag, seq: seq, len: len, extra: extra || ''}, b);
        seq++;
    } catch (e) {}
}
try {
    var ws = Process.getModuleByName('ws2_32.dll');
    var conn = ws.getExportByName('connect');
    Interceptor.attach(conn, {
        onEnter: function (args) {
            try {
                var port = args[1].add(2).readU16();
                // sockaddr_in: family(2) + port(2, BE) + ip(4)
                var ipb = args[1].add(4).readByteArray(4);
                var ip = new Uint8Array(ipb);
                var rport = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
                send({ev: 'connect', ip: ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+ip[3], port: rport});
            } catch (e) { send({ev: 'connect_err', err: e.toString()}); }
        }
    });
    send({ev: 'hooked', at: 'connect'});
} catch (e) { send({ev: 'hookerr', at: 'connect', err: e.toString()}); }
['send', 'recv'].forEach(function (fn) {
    try {
        var addr = ws.getExportByName(fn);
        if (fn === 'send') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var len = -1;
                    try { len = args[2].toInt32(); } catch (e) {}
                    if (len > 0 && len < 0x100000) dump('C2S', args[1], len, '');
                }
            });
        } else {
            Interceptor.attach(addr, {
                onEnter: function (args) { this.buf = args[1]; },
                onLeave: function (retval) {
                    var n = -1;
                    try { n = retval.toInt32(); } catch (e) {}
                    if (n > 0 && n < 0x100000) dump('S2C', this.buf, n, '');
                }
            });
        }
        send({ev: 'hooked', at: fn});
    } catch (e) { send({ev: 'hookerr', at: fn, err: e.toString()}); }
});
send({ev: 'ready'});
"""

session = frida.attach(pid)
script = session.create_script(JS)

def on_message(msg, data):
    if msg.get("type") != "send":
        log(f"[{msg.get('type')}] {msg}")
        return
    p = msg["payload"]
    ev = p.get("ev")
    if ev == "io" and data is not None:
        FOUT.write(len(data).to_bytes(4, 'little') + p["tag"].encode() + b'\x00' + data)
        FOUT.flush()
        log(f"[{p['tag']} #{p['seq']}] {p.get('len')}B head={data[:24].hex(' ')}")
    elif ev == "connect":
        log(f"[CONNECT] {p['ip']}:{p['port']}")
    elif ev == "ready":
        log("[READY] 记录中...")
    else:
        log(str(p)[:200])

script.on("message", on_message)
script.load()
log("运行中...")
maxs = float(sys.argv[2]) if len(sys.argv) > 2 else 600
t0 = time.time()
try:
    while True:
        time.sleep(1)
        if time.time() - t0 > maxs:
            break
except KeyboardInterrupt:
    pass
session.detach()
LOG.close()
FOUT.close()
