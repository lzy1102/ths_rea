# -*- coding: utf-8 -*-
"""
同花顺交易协议 - 实时挂钩取证脚本
挂 hcrypt.dll (conv*/hash*/pkc*) + zlib1.dll (deflate*/inflate*) + 帧构建器 0x2cb1d20

用法:
    python tools/live_hook.py [pid]        # 默认 pid=自动找 xiadan.exe
    (运行后去客户端点: 交易 -> 查询资金/委托/成交, 等几秒, 按 Ctrl+C 结束)

输出: captures/live_hook.log  (全部调用: 算法/密钥/IV/输入/输出 十六进制)
"""
import sys
import time
import json
import frida

LOG = open("captures/live_hook.log", "w", encoding="utf-8")

def log(s):
    print(s, flush=True)
    LOG.write(s + "\n")
    LOG.flush()

def find_pid():
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() == "xiadan.exe":
            return p.pid
    raise SystemExit("xiadan.exe 未运行")

pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
log(f"=== attach pid={pid} ===")

JS = r"""
function looksPtr(v) {
    try {
        var x = v.toString();
        if (x.length > 10) return false;
        return v.compare(ptr('0x10000')) > 0 && v.compare(ptr('0x7ffff000')) < 0;
    } catch (e) { return false; }
}

function dumpAround(fn, args, n) {
    for (var i = 0; i < n; i++) {
        try {
            var v = args[i];
            if (!looksPtr(v)) continue;
            // 猜测长度: 后面的某个小整数
            var len = 64;
            for (var j = i + 1; j < n; j++) {
                try {
                    var iv = args[j].toInt32();
                    if (iv > 0 && iv < 0x100000) { len = Math.min(iv, 256); break; }
                } catch (e) {}
            }
            var buf = v.readByteArray(len);
            send({ev: 'mem', fn: fn, argidx: i, addr: v.toString(), len: len}, buf);
        } catch (e) {}
    }
}

function getExport(dll, fn) {
    try {
        var m = Process.getModuleByName(dll);
        return m.getExportByName(fn);
    } catch (e) { return null; }
}

function hookExport(dll, fn, nargs) {
    var p = getExport(dll, fn);
    if (p === null) { send({ev: 'hook_skip', fn: fn, dll: dll}); return; }
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                send({ev: 'call', fn: fn, addr: p.toString(),
                      a: [args[0].toString(), args[1].toString(), args[2].toString(),
                          args[3].toString(), args[4].toString()]});
                dumpAround(fn, args, nargs);
            },
            onLeave: function (retval) {
                send({ev: 'ret', fn: fn, r: retval.toString()});
            }
        });
        send({ev: 'hooked', fn: fn, addr: p.toString()});
    } catch (e) {
        send({ev: 'hook_fail', fn: fn, err: e.toString()});
    }
}

var hcryptFns = ['convCreate','convCtrl','convData','convInit','convUpdate','convFinal',
                 'convBytesToKey','convAlgCtrl','convDestroy',
                 'hashCreate','hashCtrl','hashData','hashUpdate','hashFinal','hashAlgData',
                 'hcryptInit','pkcCreate','pkcCtrl','pkcEncrypt','pkcDecrypt'];
hcryptFns.forEach(function (f) { hookExport('hcrypt.dll', f, 5); });

var zlibFns = ['deflate','deflateInit_','deflateInit2_','deflateSetDictionary','deflateReset',
               'inflate','inflateInit_','inflateInit2_','inflateSetDictionary','inflateReset',
               'compress','compress2','uncompress','adler32','crc32'];
zlibFns.forEach(function (f) { hookExport('zlib1.dll', f, 5); });

// 帧构建器 (绝对VA原入口 — frida自处理E9热补丁)
try {
    var fb = ptr('0x2cb1d20');
    var target = fb;
    send({ev: 'fb_target', t: target.toString()});
    Interceptor.attach(target, {
        onEnter: function (args) {
            var buf = null;
            this.len = -1;
            try { this.len = args[1].toInt32(); } catch (e) { this.len = -1; }
            try { buf = args[0].readByteArray(Math.min(Math.abs(this.len), 1024)); } catch (e2) { buf = null; }
            var info = {ev: 'frame', len: this.len, data: this.len >= 0 ? args[0].toString() : '?'};
            try { info.ecx = this.context.ecx.toString(); } catch (e3) {}
            try { info.ret = this.returnAddress.toString(); } catch (e5) {}
            try {
                info.stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(function (a) { return a.toString(); });
            } catch (e6) { info.stack = []; }
            // 提取连接对象里的待发消息 (0xfc) 和编码缓存 (0x10c)
            try {
                var conn = this.context.ecx;
                var msg = conn.add(0xfc).readPointer();
                info.msg = msg.toString();
                if (!msg.isNull()) {
                    send({ev: 'connmsg', at: msg.toString()}, msg.readByteArray(0x40));
                    var s1 = msg.add(8).readPointer();
                    var l1 = msg.add(0xc).readInt();
                    info.s1 = s1.toString(); info.l1 = l1;
                    if (!s1.isNull() && l1 > 0 && l1 < 0x100000) {
                        send({ev: 'msgstr', at: s1.toString(), len: l1}, s1.readByteArray(Math.min(l1, 4096)));
                    }
                }
            } catch (e7) { info.derr = e7.toString(); }
            // 大帧时: dump 连接对象 + payload 周边
            try {
                if (this.len > 50) {
                    send({ev: 'connwin', at: this.context.ecx.toString()}, this.context.ecx.readByteArray(0x160));
                    try { send({ev: 'payloadwin', at: args[0].sub(0x100).toString()}, args[0].sub(0x100).readByteArray(0x780)); } catch (ew) { info.werr = ew.toString(); }
                }
            } catch (e8) { info.cerr = e8.toString(); }
            try { send(info, buf); } catch (e4) { send({ev: 'frame_err', err: e4.toString()}); }
        },
        onLeave: function (r) {
            try { send({ev: 'frame_ret', r: r.toString()}); } catch (e) {}
        }
    });
    send({ev: 'hooked', fn: 'frameBuilder@' + target.toString()});
} catch (e) { send({ev: 'hook_fail', fn: 'frameBuilder', err: e.toString()}); }

// ---- 网络接收挂钩 (采线上帧) ----
function hookRecv(dll, fn) {
    var p = getExport(dll, fn);
    if (p === null) { send({ev: 'hook_skip', fn: fn, dll: dll}); return; }
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.buf = args[1];
                this.maxlen = args[2].toInt32();
            },
            onLeave: function (r) {
                try {
                    var n = r.toInt32();
                    if (n > 0 && this.buf) {
                        var b = this.buf.readByteArray(Math.min(n, 4096));
                        send({ev: 'recv', fn: fn, n: n}, b);
                    }
                } catch (e) { send({ev: 'recv_err', err: e.toString()}); }
            }
        });
        send({ev: 'hooked', fn: fn + '@' + dll});
    } catch (e) { send({ev: 'hook_fail', fn: fn, err: e.toString()}); }
}
hookRecv('ws2_32.dll', 'recv');
hookRecv('ws2_32.dll', 'recvfrom');

function hookSend(dll, fn) {
    var p = getExport(dll, fn);
    if (p === null) return;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                try {
                    var n = args[2].toInt32();
                    if (n > 0) {
                        var b = args[1].readByteArray(Math.min(n, 4096));
                        send({ev: 'send', fn: fn, n: n}, b);
                    }
                } catch (e) {}
            }
        });
        send({ev: 'hooked', fn: fn + '@' + dll});
    } catch (e) {}
}
hookSend('ws2_32.dll', 'send');

send({ev: 'ready'});
"""

session = frida.attach(pid)
script = session.create_script(JS)

def on_message(msg, data):
    if msg.get("type") != "send":
        log(f"[frida-{msg.get('type')}] {msg}")
        return
    p = msg["payload"]
    ev = p.get("ev")
    if ev == "mem" and data:
        hexs = data.hex(" ")
        log(f"    mem[{p['fn']}].a{p['argidx']} @{p['addr']} len={p['len']}: {hexs[:400]}")
    elif ev == "call":
        log(f"[CALL] {p['fn']} args={p['a']}")
    elif ev == "ret":
        log(f"[RET ] {p['fn']} -> {p['r']}")
    elif ev == "frame":
        log(f"[FRAME] ecx={p.get('ecx')} len={p.get('len')} data={p.get('data')} ret={p.get('ret')}")
        st = p.get('stack') or []
        if st:
            log(f"    调用栈: {' '.join(st[:12])}")
        if p.get('msg'):
            log(f"    conn+0xfc msg={p.get('msg')} s1={p.get('s1')} l1={p.get('l1')}")
    elif ev == "connwin" and data:
        log(f"    [连接对象@{p.get('at')} {len(data)}B]: {data.hex(' ')}")
    elif ev == "payloadwin" and data:
        log(f"    [payload窗口@{p.get('at')}]: {data.hex(' ')}")
        log(f"    窗口ASCII: {repr(data[:400])}")
    elif ev == "connmsg" and data:
        log(f"    [msg对象@{p.get('at')}]: {data.hex(' ')[:200]}")
    elif ev == "msgstr" and data:
        log(f"    [msg文本@{p.get('at')} len={p.get('len')}]: {data.hex(' ')[:400]}")
        try:
            log(f"    文本: {data[:200].decode('gbk','replace')}")
        except Exception:
            pass
        if data:
            log(f"    frame数据: {data.hex(' ')[:800]}")
    elif ev == "frame_ret":
        log(f"[FRAME-RET] {p['r']}")
    elif ev == "recv" and data:
        log(f"[RECV] {p.get('n')}B: {data.hex(' ')[:800]}")
    elif ev == "send" and data:
        log(f"[SEND] {p.get('n')}B: {data.hex(' ')[:800]}")
    elif ev in ("recv_err", "frame_err"):
        pass
    elif ev == "hooked":
        log(f"[OK] 已挂钩 {p['fn']} @ {p['addr']}")
    elif ev == "hook_fail":
        log(f"[FAIL] 挂钩失败 {p['fn']}: {p['err']}")
    elif ev == "frame_sig_fail":
        log(f"[WARN] 帧构建器字节不符: {p.get('bytes')}")
    elif ev == "ready":
        log("[READY] 挂钩全部就绪 — 现在去客户端: 交易->查询(资金/委托/成交)!")
    else:
        log(json.dumps(p, ensure_ascii=False)[:500])

script.on("message", on_message)
script.load()
log("脚本已加载, 等待事件... (Ctrl+C 或等待超时退出)")
import time as _t
_max = float(sys.argv[2]) if len(sys.argv) > 2 else 0
_start = _t.time()
try:
    while True:
        time.sleep(1)
        if _max and _t.time() - _start > _max:
            break
except KeyboardInterrupt:
    pass
except Exception as e:
    log(f"=== 异常: {e} ===")
log("=== 退出 ===")
try:
    session.detach()
except Exception:
    pass
LOG.close()
