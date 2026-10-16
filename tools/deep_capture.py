# -*- coding: utf-8 -*-
"""
深捕 v6: 密钥捕获器 (最终章)
============================
安全策略: 只挂函数入口 (绝不用中部地址!)
核心目标: 捕获 DES 密钥/上下文
- 0xe35230  密钥装载 (arg2 = 7/8字节密钥源!) ← 头号目标
- 0xe35050  DES上下文初始化
- 0xe352f0  密钥编排生成 (3次/ctx)
- 0xe34ac0 / 0xe34a90  加密包装 A/B
- 0xe34b10  8字节分组循环 (bitwise变体)
- 0xe35a50  块核心入口
- 0xe354d0  3DES块函数
- 0x2b13790 压缩封装
- 0x2d01289 zlib包装
保持: build(0x2c13450)/send(0x2ca3f80)/frame(0x2cb1d20) + 主要候选
用法: python tools/deep_capture.py [pid] [seconds]
"""
import sys
import time
import re
import os
import frida

pid = int(sys.argv[1]) if len(sys.argv) > 1 else 14904
OUTDIR = "captures/sell_cap"
os.makedirs(OUTDIR, exist_ok=True)
LOG = open("captures/deep_capture_sell.log", "w", encoding="utf-8")

def log(s):
    print(s, flush=True)
    LOG.write(s + "\n")
    LOG.flush()

JS = r"""
var armed = false;
var _saveSeq = 0;
var keyCaught = false;

var _mainMod = Process.mainModule || Process.enumerateModules()[0];

function hexAt(p, n) {
    try {
        var b = new Uint8Array(p.readByteArray(n));
        var s = ''; for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return null; }
}

var ANCHOR = ptr('0x2c13450');
var A1 = '558bec6aff68c22a540364a1';
var _delta = null;
function tryDelta(d) {
    if (_delta !== null) return;
    var p = ANCHOR.add(d);
    if (hexAt(p, 12) !== A1) return;
    if (hexAt(p.sub(0x4ed0), 6) !== '558bec6aff68') return;
    if (hexAt(p.sub(0x95e0), 12) !== '558bec6aff68821b540364a1') return;
    _delta = d;
}
function findDelta() {
    tryDelta(_mainMod.base.sub(ptr('0xe30000')));
    tryDelta(ptr(0));
    if (_delta === null) {
        try {
            var hits = Memory.scanSync(_mainMod.base, _mainMod.size, '55 8b ec 6a ff 68 c2 2a 54 03 64 a1');
            for (var i = 0; i < hits.length && _delta === null; i++) tryDelta(hits[i].address.sub(ANCHOR));
        } catch (e) {}
    }
    return _delta;
}
function A(x) { return ptr(x).add(_delta === null ? ptr(0) : _delta); }

function saveBuf(name, ptrIn, len) {
    try { send({ev: 'save', name: name}, ptrIn.readByteArray(len)); return true; }
    catch (e) { return false; }
}

function setupHooks() {

// ---- 0) F2 序列化总调度入口 0x2b10930 (arg3 = 加密描述符对象, +0x18 = key24+iv8) ----
try {
    Interceptor.attach(A('0x2b10930'), {
        onEnter: function (args) {
            var bt = [];
            try { bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 8).map(String); } catch (e) {}
            send({ev: 'F2', a0: args[0].toString(), a1: args[1].toString(), a2: args[2].toString(), a3: args[3].toString(), bt: bt});
            try { send({ev: 'F2_obj', at: args[2].toString()}, args[2].readByteArray(0x100)); } catch (e) {}
            try { send({ev: 'F2_obj2', at: args[1].toString()}, args[1].readByteArray(0x100)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0x2b10930'});
} catch (e) { send({ev: 'hookerr', at: '0x2b10930', err: e.toString()}); }

// ---- 0b) ws2_32 recv (抓服务器原始帧!) ----
try {
    var ws = Process.getModuleByName('ws2_32.dll');
    ['recv', 'WSARecv'].forEach(function (fn) {
        try {
            var addr = ws.getExportByName(fn);
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.buf = args[1];
                    this.fn = fn;
                },
                onLeave: function (retval) {
                    var n = -1;
                    try { n = retval.toInt32(); } catch (e) {}
                    if (n > 0 && n < 0x100000) {
                        send({ev: 'recv', fn: this.fn, buf: this.buf.toString(), n: n});
                        try { send({ev: 'recvbuf'}, this.buf.readByteArray(Math.min(n, 4096))); } catch (e) {}
                    }
                }
            });
            send({ev: 'hooked', at: 'ws2_32!' + fn});
        } catch (e) {}
    });
} catch (e) { send({ev: 'hookerr', at: 'ws2_32recv', err: e.toString()}); }

// ---- 1) ★密钥装载 0xe35230 (arg1=ctx+0x180目标, arg2=密钥源) ----
try {
    Interceptor.attach(A('0xe35230'), {
        onEnter: function (args) {
            send({ev: 'KEYLOAD', dst: args[0].toString(), src: args[1].toString()});
            try { send({ev: 'keybuf'}, args[1].readByteArray(0x20)); } catch (e) {}
            try { send({ev: 'keydst'}, args[0].readByteArray(0x20)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe35230'});
} catch (e) { send({ev: 'hookerr', at: '0xe35230', err: e.toString()}); }

// ---- 2) DES 上下文初始化 0xe35050 ----
try {
    Interceptor.attach(A('0xe35050'), {
        onEnter: function (args) {
            var bt = [];
            try { bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 12).map(String); } catch (e) {}
            send({ev: 'CTXINIT', a0: args[0].toString(), a1: args[1].toString(), a2: args[2].toString(), a3: args[3].toString(), bt: bt});
            try { send({ev: 'ctxbuf'}, args[2].readByteArray(0x30)); } catch (e) {}
            try { send({ev: 'ctxbuf1'}, args[1].readByteArray(0x40)); } catch (e) {}
            try { send({ev: 'ctxpre'}, args[1].sub(0x40).readByteArray(0x80)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe35050'});
} catch (e) { send({ev: 'hookerr', at: '0xe35050', err: e.toString()}); }

// ---- 3) 密钥编排 0xe352f0 ----
try {
    Interceptor.attach(A('0xe352f0'), {
        onEnter: function (args) {
            send({ev: 'SCHED', dst: args[0].toString(), src: args[1].toString(), flag: args[2].toString()});
            try { send({ev: 'schedbuf'}, args[1].readByteArray(0x20)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe352f0'});
} catch (e) { send({ev: 'hookerr', at: '0xe352f0', err: e.toString()}); }

// ---- 4) 加密包装 A/B ----
['0xe34ac0', '0xe34a90'].forEach(function (t) {
    try {
        Interceptor.attach(A(t), {
            onEnter: function (args) {
                var bt = [];
                try { bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 12).map(String); } catch (e) {}
                send({ev: 'CRYPTO', at: t, a0: args[0].toString(), a1: args[1].toString(),
                      a2: args[2].toString(), a3: args[3].toString(), a4: args[4].toString(), a5: args[5].toString(), bt: bt});
                try { send({ev: 'cryptobuf'}, args[0].readByteArray(0x40)); } catch (e) {}
            }
        });
        send({ev: 'hooked', at: t});
    } catch (e) { send({ev: 'hookerr', at: t, err: e.toString()}); }
});

// ---- 5) 8字节分组循环 0xe34b10 ----
try {
    Interceptor.attach(A('0xe34b10'), {
        onEnter: function (args) {
            send({ev: 'BLKLOOP', a0: args[0].toString(), a1: args[1].toString(),
                  a2: args[2].toString(), a3: args[3].toString(), a4: args[4].toString(), a5: args[5].toString()});
            try { send({ev: 'blkloopbuf'}, args[0].readByteArray(0x40)); } catch (e) {}
            try { send({ev: 'blkloopbuf2'}, args[2].readByteArray(0x40)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe34b10'});
} catch (e) { send({ev: 'hookerr', at: '0xe34b10', err: e.toString()}); }

// ---- 6) 块核心 0xe35a50 ----
try {
    Interceptor.attach(A('0xe35a50'), {
        onEnter: function (args) {
            send({ev: 'BLKCORE', a0: args[0].toString(), a1: args[1].toString(), a2: args[2].toString(), a3: args[3].toString()});
            try { send({ev: 'blkcore0'}, args[0].readByteArray(0x40)); } catch (e) {}
            try { send({ev: 'blkcore1'}, args[1].readByteArray(0x40)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe35a50'});
} catch (e) { send({ev: 'hookerr', at: '0xe35a50', err: e.toString()}); }

// ---- 7) 3DES 块 0xe354d0 ----
try {
    Interceptor.attach(A('0xe354d0'), {
        onEnter: function (args) {
            send({ev: 'DESBLK', state: args[0].toString(), sched: args[1].toString()});
            try { send({ev: 'desblk_state'}, args[0].readByteArray(8)); } catch (e) {}
            try { send({ev: 'desblk_sched'}, args[1].readByteArray(0x20)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0xe354d0'});
} catch (e) { send({ev: 'hookerr', at: '0xe354d0', err: e.toString()}); }

// ---- 8) zlib包装 0x2d01289 / 压缩封装 0x2b13790 ----
try {
    Interceptor.attach(A('0x2b13790'), {
        onEnter: function (args) {
            send({ev: 'COMPRESS', a0: args[0].toString(), a1: args[1].toString(), a2: args[2].toString(),
                  a3: args[3].toString(), a4: args[4].toString()});
            try { send({ev: 'compressbuf'}, args[0].readByteArray(0x40)); } catch (e) {}
            try { send({ev: 'compressbuf1'}, args[1].readByteArray(0x40)); } catch (e) {}
        }
    });
    send({ev: 'hooked', at: '0x2b13790'});
} catch (e) { send({ev: 'hookerr', at: '0x2b13790', err: e.toString()}); }

// ---- 9) 构建/发送/帧 (保持) ----
try {
    Interceptor.attach(A('0x2c13450'), {
        onEnter: function (args) {
            armed = true;
            var th = this.context.ecx;
            send({ev: 'build_enter', th: th.toString()});
            saveBuf('build_a1_' + _saveSeq + '_' + args[0].toString(), args[0], 0x1000);
            _saveSeq++;
        }
    });
    send({ev: 'hooked', at: '0x2c13450'});
} catch (e) { send({ev: 'hookerr', at: '0x2c13450', err: e.toString()}); }

try {
    Interceptor.attach(A('0x2ca3f80'), {
        onEnter: function (args) {
            var cmd = hexAt(args[1].add(6), 2);
            send({ev: 'send', content: args[1].toString(), cmd: cmd});
            saveBuf('send_content_' + _saveSeq + '_' + cmd + '_' + args[1].toString(), args[1], 0x500);
            _saveSeq++;
            armed = false;
        }
    });
    send({ev: 'hooked', at: '0x2ca3f80'});
} catch (e) { send({ev: 'hookerr', at: '0x2ca3f80', err: e.toString()}); }

try {
    Interceptor.attach(A('0x2cb1d20'), {
        onEnter: function (args) {
            var len = -1; try { len = args[1].toInt32(); } catch (e) {}
            if (len > 50 && len < 0x20000) {
                send({ev: 'fr', content: args[0].toString(), len: len, hex: hexAt(args[0], 32)});
            }
        }
    });
    send({ev: 'hooked', at: '0x2cb1d20'});
} catch (e) { send({ev: 'hookerr', at: '0x2cb1d20', err: e.toString()}); }

}  // end setupHooks

// === 轮询等待 ===
var _tries = 0;
function attempt() {
    _tries++;
    if (findDelta() !== null) {
        send({ev: 'base', name: _mainMod.name, base: _mainMod.base.toString(), delta: _delta.toString(), tries: _tries});
        setupHooks();
        send({ev: 'ready'});
    } else if (_tries < 90) {
        if (_tries % 5 === 1) send({ev: 'waiting', tries: _tries});
        setTimeout(attempt, 2000);
    } else {
        send({ev: 'fatal', err: '基址校验失败'});
    }
}
attempt();
"""

session = frida.attach(pid)
script = session.create_script(JS)

def on_message(msg, data):
    if msg.get("type") != "send":
        log(f"[{msg.get('type')}] {msg}")
        return
    p = msg["payload"]
    ev = p.get("ev")
    if ev == "base":
        log(f"[BASE] {p['name']} delta={p['delta']} tries={p['tries']}")
    elif ev == "ready":
        log("[READY] 请在客户端操作: 买入 999998 (登录流量也会自动触发密钥捕获)")
    elif ev == "waiting":
        log(f"[等待] {p['tries']}...")
    elif ev == "fatal":
        log(f"[FATAL] {p['err']}")
    elif ev == "save" and data is not None:
        fn = os.path.join(OUTDIR, p["name"] + ".bin")
        open(fn, "wb").write(data)
        log(f"[SAVE] {fn} {len(data)}B")
    elif ev == "KEYLOAD":
        log(f"\n★★★[KEYLOAD] dst={p['dst']} src={p['src']}")
    elif ev == "keybuf" and data:
        log(f"   密钥源(32B): {data.hex(' ')}")
    elif ev == "keydst" and data:
        log(f"   目标区(32B): {data.hex(' ')}")
    elif ev == "CTXINIT":
        log(f"  [CTXINIT] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']}")
        if p.get("bt"): log("     BT: " + " <- ".join(p["bt"]))
    elif ev == "F2":
        log(f"\n[F2] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']}")
        if p.get("bt"): log("     BT: " + " <- ".join(p["bt"]))
    elif ev == "F2_obj" and data:
        log(f"     obj @{p['at']}: {data.hex(' ')}")
    elif ev == "F2_obj2" and data:
        log(f"     obj2 @{p['at']}: {data.hex(' ')}")
    elif ev == "recv":
        log(f"\n[RECV {p['fn']}] buf={p['buf']} n={p['n']}")
    elif ev == "recvbuf" and data:
        log(f"     {data[:160].hex(' ')}")
    elif ev == "ctxbuf1" and data:
        log(f"     a1区(key区): {data.hex(' ')}")
    elif ev == "ctxpre" and data:
        log(f"     key前0x40..: {data.hex(' ')}")
    elif ev == "ctxbuf" and data:
        log(f"     a2区: {data.hex(' ')}")
    elif ev == "SCHED":
        log(f"  [SCHED] dst={p['dst']} src={p['src']} flag={p['flag']}")
    elif ev == "schedbuf" and data:
        log(f"     src(32B): {data.hex(' ')}")
    elif ev == "CRYPTO":
        log(f"\n  [CRYPTO {p['at']}] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']} a4={p['a4']} a5={p['a5']}")
        if p.get("bt"): log("     BT: " + " <- ".join(p["bt"]))
    elif ev == "cryptobuf" and data:
        log(f"     a0(64B): {data.hex(' ')}")
    elif ev == "BLKLOOP":
        log(f"\n  [BLKLOOP] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']} a4={p['a4']} a5={p['a5']}")
    elif ev == "blkloopbuf" and data:
        log(f"     a0: {data[:32].hex(' ')}")
    elif ev == "blkloopbuf2" and data:
        log(f"     a2: {data[:32].hex(' ')}")
    elif ev == "BLKCORE":
        log(f"  [BLKCORE] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']}")
    elif ev == "blkcore0" and data:
        log(f"     a0: {data.hex(' ')}")
    elif ev == "blkcore1" and data:
        log(f"     a1: {data.hex(' ')}")
    elif ev == "DESBLK":
        log(f"  [DESBLK] state={p['state']} sched={p['sched']}")
    elif ev == "desblk_state" and data:
        log(f"     state: {data.hex(' ')}")
    elif ev == "desblk_sched" and data:
        log(f"     sched前32: {data.hex(' ')}")
    elif ev == "COMPRESS":
        log(f"\n  [COMPRESS] a0={p['a0']} a1={p['a1']} a2={p['a2']} a3={p['a3']} a4={p['a4']}")
    elif ev == "compressbuf" and data:
        log(f"     a0: {data[:32].hex(' ')}")
    elif ev == "compressbuf1" and data:
        log(f"     a1: {data[:32].hex(' ')}")
    elif ev == "build_enter":
        log(f"\n[BUILD] task={p['th']}")
    elif ev == "send":
        log(f"[SEND] content={p['content']} cmd={p.get('cmd')}")
    elif ev == "fr":
        log(f"[帧] content={p['content']} len={p['len']} {p.get('hex')}")
    elif ev == "hooked":
        log(f"[OK] 挂钩 {p['at']}")
    elif ev == "hookerr":
        log(f"[HOOKERR] {p['at']}: {p['err']}")
    else:
        log(str(p)[:300])

script.on("message", on_message)
script.load()
log("运行中...")
maxs = float(sys.argv[2]) if len(sys.argv) > 2 else 3600
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
