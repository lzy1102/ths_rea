# -*- coding: utf-8 -*-
"""柜台 TCP 连接: 问候 / 登录 / 会话(IV+sess) / 收发帧.

协议 (xiadan.exe 实测, docs/下单逆向进展-3.md 第1-18轮, 全链路已打通):
  帧  = fd fd fd fd + 8字符hex长度 + mode(00) + content (总长=13+len, len=content长)
  C2S = fd ff + sess4(4) + cmd(2) + 00 00 10 00 + len1(u16,压缩长)
        + len2(u16,明文长) + body(压缩体, 零填充到8)
      sess4: 登录帧=00000000; 登录后=服务器分配值(如84 7a cf ff)原样回显
      body = DES-CBC(zlib(明文), KEY, IV)
      明文[8:24] = md5签名槽 = md5(明文整体, 其中[8:24]清零) (登录帧除外)
  S2C zlib(0x50): fd ff + sess4 + ff ff 00 + 50 + psize(u32) + body@14 = zlib流
  S2C custom(0x10): fd ff + sess4 + ff ff 00 + 10 + body@10
      body = DES-CBC(zlib带4字节长度头(明文), KEY, IV) -> 用 s2c_decrypt

登录流程:
  1. TCP连柜台 -> 发 C2S#0 问候 (141B, 原样重放)
  2. 读 S2C#0 (服务器信息, 非fdff结构, 宽松解析)
  3. 发 C2S#1 (cmd=10 20, sess4=00000000, zlib(登录明文1132B))
  4. 循环读帧直到 S2C#1 (zlib含 b'WTServer-DES') ->
     sess4 = 该帧 content[2:6]; IV = 明文 b'E154.59.68\\x00' 之后 8 字节
  5. bootstrap() 回放启动序列(0030/0526/0126/0326/0226) 建立账户上下文
     (不做则业务消息回 "数据包无效：帐户无效")
"""
import collections
import queue
import re
import socket
import struct
import threading
import time
import zlib
from pathlib import Path

from .trade_crypt.body_codec import body_decrypt, s2c_decrypt, DES_KEY

FRAME_MAGIC = b'\xfd\xfd\xfd\xfd'
COUNTER_HOST = '114.141.180.27'
COUNTER_PORT = 8002

DATA_DIR = Path(__file__).resolve().parent / 'data'
HELLO_PATH = DATA_DIR / 'hello.bin'          # C2S#0 问候帧 (141B, 原样重放)
STARTUP_DIR = DATA_DIR / 'startup'           # 标准启动序列模板 (0030/0526/0126/0326/0226)
STARTUP_SH_DIR = DATA_DIR / 'startup_sh'     # 沪市扩展启动 (0029/0520/0126/0326/0226)

LOGIN_CMD = b'\x10\x20'
C2S_CONST = b'\x00\x00\x10\x00'
C2S_FLAG = b'\xff'


def build_content(cmd: bytes, sess: bytes, body_padded: bytes,
                            zlen: int, plen: int) -> bytes:
    """content = fdff+sess4+cmd+00001000+len1(u16)+len2(u16)+body.
    sess4 = 4字节会话字段 (登录时=00000000; 登录后=服务器分配值, 如 84 7a cf ff)。
    body_padded = zlib流零填充到8 (len1=zlen 为填充前长度)。"""
    assert len(cmd) == 2 and len(sess) == 4
    head = b'\xfd\xff' + sess + cmd + C2S_CONST
    head += struct.pack('<H', zlen) + struct.pack('<H', plen)
    return head + body_padded


def build_frame(content: bytes, mode: int = 0) -> bytes:
    """frame = magic + ascii8(len(content)) + mode + content (总长=13+len)。
    注意: 声明长度 == content长度 (mode字节不计入, 三处实测确认)。"""
    return FRAME_MAGIC + ("%08x" % len(content)).encode('ascii') + bytes([mode]) + content


def parse_frame(buf: bytes):
    """解析一帧, 返回 (frame_dict, 剩余bytes)。frame_dict: len/mode/content (len=content长度, mode不计入; 帧总长=13+len)。
    找不到魔数时向前 resync。"""
    i = buf.find(FRAME_MAGIC)
    if i < 0:
        return None, b''
    if i > 0:
        buf = buf[i:]
    if len(buf) < 13:
        return None, buf  # 等待更多数据
    try:
        ln = int(buf[4:12].decode('ascii'), 16)
    except ValueError:
        return None, buf[1:]  # 坏头, 跳过1字节继续找
    if ln <= 0 or ln > 0x1000000:
        return None, buf[1:]
    if len(buf) < 13 + ln:
        return None, buf  # 等待
    return {'len': ln, 'mode': buf[12], 'content': bytes(buf[13:13 + ln])}, buf[13 + ln:]


def parse_s2c(content: bytes) -> dict:
    """解析 S2C content。返回 dict(type, psize, body, sess)。
    type 0x50=zlib明文 (body@14, psize=u32@[10:14]); 0x10=加密 (body@[10:])。"""
    if len(content) < 14 or content[:2] != b'\xfd\xff':
        raise ValueError(f"S2C 头异常: {content[:14].hex(' ')}")
    sess = bytes(content[2:6])
    ftype = content[9]
    if ftype == 0x50:
        psize = struct.unpack('<I', content[10:14])[0]
        return {'type': 0x50, 'sess': sess, 'psize': psize, 'body': bytes(content[14:])}
    elif ftype == 0x10:
        return {'type': 0x10, 'sess': sess, 'psize': None, 'body': bytes(content[10:])}
    else:
        raise ValueError(f"未知 S2C type: {ftype:#x}")


class TradeConn:
    """柜台连接。用法见 examples/trade_live.py。"""

    def __init__(self, host: str = COUNTER_HOST, port: int = COUNTER_PORT,
                 timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self._rxbuf = b''
        self._resp_q = queue.Queue()      # 应答帧队列 (读线程)
        self._push_q = queue.Queue()      # 推送队列
        self._push_ev = threading.Event()
        self.pushes = collections.deque(maxlen=200)
        self.push_max = 200
        self.on_push = None
        self._reader_on = False
        self._reader_err = None
        self._stop = threading.Event()
        self._hb_on = False
        self._hb_stop = threading.Event()
        self.sess = bytes(4)
        self.iv = None

    # ---- 底层 ----
    def connect(self, bind_port: int = 0, dump_dir: str = None):
        self.stop_reader()
        self._reader_err = None
        while not self._resp_q.empty():
            try:
                self._resp_q.get_nowait()
            except queue.Empty:
                break
        self.close()
        self.dump_dir = dump_dir
        self._dump_seq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        if bind_port:
            self.sock.bind(('', bind_port))
        self.sock.connect((self.host, self.port))
        self._rxbuf = b''

    def _dump(self, tag: str, data: bytes):
        if not getattr(self, 'dump_dir', None):
            return
        self._dump_seq += 1
        Path(self.dump_dir).mkdir(parents=True, exist_ok=True)
        Path(self.dump_dir, '%03d_%s.bin' % (self._dump_seq, tag)).write_bytes(bytes(data))

    def close(self):
        sk, self.sock = self.sock, None
        try:
            if sk:
                sk.close()
        except OSError:
            pass

    def _recvn(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("对端关闭连接")
            out += chunk
        return bytes(out)

    def recv_frame(self) -> dict:
        """读一完整帧 (带 resync)。"""
        while True:
            fr, rest = parse_frame(self._rxbuf)
            if fr is not None:
                self._rxbuf = rest
                raw = FRAME_MAGIC + ('%08x' % fr['len']).encode('ascii') + bytes([fr['mode']]) + fr['content']
                self._dump('s2c', raw)
                return fr
            # 需要更多数据: 先消费已确认的垃圾 (保留末尾3字节防魔数截断)。
            # 注意: 必须单次 recv (服务器发完一帧就停, 等凑满会超时)。
            if self._rxbuf.find(FRAME_MAGIC) < 0:
                keep = self._rxbuf[-3:] if len(self._rxbuf) >= 3 else self._rxbuf
                self._rxbuf = keep
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError('对端关闭连接')
            self._rxbuf += chunk

    def send_frame(self, content: bytes, mode: int = 0) -> int:
        fr = build_frame(content, mode)
        self.sock.sendall(fr)
        self._dump('c2s', fr)
        return len(fr)

    def send_msg(self, wire_cmd: bytes, plaintext: bytes, iv: bytes) -> dict:
        """明文 -> zlib -> DES-CBC -> 组帧发送。返回 {len1,len2,content_len}。"""
        from .trade_crypt.body_codec import body_encrypt
        body, zlen = body_encrypt(plaintext, iv)
        content = build_content(wire_cmd, self.sess, body, zlen, len(plaintext))
        self.send_frame(content)
        return {'len1': zlen, 'len2': len(plaintext), 'content_len': len(content)}

    # ---- 登录 ----
    def greeting(self, blob: bytes = None) -> bytes:
        """发 C2S#0 问候, 收 S2C#0, 返回其 content (服务器信息, 非fdff结构)。
        blob 缺省用包内 data/hello.bin (原样重放的141B问候帧)。"""
        if blob is None:
            blob = HELLO_PATH.read_bytes()
        self.sock.sendall(blob)
        fr = self.recv_frame()
        return fr['content']

    def login(self, login_plaintext: bytes, max_wait: int = 10) -> dict:
        """发 C2S#1 登录帧; 循环收帧直到 S2C#1(WTServer-DES)。
        返回 {'sess': 4B, 'iv': 8B, 's2c1': 明文} 并更新 self.sess/self.iv。
        登录帧会话字段=00000000 (实测真客户端如此; 写 ff 会被服务端静默拒绝)。"""
        # 登录帧 body 为 zlib 明文(不加密!): 实测 C2S#1 body=78 9c 开头。
        # 但 body 区仍需零填充到8 (如 675->680), 否则服务端不分配 sess!
        z = zlib.compress(login_plaintext, 6)
        zpad = z + b'\x00' * ((-len(z)) % 8)
        content = build_content(LOGIN_CMD, bytes(4), zpad, len(z), len(login_plaintext))
        self.send_frame(content)
        for _ in range(max_wait):
            fr = self.recv_frame()
            c = fr['content']
            if len(c) >= 14 and c[:2] == b'\xfd\xff' and c[9] == 0x50:
                try:
                    pt = zlib.decompress(bytes(c[14:]))
                except Exception:
                    continue
                if b'WTServer-DES' in pt:
                    self.sess = bytes(c[2:6])
                    self.iv = self._extract_iv(pt)
                    return {'sess': self.sess, 'iv': self.iv, 's2c1': pt}
        raise TimeoutError("未收到 S2C#1 登录应答")

    @staticmethod
    def _extract_iv(s2c1_plain: bytes) -> bytes:
        """IV = 明文 b'E154.59.68\\x00' 之后 8 字节; 兜底取末8字节。"""
        i = s2c1_plain.find(b'E154.59.68\x00')
        if i >= 0 and len(s2c1_plain) >= i + 19:
            return bytes(s2c1_plain[i + 11:i + 19])
        return bytes(s2c1_plain[-8:])

    # ---- 启动序列 ----
    def bootstrap(self, iv: bytes, seq=None, tick: int = None,
                  tpl_dir: str = None, zjzh: str = None, gdzh_sh: str = None,
                  gdzh_sz: str = None, name_gbk: bytes = None,
                  deptid=None, verinfo: str = None, machine_info: dict = None) -> list:
        """回放启动序列 (0030校验股东/0526帐户/0126/0326/0226) 建立账户上下文。

        不做这一步, 业务消息 (0124/0221) 会回 "数据包无效：帐户无效"。
        模板 = 真客户端解密明文 (包内 data/startup*/*.bin), 逐条补丁:
        sess4 / tick / seq / md5签名 + 账号占位符(zjzh/gdzh/户名)。
        返回 [(wire_cmd, 应答dict), ...]。
        seq 传 trade_msg.MsgSeq(2) (登录已用1); tick 传会话内单调毫秒值。
        沪市交易需再调一次 tpl_dir=STARTUP_SH_DIR。
        zjzh/gdzh_sh/gdzh_sz/name_gbk: 真实账号配置 (模板内为脱敏占位符, 必须传入)。
        """
        from . import trade_msg as TM
        from . import machine as _machine
        if tpl_dir is None:
            tpl_dir = STARTUP_DIR
        elif isinstance(tpl_dir, str):
            tpl_dir = Path(tpl_dir)
        tpls = sorted(Path(tpl_dir).glob('*.bin'))
        if not tpls:
            raise FileNotFoundError(f"缺少启动序列模板: {tpl_dir}")
        outs = []
        for f in tpls:
            pt = bytearray(f.read_bytes())
            TM.patch_account(pt, zjzh=zjzh, gdzh_sh=gdzh_sh, gdzh_sz=gdzh_sz,
                             name_gbk=name_gbk)
            TM.patch_broker(pt, deptid=deptid, verinfo=verinfo)
            _machine.patch(pt, info=machine_info)
            pt[0x02:0x06] = self.sess
            if tick is not None:
                struct.pack_into('<I', pt, 0x88, tick & 0xFFFFFFFF)
            if seq is not None:
                struct.pack_into('<I', pt, 0x8c, seq.next())
            pt[8:24] = TM._sign(bytes(pt))
            wire = bytes([pt[6], pt[7] | 0x20])
            self.send_msg(wire, bytes(pt), iv)
            outs.append((wire, self.recv_msg()))
        return outs

    # ---- 收 S2C 业务帧 ----
    def recv_msg(self, timeout: float = None) -> dict:
        """收一帧 S2C 并解包/解密/解压。返回 {type, sess, psize, plaintext}。

        启动读线程后, 应答帧从响应队列取 (推送帧已在读线程里分流到推送队列);
        未启动读线程时退回同步 recv_frame。
        timeout: 等待应答的最长秒数 (仅队列模式有效)。
        """
        if self._reader_on:
            try:
                fr = self._resp_q.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError('等待柜台应答超时 (%.1fs)' % (timeout or 0))
            if isinstance(fr, Exception):
                raise fr
        else:
            fr = self.recv_frame()
        return self._decode_s2c(fr)

    def _decode_s2c(self, fr: dict) -> dict:
        info = parse_s2c(fr['content'])
        self.sess = info['sess']
        if info['type'] == 0x50:
            info['plaintext'] = zlib.decompress(info['body'])
        else:
            if self.iv is None:
                raise RuntimeError("custom 帧需要 IV, 请先 login()")
            info['plaintext'] = s2c_decrypt(info['body'], self.iv)
        info['text'] = info['plaintext'].decode('gbk', 'replace')
        self._dump('s2c_plain', info['plaintext'])
        return info

    # ---- 读线程: 应答/推送分流 ----
    def start_reader(self, on_push=None):
        """启动后台读线程。

        协议判据 (实测): 应答帧 type=0x10 (DES 加密), 推送帧 type=0x50 (zlib 明文,
        携带行情/成交回报 k=v: zqdm/zqmc/zgj/zdj/open/cjje/cjl/ywzt/statusflag ...)。
        on_push(dict) 在收到推送时调用 (dict 含 plaintext/text/kv/frames)。
        """
        if self._reader_on:
            return
        self._reader_on = True
        self.on_push = on_push
        self.pushes.clear()
        self._stop.clear()
        self._t = threading.Thread(target=self._reader_loop, name='ths-reader', daemon=True)
        self._t.start()

    def stop_reader(self):
        """停止读线程 (唤醒阻塞的 recv 并等待退出, 避免与新连接抢 socket)。"""
        self._reader_on = False
        self._stop.set()
        t = getattr(self, '_t', None)
        if t and t.is_alive():
            try:
                self.sock.settimeout(0.3)
            except Exception:
                pass
            t.join(timeout=2.0)
        try:
            if self.sock:
                self.sock.settimeout(self.timeout)
        except Exception:
            pass

    def _reader_loop(self):
        while not self._stop.is_set() and self.sock is not None:
            try:
                fr = self.recv_frame()
            except (socket.timeout, TimeoutError):
                continue
            except Exception as e:            # 连接断开 -> 通知等待者
                if self._stop.is_set():
                    return
                self._reader_err = e
                self._resp_q.put(e)
                return
            c = fr['content']
            t = c[9] if len(c) >= 10 else None
            if t == 0x50 and len(c) >= 14:
                try:
                    pt = zlib.decompress(bytes(c[14:]))
                except Exception:
                    self._resp_q.put(fr)
                    continue
                item = {'type': 0x50, 'sess': fr['content'][2:6], 'plaintext': pt,
                        'text': pt.decode('gbk', 'replace'),
                        'kv': dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)=([^\x00&\n]*)',
                                              pt.decode('gbk', 'replace'))),
                        'ts': time.time()}
                self.pushes.append(item)
                self._push_q.put(item)
                self._push_ev.set()
                if self.on_push:
                    try:
                        self.on_push(item)
                    except Exception:
                        pass
            elif t is None and len(c) <= 4:
                continue                        # 3/4字节保活确认帧
            else:
                self._resp_q.put(fr)

    def wait_pushes(self, timeout: float = 1.0) -> list:
        """等待并返回待处理推送 (成交回报等)。"""
        out = []
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self._push_ev.is_set():
                self._push_ev.clear()
                while not self._push_ev.is_set():
                    try:
                        out.append(self._push_q.get(timeout=max(0.05, timeout - (time.time() - t0))))
                    except queue.Empty:
                        break
                continue
            time.sleep(0.05)
        return out

    # ---- 心跳 ----
    def start_heartbeat(self, interval: float = 30.0):
        """按真客户端行为周期性发 3 字节保活帧 (content=00 00 00)。"""
        if self._hb_on:
            return
        self._hb_on = True
        self._hb_stop.clear()

        def _loop():
            while not self._hb_stop.wait(interval):
                try:
                    self.send_frame(b'\x00\x00\x00')
                except Exception:
                    return
        self._hb_t = threading.Thread(target=_loop, name='ths-hb', daemon=True)
        self._hb_t.start()

    def stop_heartbeat(self):
        self._hb_on = False
        self._hb_stop.set()
        return info
