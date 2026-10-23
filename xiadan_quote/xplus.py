from __future__ import annotations

import base64
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, Tuple, Union

FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"
MAX_FRAME_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class WsMessage:
    ver: int
    caller: str
    act: str
    param: Any
    raw: bytes
    direction: str = ""


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("frame too large")
    return FRAME_MAGIC + f"{len(payload):08x}".encode("ascii") + payload


def iter_frames(stream: bytes) -> Iterator[bytes]:
    offset = 0
    while True:
        start = stream.find(FRAME_MAGIC, offset)
        if start < 0 or start + 12 > len(stream):
            return
        try:
            length = int(stream[start + 4 : start + 12], 16)
        except ValueError:
            offset = start + 1
            continue
        if length < 0 or length > MAX_FRAME_SIZE or start + 12 + length > len(stream):
            offset = start + 1
            continue
        yield stream[start + 12 : start + 12 + length]
        offset = start + 12 + length


def decode_message(payload: bytes, direction: str = "") -> Optional[WsMessage]:
    if not payload:
        return None
    text: Optional[str] = None
    if payload.lstrip().startswith(b"{"):
        text = payload.decode("utf-8", errors="replace")
    else:
        try:
            decoded = base64.b64decode(payload + b"=" * ((4 - len(payload) % 4) % 4))
        except Exception:
            decoded = b""
        if decoded.lstrip().startswith(b"{"):
            text = decoded.decode("utf-8", errors="replace")
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    return WsMessage(
        ver=int(value.get("ver") or 0),
        caller=str(value.get("caller") or ""),
        act=str(value.get("act") or ""),
        param=value.get("param"),
        raw=payload,
        direction=direction,
    )


def encode_message(
    act: str,
    param: Any = "",
    ver: int = 5,
    caller: str = "xiadan",
) -> bytes:
    value = {"param": param, "ver": ver, "caller": caller, "act": act}
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return base64.b64encode(text.encode("utf-8"))


def build_heartbeat() -> bytes:
    return b"\x00\x00\x00"


def iter_raw_capture(path: Union[str, Path]) -> Iterator[Tuple[str, bytes]]:
    data = Path(path).read_bytes()
    offset = 0
    while offset + 5 <= len(data):
        length = struct.unpack_from("<I", data, offset)[0]
        end = data.find(b"\x00", offset + 4)
        if end < 0:
            return
        tag = data[offset + 4 : end].decode("latin1")
        payload = data[end + 1 : end + 1 + length]
        if len(payload) != length:
            return
        yield tag, payload
        offset = end + 1 + length


def iter_capture_frames(path: Union[str, Path]) -> Iterator[Tuple[str, bytes]]:
    for tag, raw in iter_raw_capture(path):
        for payload in iter_frames(raw):
            yield tag, payload


def iter_capture_messages(path: Union[str, Path]) -> Iterator[WsMessage]:
    for tag, payload in iter_capture_frames(path):
        message = decode_message(payload, tag)
        if message is not None:
            yield message


class XiadanWsClient:
    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buffer = bytearray()

    def connect(self) -> None:
        if self.sock is not None:
            return
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self._buffer.clear()

    def __enter__(self) -> "XiadanWsClient":
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def send_frame(self, payload: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("client is not connected")
        self.sock.sendall(encode_frame(payload))

    def send_message(
        self,
        act: str,
        param: Any = "",
        ver: int = 5,
        caller: str = "xiadan",
    ) -> None:
        self.send_frame(encode_message(act, param, ver, caller))

    def send_heartbeat(self) -> None:
        self.send_frame(build_heartbeat())

    def _read_exact(self, size: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("client is not connected")
        while len(self._buffer) < size:
            chunk = self.sock.recv(max(4096, size - len(self._buffer)))
            if not chunk:
                raise ConnectionError("connection closed")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def recv_frame(self) -> bytes:
        header = self._read_exact(12)
        if header[:4] != FRAME_MAGIC:
            raise ValueError("invalid xiadan-plus frame")
        length = int(header[4:12], 16)
        if length > MAX_FRAME_SIZE:
            raise ValueError("frame too large")
        return self._read_exact(length)

    def recv_message(self) -> Optional[WsMessage]:
        while True:
            message = decode_message(self.recv_frame())
            if message is not None:
                return message

    def iter_messages(self) -> Iterator[WsMessage]:
        while True:
            message = self.recv_message()
            if message is not None:
                yield message
