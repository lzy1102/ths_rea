import struct

from xiadan_quote.xplus import (
    FRAME_MAGIC,
    build_heartbeat,
    decode_message,
    encode_frame,
    encode_message,
    iter_capture_messages,
    iter_frames,
)


def test_frame_roundtrip():
    payload = b"hello"
    frame = encode_frame(payload)
    assert frame[:4] == FRAME_MAGIC
    assert frame[4:12] == b"00000005"
    assert list(iter_frames(b"junk" + frame + frame)) == [payload, payload]


def test_message_roundtrip():
    payload = encode_message(
        "change-emb-stockquote-symbol",
        {"symbol": "000651", "market": 33},
        ver=5,
        caller="xiadan",
    )
    message = decode_message(payload)
    assert message is not None
    assert message.ver == 5
    assert message.caller == "xiadan"
    assert message.act == "change-emb-stockquote-symbol"
    assert message.param == {"symbol": "000651", "market": 33}


def test_decode_plain_json_and_binary():
    message = decode_message(b'{"ver":6,"caller":"xiadan-plus","act":"heartbeat"}')
    assert message is not None
    assert message.act == "heartbeat"
    assert decode_message(b"\xc2\x01\x00\x00") is None


def test_iter_capture_messages(tmp_path):
    first = encode_frame(encode_message("show-emb-stockquote"))
    second = encode_frame(build_heartbeat())
    third = encode_frame(
        b'{"ver":6,"caller":"xiadan-plus","act":"emb-sq-stat",'
        b'"param":{"symbol":"000651","market":"33"}}'
    )
    data = b""
    for tag, frame in [(b"C2S", first), (b"C2S", second), (b"S2C", third)]:
        data += struct.pack("<I", len(frame)) + tag + b"\x00" + frame
    path = tmp_path / "capture.bin"
    path.write_bytes(data)
    messages = list(iter_capture_messages(path))
    assert [message.act for message in messages] == ["show-emb-stockquote", "emb-sq-stat"]
    assert messages[1].direction == "S2C"
    assert messages[1].param["symbol"] == "000651"
