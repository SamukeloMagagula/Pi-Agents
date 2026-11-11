from __future__ import annotations

import asyncio
import struct

import pytest

from devmon.shared.framing import (
    MAX_FRAME,
    ConnectionClosed,
    FrameTooLarge,
    encode_frame,
    read_frame,
)


async def _read(data: bytes, eof: bool = True) -> bytes:
    # Built inside the running loop so the reader binds to it and nothing leaks.
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return await read_frame(reader)


def feed_and_read(data: bytes, eof: bool = True) -> bytes:
    return asyncio.run(_read(data, eof))


def test_roundtrip():
    assert feed_and_read(encode_frame(b"hello")) == b"hello"


def test_length_prefix_is_big_endian():
    assert encode_frame(b"ab")[:4] == b"\x00\x00\x00\x02"


def test_oversized_declared_length_raises_before_reading_body():
    with pytest.raises(FrameTooLarge):
        feed_and_read(struct.pack(">I", MAX_FRAME + 1))


def test_eof_mid_frame_raises_connection_closed():
    with pytest.raises(ConnectionClosed):
        feed_and_read(struct.pack(">I", 10) + b"abc", eof=True)


def test_encode_frame_rejects_oversized_payload():
    with pytest.raises(FrameTooLarge):
        encode_frame(b"x" * (MAX_FRAME + 1))
