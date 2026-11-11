from __future__ import annotations

import asyncio
import struct

# Noise caps a single message at 65535 bytes, so a frame can never be larger.
MAX_FRAME = 65_535


class FrameTooLarge(Exception):
    pass


class ConnectionClosed(Exception):
    pass


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME:
        raise FrameTooLarge(f"payload of {len(payload)} bytes exceeds {MAX_FRAME}")
    return struct.pack(">I", len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader, max_len: int = MAX_FRAME) -> bytes:
    try:
        header = await reader.readexactly(4)
        (length,) = struct.unpack(">I", header)
        # Check before reading so a hostile peer cannot make us buffer a huge body.
        if length > max_len:
            raise FrameTooLarge(f"declared length {length} exceeds {max_len}")
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionClosed("connection closed mid-frame") from exc
