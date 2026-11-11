from __future__ import annotations

import asyncio
import json
from typing import NoReturn

from noise.connection import Keypair, NoiseConnection

from devmon.shared.framing import ConnectionClosed, FrameTooLarge, encode_frame, read_frame
from devmon.shared.keys import fingerprint, normalize_fingerprint

PROTOCOL_NAME = b"Noise_XX_25519_AESGCM_SHA256"
MAX_MESSAGE = 1_048_576

# 65 000 + 1 flag byte + 16-byte AEAD tag stays under Noise's 65 535-byte message cap.
CHUNK = 65_000
# A full-size message needs 17 chunks; more than this is a peer stalling us with empty ones.
MAX_CHUNKS = 64
_MORE = b"\x01"
_LAST = b"\x00"


class HubKeyMismatch(Exception):
    pass


class HandshakeError(Exception):
    pass


class MessageTooLarge(Exception):
    pass


# These two helpers are the only code that touches noiseprotocol internals.
# In 0.3.x the peer's static key is stored only as `HandshakeState.rs`
# (`NoiseProtocol.keypairs["rs"]` is never written), and processing the final
# handshake message calls `handshake_done()`, which deletes
# `noise_protocol.handshake_state` inside that same read/write call. So the
# handshake state must be captured before the read that ends the handshake.


def _capture_handshake_state(conn: NoiseConnection) -> object:
    return conn.noise_protocol.handshake_state


def _remote_static(handshake_state: object) -> bytes:
    """The peer's static public key from a handshake state captured earlier."""
    rs = getattr(handshake_state, "rs", None)
    if rs is None:
        raise HandshakeError("remote static key not available")
    return bytes(rs.public_bytes)


def _new_connection(static_priv: bytes, initiator: bool) -> NoiseConnection:
    conn = NoiseConnection.from_name(PROTOCOL_NAME)
    if initiator:
        conn.set_as_initiator()
    else:
        conn.set_as_responder()
    conn.set_keypair_from_private_bytes(Keypair.STATIC, static_priv)
    conn.start_handshake()
    return conn


async def _send_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(encode_frame(payload))
    await writer.drain()


def _fail_handshake(writer: asyncio.StreamWriter, exc: Exception) -> NoReturn:
    writer.close()
    if isinstance(exc, HandshakeError):
        raise exc
    raise HandshakeError(f"handshake failed: {exc!r}") from exc


class SecureChannel:
    """Encrypted JSON messages over a completed Noise session.

    One task may send while another receives; concurrent recv() calls are not supported.
    """

    def __init__(
        self,
        conn: NoiseConnection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_static: bytes,
    ) -> None:
        self._conn = conn
        self._reader = reader
        self._writer = writer
        self.remote_static = remote_static
        # On Python 3.9 two tasks awaiting drain() on one paused writer trips an assertion
        # in asyncio (fixed in 3.10), which would look like a dropped link. The agent sends
        # from its metrics and database loops at once, so sends take turns.
        self._send_lock = asyncio.Lock()

    async def send(self, obj: dict) -> None:
        """Raises MessageTooLarge (channel stays open) if the JSON exceeds MAX_MESSAGE."""
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_MESSAGE:
            raise MessageTooLarge(f"message of {len(data)} bytes exceeds {MAX_MESSAGE}")
        async with self._send_lock:
            frames = []
            for start in range(0, len(data), CHUNK):
                flag = _LAST if start + CHUNK >= len(data) else _MORE
                frames.append(encode_frame(self._conn.encrypt(flag + data[start : start + CHUNK])))
            # Encrypt and write with no await between, so nonces go out in the order used.
            self._writer.write(b"".join(frames))
            await self._writer.drain()

    async def recv(self) -> dict:
        """Return the next message.

        Closes the channel and raises ConnectionClosed on EOF, a bad frame, a decrypt
        failure or invalid JSON; closes it and raises MessageTooLarge past MAX_MESSAGE.
        """
        parts = []
        total = 0
        while True:
            try:
                frame = await read_frame(self._reader)
            except ConnectionClosed:
                self.close()
                raise
            except (FrameTooLarge, OSError) as exc:
                self.close()
                raise ConnectionClosed(f"connection lost: {exc!r}") from exc
            try:
                plain = self._conn.decrypt(frame)
            except Exception as exc:
                # Tampered or out-of-order ciphertext: the session can't be trusted any more.
                self.close()
                raise ConnectionClosed("message failed authentication") from exc
            if not plain or plain[0] not in (0, 1):
                self.close()
                raise ConnectionClosed("malformed chunk")
            total += len(plain) - 1
            if total > MAX_MESSAGE:
                self.close()
                raise MessageTooLarge(f"incoming message exceeds {MAX_MESSAGE} bytes")
            parts.append(bytes(plain[1:]))
            if plain[0] == 0:
                break
            if len(parts) >= MAX_CHUNKS:
                self.close()
                raise ConnectionClosed("message split into too many chunks")
        try:
            obj = json.loads(b"".join(parts).decode("utf-8"))
        except ValueError as exc:
            self.close()
            raise ConnectionClosed("message is not valid JSON") from exc
        if not isinstance(obj, dict):
            self.close()
            raise ConnectionClosed("message is not a JSON object")
        return obj

    def close(self) -> None:
        self._writer.close()


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    static_priv: bytes,
    expected_hub_fingerprint: str,
) -> SecureChannel:
    """Run the Noise XX handshake as initiator (the agent).

    Raises HubKeyMismatch if the hub's static key does not match the expected
    fingerprint; message 3 is then never sent, so the agent's static key is not
    revealed. Any other failure, including the hub closing the connection
    mid-handshake, raises HandshakeError. The writer is closed on every failure.
    """
    try:
        conn = _new_connection(static_priv, initiator=True)
        hs = _capture_handshake_state(conn)
        await _send_frame(writer, conn.write_message())
        conn.read_message(await read_frame(reader))
        hub_static = _remote_static(hs)
    except Exception as exc:
        _fail_handshake(writer, exc)

    if normalize_fingerprint(fingerprint(hub_static)) != normalize_fingerprint(
        expected_hub_fingerprint
    ):
        writer.close()
        raise HubKeyMismatch(
            f"hub key {fingerprint(hub_static)} does not match expected {expected_hub_fingerprint}"
        )

    try:
        await _send_frame(writer, conn.write_message())
        if not conn.handshake_finished:
            raise HandshakeError("handshake did not finish after message 3")
    except Exception as exc:
        _fail_handshake(writer, exc)
    return SecureChannel(conn, reader, writer, hub_static)


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    static_priv: bytes,
) -> SecureChannel:
    """Run the Noise XX handshake as responder (the hub).

    The agent's static key is known only after message 3. Every failure,
    including the agent closing the connection mid-handshake (e.g. after it
    rejected our key), raises HandshakeError; the writer is closed.
    """
    try:
        conn = _new_connection(static_priv, initiator=False)
        # Must be taken now: reading message 3 deletes it from the connection.
        hs = _capture_handshake_state(conn)
        conn.read_message(await read_frame(reader))
        await _send_frame(writer, conn.write_message())
        conn.read_message(await read_frame(reader))
        if not conn.handshake_finished:
            raise HandshakeError("handshake did not finish after message 3")
        agent_static = _remote_static(hs)
    except Exception as exc:
        _fail_handshake(writer, exc)
    return SecureChannel(conn, reader, writer, agent_static)
