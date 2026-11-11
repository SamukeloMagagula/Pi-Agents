from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from devmon.shared.framing import ConnectionClosed
from devmon.shared.keys import fingerprint, public_from_private
from devmon.shared.link import (
    MAX_MESSAGE,
    HandshakeError,
    HubKeyMismatch,
    MessageTooLarge,
    client_handshake,
    server_handshake,
)

TIMEOUT = 5


def _new_key():
    priv = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return priv, public_from_private(priv)


class _Hub:
    """A real server on 127.0.0.1 that runs server_handshake on the first connection."""

    def __init__(self, static_priv: bytes) -> None:
        self.static_priv = static_priv
        self.writers = []  # every writer, both sides, so shutdown closes them all
        self.server_writer = None

    async def start(self) -> None:
        self.result = asyncio.get_running_loop().create_future()
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer) -> None:
        self.writers.append(writer)
        self.server_writer = writer
        try:
            chan = await server_handshake(reader, writer, self.static_priv)
        except Exception as exc:
            self.result.set_exception(exc)
        else:
            self.result.set_result(chan)

    async def connect(self, client_priv: bytes, expected_fp: str, wrap=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        w = wrap(writer) if wrap else writer
        return await asyncio.wait_for(client_handshake(reader, w, client_priv, expected_fp), TIMEOUT)

    async def server_channel(self):
        return await asyncio.wait_for(self.result, TIMEOUT)

    async def shutdown(self) -> None:
        for w in self.writers:
            w.close()
        for w in self.writers:
            try:
                await asyncio.wait_for(w.wait_closed(), TIMEOUT)
            except Exception:
                pass  # already reset/closed by the peer; we only need it gone
        self.server.close()
        await asyncio.wait_for(self.server.wait_closed(), TIMEOUT)


async def _paired(wrap=None):
    """Return (hub, client_chan, server_chan, client_pub, server_pub)."""
    server_priv, server_pub = _new_key()
    client_priv, client_pub = _new_key()
    hub = _Hub(server_priv)
    await hub.start()
    try:
        client_chan = await hub.connect(client_priv, fingerprint(server_pub), wrap)
        server_chan = await hub.server_channel()
    except BaseException:
        await hub.shutdown()
        raise
    return hub, client_chan, server_chan, client_pub, server_pub


def test_roundtrip_both_directions():
    async def main():
        hub, client_chan, server_chan, _, _ = await _paired()
        try:
            await asyncio.wait_for(client_chan.send({"a": 1}), TIMEOUT)
            assert await asyncio.wait_for(server_chan.recv(), TIMEOUT) == {"a": 1}
            reply = {"ok": True, "items": [1, 2, 3], "text": "héllo"}
            await asyncio.wait_for(server_chan.send(reply), TIMEOUT)
            assert await asyncio.wait_for(client_chan.recv(), TIMEOUT) == reply
        finally:
            await hub.shutdown()

    asyncio.run(main())


def test_server_learns_client_static():
    async def main():
        hub, client_chan, server_chan, client_pub, server_pub = await _paired()
        try:
            assert server_chan.remote_static == client_pub
            assert client_chan.remote_static == server_pub
        finally:
            await hub.shutdown()

    asyncio.run(main())


def test_client_rejects_wrong_hub_fingerprint():
    async def main():
        server_priv, _ = _new_key()
        client_priv, _ = _new_key()
        _, other_pub = _new_key()
        hub = _Hub(server_priv)
        await hub.start()
        try:
            with pytest.raises(HubKeyMismatch):
                await hub.connect(client_priv, fingerprint(other_pub))
            with pytest.raises(HandshakeError) as info:
                await hub.server_channel()
            # The hub must fail because the agent hung up before message 3, not
            # because a message 3 arrived and was rejected. OSError covers a
            # Windows reset in place of a clean EOF.
            assert isinstance(info.value.__cause__, (ConnectionClosed, OSError))
        finally:
            await hub.shutdown()

    asyncio.run(main())


def test_large_message_chunked():
    async def main():
        hub, client_chan, server_chan, _, _ = await _paired()
        try:
            msg = {"blob": "x" * 900_000, "tail": "end"}
            # Send and receive together: 900 KB exceeds the socket buffers, so
            # drain() only returns once the other side is reading.
            _, got = await asyncio.wait_for(
                asyncio.gather(client_chan.send(msg), server_chan.recv()), TIMEOUT
            )
            assert got == msg
        finally:
            await hub.shutdown()

    asyncio.run(main())


def test_message_over_1mib_rejected():
    async def main():
        hub, client_chan, _, _, _ = await _paired()
        try:
            with pytest.raises(MessageTooLarge):
                await asyncio.wait_for(client_chan.send({"blob": "x" * MAX_MESSAGE}), TIMEOUT)
        finally:
            await hub.shutdown()

    asyncio.run(main())


class _CorruptingWriter:
    """Delegates to a StreamWriter; once armed, flips byte 10 of the next write."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.armed = False

    def write(self, data) -> None:
        if self.armed:
            self.armed = False
            data = bytearray(data)
            data[10] ^= 0xFF
            data = bytes(data)
        self._inner.write(data)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_tampered_ciphertext_closes():
    async def main():
        wrappers = []

        def wrap(writer):
            wrappers.append(_CorruptingWriter(writer))
            return wrappers[0]

        hub, client_chan, server_chan, _, _ = await _paired(wrap)
        try:
            # Arm only after the handshake so the first transport frame is the one hit.
            wrappers[0].armed = True
            await asyncio.wait_for(client_chan.send({"a": 1}), TIMEOUT)
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(server_chan.recv(), TIMEOUT)
            assert hub.server_writer.is_closing()
            # The hub hung up, so the agent sees the channel close too.
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(client_chan.recv(), TIMEOUT)
        finally:
            await hub.shutdown()

    asyncio.run(main())



def test_concurrent_sends_take_turns():
    """Many tasks sending at once (the agent's metrics and database loops) all arrive intact."""
    async def main():
        hub, client, server, _, _ = await _paired()
        try:
            big = "x" * 200_000  # several chunks each, so unguarded writes could interleave

            async def receive_all():
                return [(await server.recv())["n"] for _ in range(20)]

            # Read while sending: 4 MB would otherwise fill the socket and block the senders.
            reader = asyncio.ensure_future(receive_all())
            await asyncio.wait_for(
                asyncio.gather(*(client.send({"n": i, "pad": big}) for i in range(20))), TIMEOUT)
            got = await asyncio.wait_for(reader, TIMEOUT)
            assert sorted(got) == list(range(20))
        finally:
            await hub.shutdown()

    asyncio.run(main())


def test_endless_empty_chunks_close_the_channel():
    from devmon.shared.framing import encode_frame
    from devmon.shared.link import MAX_CHUNKS

    async def main():
        hub, client_chan, server_chan, _, _ = await _paired()
        try:
            # An authenticated peer sends "more follows" with nothing in it, over and over.
            for _ in range(MAX_CHUNKS + 5):
                client_chan._writer.write(encode_frame(client_chan._conn.encrypt(b"\x01")))
            await client_chan._writer.drain()
            with pytest.raises(ConnectionClosed, match="too many chunks"):
                await asyncio.wait_for(server_chan.recv(), TIMEOUT)
        finally:
            await hub.shutdown()

    asyncio.run(main())
