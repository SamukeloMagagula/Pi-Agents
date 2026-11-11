"""Gossip: signed UDP heartbeats between the agents of one cluster.

Every BEAT_S each agent sends every peer the hub listed a small JSON heartbeat:
- who it is and a sequence number
- whether it can reach the hub
- any attackers it blocked on its own

The heartbeat is signed with the agent's Ed25519 gossip key. Peers check it against the
public key the hub vouched for (the hub only lists approved devices), and refuse replays:
the sequence number must grow.

What it is for:
- the hub learns from each agent whom it hears, so a silent device can be told apart as
  "down" or "running, but cut off from the hub"
- attackers blocked while the hub is unreachable are blocked cluster-wide
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from devmon.shared import netrules
from devmon.shared.keys import load_or_create_static_key

log = logging.getLogger(__name__)

DEFAULT_PORT = 55556
BEAT_S = 5
REPORT_EVERY = 6  # beats: the hub gets a peers report every 30 s
SIG_LEN = 64
MAX_PACKET = 1400
DOMAIN = b"devmon-gossip-v1\n"
MAX_BLOCKS = 32


def load_key(path: Path) -> Ed25519PrivateKey:
    # The key file holds 32 random bytes, which are as good an Ed25519 seed as an X25519 key.
    priv, _ = load_or_create_static_key(path)
    return Ed25519PrivateKey.from_private_bytes(priv)


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


class Gossip:
    def __init__(self, key: Ed25519PrivateKey, port: int = DEFAULT_PORT,
                 clock: Callable[[], float] = time.time) -> None:
        self.key = key
        self.port = port
        self.clock = clock
        self.pub_hex = public_hex(key)
        self.you: Optional[int] = None
        self.peers: Dict[int, Dict[str, Any]] = {}
        # peer id -> (heard at, its hub_ok, last seq)
        self.heard: Dict[int, Tuple[float, bool, int]] = {}
        # Milliseconds since 1970: keeps growing across restarts, so peers accept it.
        self.seq = int(clock() * 1000)

    def set_peers(self, policy: Dict[str, Any]) -> None:
        self.you = policy["you"]
        peers = {}
        for p in policy["peers"]:
            if p["id"] == self.you or netrules.parse_ip(p["ip"]) is None:
                continue
            try:
                pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["pub"]))
            except ValueError:
                continue
            peers[p["id"]] = {"ip": p["ip"], "port": p["port"], "pub": pub, "name": p["name"]}
        self.peers = peers
        self.heard = {k: v for k, v in self.heard.items() if k in peers}

    def packet(self, hub_ok: bool, blocks: List[List[Any]]) -> Optional[bytes]:
        """This node's next heartbeat; blocks are [ip, seconds left]."""
        if self.you is None:
            return None
        self.seq += 1
        body = json.dumps({"v": 1, "from": self.you, "seq": self.seq, "hub_ok": hub_ok,
                           "blocks": blocks[:MAX_BLOCKS]}, separators=(",", ":")).encode()
        return self.key.sign(DOMAIN + body) + body

    def receive(self, data: bytes, now: float) -> List[Tuple[str, int]]:
        """Check one heartbeat. Returns its blocks [(ip, seconds)], or [] if not trusted."""
        if not SIG_LEN < len(data) <= MAX_PACKET:
            return []
        sig, body = data[:SIG_LEN], data[SIG_LEN:]
        try:
            msg = json.loads(body.decode("utf-8"))
            sender = msg["from"]
            seq = msg["seq"]
        except (ValueError, KeyError, TypeError):
            return []
        peer = self.peers.get(sender) if isinstance(sender, int) else None
        if peer is None or not isinstance(seq, int):
            return []
        try:
            peer["pub"].verify(sig, DOMAIN + body)
        except InvalidSignature:
            return []
        last = self.heard.get(sender)
        if last is not None and seq <= last[2]:
            return []  # a replay, or an old packet arriving late
        self.heard[sender] = (now, msg.get("hub_ok") is True, seq)
        out = []
        for entry in msg.get("blocks") or []:
            if (isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], str)
                    and isinstance(entry[1], int) and not isinstance(entry[1], bool)
                    and netrules.parse_ip(entry[0]) is not None and entry[1] > 0):
                out.append((str(netrules.parse_ip(entry[0])), min(entry[1], 7 * 86400)))
        return out[:MAX_BLOCKS]

    def report(self, now: float) -> Dict[str, Any]:
        peers = []
        for pid in sorted(self.peers):
            h = self.heard.get(pid)
            peers.append({"id": pid, "heard_s": None if h is None else max(now - h[0], 0.0),
                          "hub_ok": None if h is None else h[1]})
        return {"type": "peers", "peers": peers}


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet: Callable[[bytes], None]) -> None:
        self.on_packet = on_packet

    def datagram_received(self, data: bytes, addr: Any) -> None:
        try:
            self.on_packet(data)
        except Exception:
            log.exception("gossip packet handling failed")

    def error_received(self, exc: Exception) -> None:
        log.debug("gossip socket error: %s", exc)


async def open_endpoint(port: int, on_packet: Callable[[bytes], None]) -> Any:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Protocol(on_packet), local_addr=("0.0.0.0", port))
    return transport
