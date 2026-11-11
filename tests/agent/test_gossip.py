from __future__ import annotations

import json

from devmon.agent.gossip import DOMAIN, Gossip, load_key, public_hex
from devmon.shared.messages import validate


def node(tmp_path, name, you):
    g = Gossip(load_key(tmp_path / (name + ".key")), clock=lambda: 1000.0)
    g.you = you
    return g


def policy(you, peers):
    return {"type": "policy", "you": you, "block_s": 3600, "trusted": [], "modes": {},
            "thresholds": {}, "peers": peers}


def entry(i, g):
    return {"id": i, "name": "pi-%d" % i, "ip": "192.168.1.%d" % i, "port": 55556,
            "pub": g.pub_hex}


def pair(tmp_path):
    a = node(tmp_path, "a", 1)
    b = node(tmp_path, "b", 2)
    a.set_peers(policy(1, [entry(1, a), entry(2, b)]))
    b.set_peers(policy(2, [entry(1, a), entry(2, b)]))
    return a, b


def test_key_is_stable(tmp_path):
    assert public_hex(load_key(tmp_path / "g.key")) == public_hex(load_key(tmp_path / "g.key"))


def test_signed_heartbeat_is_heard_and_reported(tmp_path):
    a, b = pair(tmp_path)
    assert list(a.peers) == [2]                       # never itself
    blocks = b.receive(a.packet(True, [["203.0.113.5", 1800]]), 1000.0)
    assert blocks == [("203.0.113.5", 1800)]
    report = {**b.report(1004.0), "ts": 1004.0}
    validate(report)
    assert report["peers"] == [{"id": 1, "heard_s": 4.0, "hub_ok": True}]


def test_replay_forgery_and_strangers_are_ignored(tmp_path):
    a, b = pair(tmp_path)
    p1 = a.packet(False, [])
    assert b.receive(p1, 1.0) == [] and 1 in b.heard
    seq = b.heard[1][2]
    assert b.receive(p1, 2.0) == []                           # a replay changes nothing
    assert b.heard[1] == (1.0, False, seq)
    p2 = a.packet(False, [["203.0.113.5", 60]])
    assert b.receive(p2.replace(b"203.0.113.5", b"203.0.113.6"), 3.0) == []     # forged
    stranger = node(tmp_path, "c", 1)                 # claims to be node 1, with another key
    assert b.receive(stranger.packet(True, [["203.0.113.7", 60]]), 4.0) == []
    assert b.receive(b"x" * 10, 5.0) == []
    assert b.receive(bytes(64) + b"{}", 5.0) == []
    assert b.receive(p2, 6.0) == [("203.0.113.5", 60)]       # the genuine one still counts


def test_bad_block_entries_are_dropped(tmp_path):
    a, b = pair(tmp_path)
    body = json.dumps({"v": 1, "from": 1, "seq": 10 ** 15, "hub_ok": False,
                       "blocks": [["not-ip", 60], ["203.0.113.5", True], ["203.0.113.6", -5],
                                  ["::ffff:203.0.113.9", 10 ** 9], "x"]}).encode()
    packet = a.key.sign(DOMAIN + body) + body
    assert b.receive(packet, 1.0) == [("203.0.113.9", 7 * 86400)]


def test_unheard_peer_and_policy_changes(tmp_path):
    a, b = pair(tmp_path)
    assert b.report(5.0)["peers"] == [{"id": 1, "heard_s": None, "hub_ok": None}]
    b.receive(a.packet(True, []), 1.0)
    b.set_peers(policy(2, [entry(2, b)]))              # node 1 removed by the hub
    assert b.peers == {} and b.heard == {}


def test_no_heartbeat_before_the_hub_says_who_we_are(tmp_path):
    g = Gossip(load_key(tmp_path / "x.key"))
    assert g.packet(True, []) is None


def test_heartbeat_over_real_udp(tmp_path):
    import asyncio
    import socket

    from devmon.agent.gossip import open_endpoint

    def free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    a = node(tmp_path, "a", 1)
    b = node(tmp_path, "b", 2)
    pa, pb = free_port(), free_port()
    peers = [dict(entry(1, a), ip="127.0.0.1", port=pa), dict(entry(2, b), ip="127.0.0.1", port=pb)]
    a.set_peers(policy(1, peers))
    b.set_peers(policy(2, peers))
    got = []

    async def run():
        ta = await open_endpoint(pa, lambda data: None)
        tb = await open_endpoint(pb, lambda data: got.append(b.receive(data, 5.0)))
        try:
            ta.sendto(a.packet(True, [["203.0.113.5", 60]]), ("127.0.0.1", pb))
            for _ in range(100):
                if got:
                    break
                await asyncio.sleep(0.02)
        finally:
            ta.close()
            tb.close()
    asyncio.run(run())
    assert got == [[("203.0.113.5", 60)]] and b.heard[1][1] is True
