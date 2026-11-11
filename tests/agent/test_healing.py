from __future__ import annotations

import json
import socket
import sys
import threading

import pytest

from devmon.agent.healing import FixerLink, LocalHealer, PolicyStore, result_message
from devmon.shared.messages import validate

POLICY = {"type": "policy", "you": 2, "block_s": 3600, "trusted": ["198.51.100.0/24"],
          "modes": {"disk_cleanup": "auto", "cool_down": "auto", "free_memory": "suggest",
                    "block_ip": "auto", "block_ip_lan": "suggest"},
          "thresholds": {"disk_red": 90, "mem_red": 90, "temp_red": 80}, "peers": []}


def metrics(mem=40.0, temp=50.0, disk=50.0):
    return {"type": "metrics", "ts": 0, "mem": {"percent": mem, "swap_percent": 0},
            "temp_c": temp, "disks": [{"mount": "/", "percent": disk, "total_gb": 1,
                                       "used_gb": 1}]}


def fails(ip, n, ts):
    return {"events": [{"ts": ts, "kind": "auth_fail", "source": "ssh", "ip": ip,
                        "user": "root", "port": None, "count": n}]}


def test_policy_store_saves_and_reloads(tmp_path):
    path = tmp_path / "policy.json"
    store = PolicyStore(path)
    assert store.policy is None and store.mode("disk_cleanup") == "off"
    assert store.update(POLICY) and not store.update(dict(POLICY))
    again = PolicyStore(path)
    assert again.mode("disk_cleanup") == "auto" and again.mode("reboot") == "off"
    assert again.block_mode("203.0.113.5") == "auto"
    assert again.block_mode("192.168.1.50") == "suggest"
    assert again.trusted("198.51.100.7") and not again.trusted("203.0.113.5")
    path.write_text("{broken", encoding="utf-8")
    assert PolicyStore(path).policy is None
    path.write_text(json.dumps({**POLICY, "block_s": 1}), encoding="utf-8")
    assert PolicyStore(path).policy is None                 # invalid: ignored


def healer():
    store = PolicyStore(None)
    store.update(POLICY)
    return LocalHealer(store)


def test_local_healer_waits_for_a_silent_hub_and_auto_modes():
    h = healer()
    assert h.on_metrics(metrics(disk=95, mem=95, temp=85), 100, hub_silent_s=10) == []
    out = h.on_metrics(metrics(disk=95, mem=95, temp=85), 160, hub_silent_s=70)
    # Memory is "suggest": nothing happens without the owner.
    assert [(r["fault"], r["action"]) for r in out] == [("temp", "cool_down"),
                                                        ("disk:/", "disk_cleanup")]
    assert all(r["detected"] == 100 for r in out) and out[1]["params"] == {"mount": "/"}
    # Cooldown: not again within 10 minutes, even though still red.
    assert h.on_metrics(metrics(disk=95, temp=85), 200, hub_silent_s=110) == []
    assert len(h.on_metrics(metrics(disk=95, temp=85), 800, hub_silent_s=710)) == 2


def test_local_healer_red_since_resets_when_healthy():
    h = healer()
    h.on_metrics(metrics(disk=95), 100, 0)
    h.on_metrics(metrics(disk=50), 110, 0)
    (r,) = h.on_metrics(metrics(disk=95), 200, 100)
    assert r["detected"] == 200


def test_local_attack_blocking():
    h = healer()
    assert h.on_events(fails("203.0.113.5", 9, 100), 100, hub_silent_s=100) == []
    (r,) = h.on_events(fails("203.0.113.5", 1, 110), 110, hub_silent_s=100)
    assert r == {"fault": "attack", "action": "block_ip", "detected": 100, "origin": "local",
                 "params": {"ip": "203.0.113.5", "seconds": 3600}}
    assert h.on_events(fails("203.0.113.5", 20, 120), 120, 100) == []    # already blocked
    assert h.blocks_to_share(130) == [["203.0.113.5", 3710]]
    # Trusted and LAN attackers are left alone (LAN blocking is only suggested by default).
    assert h.on_events(fails("198.51.100.7", 50, 130), 130, 100) == []
    assert h.on_events(fails("192.168.1.50", 50, 130), 130, 100) == []
    # The hub is there: it decides.
    assert h.on_events(fails("203.0.113.99", 50, 130), 130, hub_silent_s=5) == []


def test_port_scan_counted_by_distinct_ports():
    h = healer()
    events = [{"ts": 100, "kind": "fw_drop", "source": "firewall", "ip": "203.0.113.8",
               "user": None, "port": p, "count": 1} for p in range(1000, 1015)]
    (r,) = h.on_events({"events": events}, 100, 100)
    assert r["params"]["ip"] == "203.0.113.8"


def test_peer_blocks():
    h = healer()
    r = h.on_peer_block("203.0.113.5", 1000 + 1800, 1000)
    assert r["origin"] == "gossip" and r["params"]["seconds"] == 1800
    assert h.on_peer_block("203.0.113.5", 1000 + 1800, 1001) is None   # already blocked
    assert h.on_peer_block("203.0.113.6", 900, 1000) is None            # expired
    assert h.on_peer_block("198.51.100.1", 5000, 1000) is None          # trusted


def test_result_message_is_valid():
    h = healer()
    (r,) = h.on_events(fails("203.0.113.5", 10, 100), 100, 100)
    validate(result_message(r, {"ok": True, "detail": "blocked"}, 101))


def test_fixer_link_without_a_fixer(tmp_path):
    link = FixerLink(str(tmp_path / "none.sock"))
    assert not link.available()
    assert link.call("reboot", {})["ok"] is False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Unix sockets")
def test_fixer_link_round_trip(tmp_path):
    path = str(tmp_path / "f.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        req = json.loads(conn.makefile().readline())
        conn.sendall(json.dumps({"ok": True, "detail": "did " + req["action"]}).encode() + b"\n")
        conn.close()
    t = threading.Thread(target=serve)
    t.start()
    assert FixerLink(path).call("free_memory", {}) == {"ok": True, "detail": "did free_memory"}
    t.join()
