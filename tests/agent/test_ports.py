from __future__ import annotations

from collections import namedtuple

import psutil

from devmon.agent.collectors.ports import _process_name, collect_ports
from devmon.shared.messages import validate

Conn = namedtuple("Conn", "fd family type laddr raddr status pid")
Addr = namedtuple("Addr", "ip port")


def _listen(ip, port, pid=10):
    return Conn(-1, 2, 1, Addr(ip, port), (), psutil.CONN_LISTEN, pid)


def _collect(conns, names=None):
    names = names or {10: "sshd", 20: "mariadbd"}
    asked = []

    def name(pid):
        asked.append(pid)
        return names.get(pid)

    def net_connections(kind):
        assert kind == "tcp"
        return conns

    return collect_ports(net_connections=net_connections, process_name=name), asked


def test_ipv4_and_ipv6_listeners_merge_into_one_port():
    msg, _ = _collect([_listen("::", 22), _listen("0.0.0.0", 22), _listen("127.0.0.1", 3306, 20)])
    assert validate(dict(msg, ts=1.0)) is not None
    assert msg["ports"] == [
        {"proto": "tcp", "port": 22, "addresses": ["0.0.0.0", "::"], "process": "sshd"},
        {"proto": "tcp", "port": 3306, "addresses": ["127.0.0.1"], "process": "mariadbd"},
    ]


def test_only_listening_sockets_count():
    established = Conn(-1, 2, 1, Addr("10.0.0.2", 51000), Addr("10.0.0.9", 443),
                       psutil.CONN_ESTABLISHED, 10)
    msg, _ = _collect([established, _listen("0.0.0.0", 80)])
    assert [p["port"] for p in msg["ports"]] == [80]


def test_unknown_process_is_none_and_each_pid_is_looked_up_once():
    msg, asked = _collect([_listen("0.0.0.0", 8080, None), _listen("0.0.0.0", 22),
                           _listen("::", 2222)])
    assert msg["ports"][2]["process"] is None  # 8080
    assert asked.count(10) == 1


def test_access_denied_gives_none(monkeypatch):
    def denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(psutil, "Process", denied)
    assert _process_name(1234) is None
    assert _process_name(None) is None


def test_runs_against_the_real_machine():
    msg = collect_ports()
    validate(dict(msg, ts=1.0))
