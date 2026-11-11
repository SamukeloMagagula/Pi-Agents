from __future__ import annotations

import asyncio
import json
import copy
import logging
import threading

from devmon import __version__
from devmon.agent.config import AgentConfig
from devmon.agent import runner as runner_mod
from devmon.agent.runner import run_agent
from devmon.shared.keys import fingerprint, load_or_create_static_key
from devmon.shared.link import HandshakeError, server_handshake
from devmon.shared.messages import validate

TICK = 10  # the metrics loop's sleep
DB_TICK = 30  # the database loop's sleep; every other sleep is a backoff or the rejected wait
TIMEOUT = 10
WELCOME = {"type": "welcome", "status": "approved"}  # a hub from before acks
WELCOME_ACKS = {"type": "welcome", "status": "approved", "acks": True}
FAST = {
    "cpu": {"percent": 12.5, "cores": 4, "load1": 0.5},
    "mem": {"percent": 40.0, "swap_percent": 0.0},
    "temp_c": 45.0,
    "net": {"bytes_sent": 100, "bytes_recv": 200},
}
SLOW = {
    "disks": [{"mount": "/", "percent": 50.0, "total_gb": 32.0, "used_gb": 16.0}],
    "uptime_s": 1234.0,
}


class FakeTime:
    """Fake clock and sleep. Metrics and DB ticks run only when the test releases them."""

    def __init__(self, gated=(TICK, DB_TICK)) -> None:
        self.t = 1_000_000.0
        self.delays = []
        self.calls = {d: 0 for d in gated}
        self.released = {d: 0 for d in gated}
        self._permits = {d: asyncio.Semaphore(0) for d in gated}

    def clock(self) -> float:
        return self.t

    async def sleep(self, d) -> None:
        self.delays.append(d)
        if d in self._permits:
            self.calls[d] += 1
            await self._permits[d].acquire()
        self.t += d
        await asyncio.sleep(0)

    def backoffs(self):
        return [d for d in self.delays if d not in self._permits]

    def release(self, n: int, d: int = TICK) -> None:
        self.released[d] += n
        for _ in range(n):
            self._permits[d].release()

    async def run_ticks(self, n: int, d: int = TICK) -> None:
        """Let the loop sleeping d run n ticks; return once it has handled them all."""
        self.release(n, d)
        # A loop calls sleep(d) again only after delivering its previous tick.
        while self.calls[d] < self.released[d] + 1:
            await asyncio.sleep(0.005)


class Collectors:
    """Fake collectors; each collect_fast() result carries a counter `n`."""

    def __init__(self) -> None:
        self.n = 0  # 0 is the priming call at startup, which is discarded

    def fast(self):
        msg = copy.deepcopy(FAST)
        msg["n"] = self.n
        self.n += 1
        return msg

    def slow(self):
        return copy.deepcopy(SLOW)


class Hub:
    """A listening socket; the test decides when each connection is handshaken."""

    def __init__(self, static_priv: bytes) -> None:
        self.static_priv = static_priv
        self.conns = asyncio.Queue()
        self.writers = []

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _accept(self, reader, writer) -> None:
        self.writers.append(writer)
        self.conns.put_nowait((reader, writer))

    async def next_connection(self):
        return await self.conns.get()

    async def handshake(self, conn):
        return await server_handshake(conn[0], conn[1], self.static_priv)

    async def next_channel(self):
        return await self.handshake(await self.next_connection())

    async def close(self) -> None:
        self.server.close()
        for w in self.writers:
            w.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)


async def _with_agent(tmp_path, body, hub_fp=None, collect_db=None, collect_ports=None,
                      gated=(TICK, DB_TICK), collect_security=None, collect_packages=None,
                      collect_events=None, **extra):
    hub_priv, hub_pub = load_or_create_static_key(tmp_path / "hub.key")
    hub = Hub(hub_priv)
    await hub.start()
    fake = FakeTime(gated)
    src = Collectors()
    stop = asyncio.Event()
    cfg = AgentConfig(
        hub_host="127.0.0.1",
        hub_fingerprint=hub_fp or fingerprint(hub_pub),
        key_path=tmp_path / "agent.key",
        hub_port=hub.port,
        device_kind="linux",
    )
    agent = asyncio.ensure_future(run_agent(
        cfg, clock=fake.clock, sleep=fake.sleep, collect_fast=src.fast,
        collect_slow=src.slow, collect_db=collect_db,
        collect_ports=collect_ports, collect_security=collect_security,
        collect_packages=collect_packages, collect_events=collect_events, stop=stop, **extra,
    ))
    try:
        await body(hub, fake, agent)
    finally:
        stop.set()
        try:
            # Proves stop ends run_agent promptly.
            await asyncio.wait_for(agent, 5)
        finally:
            await hub.close()


def _run(tmp_path, body, **kwargs):
    asyncio.run(asyncio.wait_for(_with_agent(tmp_path, body, **kwargs), TIMEOUT))


async def _recv(chan, n):
    return [validate(await chan.recv()) for _ in range(n)]


def test_hello_then_metrics_with_disks_every_sixth(tmp_path):
    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        hello = validate(await chan.recv())
        assert hello["type"] == "hello"
        assert hello["agent_version"] == __version__
        assert hello["device_kind"] == "linux"
        await chan.send(WELCOME)

        await fake.run_ticks(12)
        got = await _recv(chan, 12)
        assert [m["type"] for m in got] == ["metrics"] * 12
        assert [m["n"] for m in got] == list(range(1, 13))
        ts = [m["ts"] for m in got]
        assert ts == sorted(ts) and len(set(ts)) == 12
        assert [i for i, m in enumerate(got) if m["disks"] is not None] == [0, 6]
        assert [i for i, m in enumerate(got) if m["uptime_s"] is not None] == [0, 6]
        assert got[6]["disks"] == SLOW["disks"]
        assert got[1]["cpu"] == FAST["cpu"]

    _run(tmp_path, body)


def _db_message():
    return {"type": "db", "ts": 0.0, "instance": "127.0.0.1:3306", "error": None,
            "overview": None, "long_running": [], "databases": [], "replication": None}


def test_db_message_every_30_s(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    results = [None, _db_message(), _db_message()]  # the first call returns garbage

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)

        await fake.run_ticks(3, DB_TICK)
        got = await _recv(chan, 2)
        assert [m["type"] for m in got] == ["db", "db"]
        # Stamped with the agent's clock at each 30 s tick (the non-dict one was skipped).
        assert [m["ts"] for m in got] == [fake.t - 30, fake.t]
        assert fake.t == 1_000_000.0 + 90
        assert not agent.done()

    _run(tmp_path, body, collect_db=lambda: results.pop(0))
    assert any(r.levelno == logging.ERROR and "not a dict" in r.getMessage()
               for r in caplog.records)


def test_hung_database_does_not_stop_metrics(tmp_path):
    started = threading.Event()
    unblock = threading.Event()

    def collect_db():
        started.set()
        # Timeout is only a backstop; the test sets unblock before it ends.
        unblock.wait(TIMEOUT)
        return _db_message()

    async def body(hub, fake, agent):
        try:
            chan = await hub.next_channel()
            assert (await chan.recv())["type"] == "hello"
            await chan.send(WELCOME)

            fake.release(1, DB_TICK)
            while not started.is_set():
                await asyncio.sleep(0.005)
            # collect_db is now stuck in its thread; metrics must keep flowing.
            await fake.run_ticks(3)
            got = await _recv(chan, 3)
            assert [(m["type"], m["n"]) for m in got] == [("metrics", n) for n in (1, 2, 3)]
        finally:
            unblock.set()

    _run(tmp_path, body, collect_db=collect_db)


def test_metrics_keep_flowing_while_database_reports_errors(tmp_path):
    def collect_db():
        msg = _db_message()
        msg["error"] = "(1045, \"Access denied for user 'mon'@'localhost'\")"
        return msg

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)

        await fake.run_ticks(1, DB_TICK)
        (db,) = await _recv(chan, 1)
        assert db["type"] == "db" and "Access denied" in db["error"]
        await fake.run_ticks(3)
        got = await _recv(chan, 3)
        assert [m["type"] for m in got] == ["metrics"] * 3
        assert not agent.done()

    _run(tmp_path, body, collect_db=collect_db)


def test_reconnect_replays_buffered_messages_once_in_order(tmp_path):
    async def body(hub, fake, agent):
        chan1 = await hub.next_channel()
        assert (await chan1.recv())["type"] == "hello"
        await chan1.send(WELCOME)
        await fake.run_ticks(3)
        first = await _recv(chan1, 3)
        assert [m["n"] for m in first] == [1, 2, 3]

        chan1.close()
        # The agent noticed the loss and reconnected; hold its handshake so it
        # stays disconnected while it keeps collecting.
        conn2 = await hub.next_connection()
        assert fake.backoffs() == [1]
        await fake.run_ticks(4)

        chan2 = await hub.handshake(conn2)
        assert validate(await chan2.recv())["type"] == "hello"
        await chan2.send(WELCOME)
        replayed = await _recv(chan2, 4)
        assert [m["n"] for m in replayed] == [4, 5, 6, 7]
        ts = [m["ts"] for m in replayed]
        assert ts == sorted(ts) and ts[0] > first[-1]["ts"]

        # The next live message follows directly: nothing was sent twice.
        await fake.run_ticks(1)
        live = await _recv(chan2, 1)
        assert live[0]["n"] == 8
        assert live[0]["ts"] > ts[-1]
        # Each send says when it was sent, so the hub can place resent readings.
        assert [m["sent"] for m in replayed] == [fake.t - 10] * 4
        assert live[0]["sent"] == fake.t

    _run(tmp_path, body)


def test_unconfirmed_messages_are_resent_after_reconnect(tmp_path):
    async def body(hub, fake, agent):
        chan1 = await hub.next_channel()
        assert (await chan1.recv())["type"] == "hello"
        await chan1.send(WELCOME_ACKS)
        await fake.run_ticks(3)
        first = await _recv(chan1, 3)
        assert [(m["n"], m["seq"]) for m in first] == [(1, 1), (2, 2), (3, 3)]
        # Only the first is confirmed before the link dies; 2 and 3 were written
        # into it but may never have arrived (a laptop going to sleep).
        await chan1.send({"type": "ack", "seq": 1})
        chan1.close()

        conn2 = await hub.next_connection()
        await fake.run_ticks(2)
        chan2 = await hub.handshake(conn2)
        assert validate(await chan2.recv())["type"] == "hello"
        await chan2.send(WELCOME_ACKS)
        resent = await _recv(chan2, 4)
        assert [m["n"] for m in resent] == [2, 3, 4, 5]

        await chan2.send({"type": "ack", "seq": 5})
        await fake.run_ticks(1)
        (live,) = await _recv(chan2, 1)
        assert live["n"] == 6
        # Confirmed messages are gone for good: only 6 would be resent now.
        chan2.close()
        chan3 = await hub.next_channel()
        assert validate(await chan3.recv())["type"] == "hello"
        await chan3.send(WELCOME_ACKS)
        (again,) = await _recv(chan3, 1)
        assert again["n"] == 6

    _run(tmp_path, body)


def test_missing_acks_force_a_reconnect(tmp_path, caplog):
    caplog.set_level(logging.WARNING)

    async def body(hub, fake, agent):
        chan1 = await hub.next_channel()
        assert (await chan1.recv())["type"] == "hello"
        await chan1.send(WELCOME_ACKS)
        # The hub never confirms. The first message goes out at the first or second tick
        # (depending on whether the welcome was handled yet), so the oldest unconfirmed
        # send passes 60 s at tick 8 or 9, never before.
        ticks = 0
        while hub.conns.empty():
            assert ticks < 9, "no reconnect after 90 s without acks"
            await fake.run_ticks(1)
            ticks += 1
            for _ in range(30):  # give a reconnect time to reach the listener
                if not hub.conns.empty():
                    break
                await asyncio.sleep(0.01)
        assert ticks in (8, 9)
        conn2 = await hub.next_connection()
        assert fake.backoffs() == [1]

        chan2 = await hub.handshake(conn2)
        assert validate(await chan2.recv())["type"] == "hello"
        await chan2.send(WELCOME_ACKS)
        resent = await _recv(chan2, ticks)
        assert [m["n"] for m in resent] == list(range(1, ticks + 1))

    _run(tmp_path, body)
    assert any("has not confirmed messages" in r.getMessage() for r in caplog.records)


def test_wrong_fingerprint_logs_and_backs_off(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    _, other_pub = load_or_create_static_key(tmp_path / "other.key")

    async def body(hub, fake, agent):
        async def serve():
            while True:
                try:
                    await hub.next_channel()
                except HandshakeError:
                    pass  # the agent hangs up once it sees the wrong key

        server = asyncio.ensure_future(serve())
        try:
            while len(fake.backoffs()) < 8:
                await asyncio.sleep(0.005)
        finally:
            server.cancel()
            await asyncio.gather(server, return_exceptions=True)
        assert fake.backoffs()[:8] == [1, 2, 4, 8, 16, 32, 60, 60]
        assert not agent.done()

    _run(tmp_path, body, hub_fp=fingerprint(other_pub))
    assert any(
        r.levelno == logging.ERROR and "does not match configured fingerprint" in r.getMessage()
        for r in caplog.records
    )


def test_rejected_waits_300_s_then_retries(tmp_path):
    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send({"type": "rejected"})
        await hub.next_connection()
        assert fake.backoffs() == [300]

    _run(tmp_path, body)


def test_ports_reported_after_30_s_then_every_300_s(tmp_path):
    PORTS = {"type": "ports", "ports": [
        {"proto": "tcp", "port": 22, "addresses": ["0.0.0.0", "::"], "process": "sshd"}]}
    results = [RuntimeError("psutil hiccup"), PORTS]

    def collect_ports():
        r = results.pop(0) if len(results) > 1 else results[0]
        if isinstance(r, Exception):
            raise r
        return copy.deepcopy(r)

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)
        start = fake.t
        fake.release(1, 30)  # the first report fails; metrics are unaffected
        while fake.calls[300] < 1:  # the loop moved on to its 300 s interval
            await asyncio.sleep(0.005)
        await fake.run_ticks(1)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "metrics"
        await fake.run_ticks(2, 300)
        got = await _recv(chan, 2)
        assert [m["type"] for m in got] == ["ports", "ports"]
        assert got[0]["ports"] == PORTS["ports"]
        assert got[0]["ts"] == start + 30 + 10 + 300
        assert got[1]["ts"] == got[0]["ts"] + 300

    _run(tmp_path, body, collect_ports=collect_ports, gated=(TICK, 30, 300))


async def _step(fake, first, nxt):
    """Release one sleep of `first` and wait until the loop is sleeping `nxt`."""
    want = fake.calls[nxt] + 1
    fake.release(1, first)
    while fake.calls[nxt] < want:
        await asyncio.sleep(0.005)


def test_security_after_60_s_then_hourly_and_packages_daily(tmp_path):
    SEC = {"type": "security", "helper": None, "helper_error": "not yet", "updates": None}
    PKGS = {"type": "packages", "os": {}, "ecosystem": "Debian:12",
            "packages": [{"name": "openssl", "version": "3.0.15-1~deb12u1"}]}

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)
        start = fake.t
        await _step(fake, 60, 3600)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "security" and m["ts"] == start + 60
        await _step(fake, 120, 86400)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "packages" and m["packages"] == PKGS["packages"]
        await fake.run_ticks(1, 3600)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "security"
        await fake.run_ticks(1, 86400)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "packages"

    _run(tmp_path, body, collect_security=lambda: dict(SEC),
         collect_packages=lambda: dict(PKGS), gated=(TICK, 60, 3600, 120, 86400))


def test_no_packages_on_this_os_sends_nothing(tmp_path):
    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)
        await _step(fake, 120, 86400)
        await fake.run_ticks(1, 86400)
        await fake.run_ticks(1)
        (m,) = await _recv(chan, 1)
        assert m["type"] == "metrics"  # nothing queued ahead of it

    _run(tmp_path, body, collect_packages=lambda: None, gated=(TICK, 120, 86400))


def test_events_every_interval_only_when_there_is_something(tmp_path, monkeypatch):
    # The real interval equals the metrics tick; a distinct one keeps the fake clock's
    # gates apart.
    monkeypatch.setattr(runner_mod, "EVENTS_INTERVAL_S", 11)
    EV = {"type": "events", "sources": None, "events": [
        {"ts": 1.0, "kind": "auth_fail", "source": "ssh", "ip": "203.0.113.9",
         "user": "root", "port": None, "count": 3}]}
    results = [None, dict(EV)]

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert (await chan.recv())["type"] == "hello"
        await chan.send(WELCOME)
        start = fake.t
        await fake.run_ticks(2, 11)  # nothing new, then one batch
        (m,) = await _recv(chan, 1)
        assert m["type"] == "events" and m["ts"] == start + 22
        assert m["events"][0]["count"] == 3

    _run(tmp_path, body, collect_events=lambda: results.pop(0) if results else None,
         gated=(TICK, 11))


# ---- Phase 8: fixes, policy and local decisions --------------------------------------


class FakeFixer:
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply or {"ok": True, "detail": "done"}
        self.called = threading.Event()

    def available(self):
        return True

    def call(self, action, params):
        self.calls.append((action, params))
        self.called.set()
        return dict(self.reply)


POLICY = {"type": "policy", "you": 7, "block_s": 3600, "trusted": [],
          "modes": {"disk_cleanup": "auto", "free_memory": "suggest"},
          "thresholds": {"disk_red": 90}, "peers": []}


def test_fix_from_hub_runs_once_and_result_is_delivered(tmp_path):
    fixer = FakeFixer({"ok": True, "detail": "restarted nginx.service; it is running"})

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        hello = validate(await chan.recv())
        assert hello["fixer"] is True
        await chan.send(WELCOME_ACKS)
        fix = {"type": "fix", "id": 42, "action": "restart_service", "params": {"unit": "nginx"}}
        await chan.send(fix)
        await chan.send(fix)                                    # a resend is not done twice
        (result,) = await _recv(chan, 1)
        assert result["type"] == "fix_result" and result["id"] == 42 and result["ok"]
        assert result["detail"] == "restarted nginx.service; it is running"
        assert fixer.calls == [("restart_service", {"unit": "nginx"})]
        await chan.send({"type": "fix", "id": 43, "action": "rm", "params": {}})  # invalid
        await chan.send({"type": "ack", "seq": result["seq"]})
        await fake.run_ticks(1)
        assert (await _recv(chan, 1))[0]["type"] == "metrics"
        assert len(fixer.calls) == 1

    _run(tmp_path, body, fixer=fixer)


def test_no_fixer_answers_with_a_failure(tmp_path):
    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        assert validate(await chan.recv())["fixer"] is False
        await chan.send(WELCOME_ACKS)
        await chan.send({"type": "fix", "id": 1, "action": "reboot", "params": {}})
        (result,) = await _recv(chan, 1)
        assert result["ok"] is False and "no fixer" in result["detail"]

    _run(tmp_path, body)


def test_policy_is_saved_and_used_alone_when_the_hub_goes_silent(tmp_path):
    fixer = FakeFixer({"ok": True, "detail": "freed 2.0 GB on /"})
    policy_path = tmp_path / "policy.json"

    def slow_full():
        return {"disks": [{"mount": "/", "percent": 95.0, "total_gb": 32.0, "used_gb": 30.4}],
                "uptime_s": 99.0}

    async def body(hub, fake, agent):
        chan = await hub.next_channel()
        await chan.recv()
        await chan.send(WELCOME_ACKS)
        await chan.send(POLICY)
        await fake.run_ticks(1)
        (m,) = await _recv(chan, 1)
        assert m["disks"][0]["percent"] == 95.0
        assert json.loads(policy_path.read_text())["you"] == 7
        assert fixer.calls == []                       # the hub is there: it decides
        # The hub stops answering. After a minute of silence the agent acts on its own.
        await fake.run_ticks(6)
        await _recv(chan, 6)
        (result,) = await _recv(chan, 1)
        assert fixer.calls == [("disk_cleanup", {"mount": "/"})]
        assert result["type"] == "fix_result" and result["id"] is None
        assert result["origin"] == "local" and result["fault"] == "disk:/"
        assert result["detected"] == m["ts"]

    asyncio.run(asyncio.wait_for(_with_slow(tmp_path, body, slow_full, fixer=fixer,
                                            policy_path=policy_path), TIMEOUT))


async def _with_slow(tmp_path, body, slow, **extra):
    # Like _with_agent, but every metrics reading includes disks.
    orig = Collectors.slow
    Collectors.slow = lambda self: slow()
    orig_every = runner_mod.SLOW_EVERY
    runner_mod.SLOW_EVERY = 1
    try:
        await _with_agent(tmp_path, body, **extra)
    finally:
        Collectors.slow = orig
        runner_mod.SLOW_EVERY = orig_every
