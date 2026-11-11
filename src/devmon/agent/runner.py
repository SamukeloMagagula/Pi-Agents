from __future__ import annotations

import asyncio
import logging
import platform
import socket
import time
from collections import deque
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Set

from devmon import __version__
from devmon.agent.buffer import Outbox
from devmon.agent.collectors.system import collect_fast as _collect_fast
from devmon.agent.collectors.system import collect_slow as _collect_slow
from devmon.agent.collectors.system import detect_device_kind
from devmon.agent.config import AgentConfig
from devmon.agent.gossip import BEAT_S, REPORT_EVERY, Gossip, open_endpoint
from devmon.agent.healing import FixerLink, LocalHealer, PolicyStore, result_message
from devmon.shared.framing import ConnectionClosed
from devmon.shared.keys import load_or_create_static_key
from devmon.shared.link import HubKeyMismatch, MessageTooLarge, SecureChannel, client_handshake
from devmon.shared.messages import InvalidMessage, validate

log = logging.getLogger(__name__)

TICK_S = 10
SLOW_EVERY = 6  # disks + uptime every 60 s
DB_INTERVAL_S = 30
PORTS_FIRST_S = 30  # soon after start, so a new device's services can be suggested
PORTS_INTERVAL_S = 300
SECURITY_FIRST_S = 60  # the helper's first run is 1-2 minutes after boot
SECURITY_INTERVAL_S = 3600
PACKAGES_FIRST_S = 120
PACKAGES_INTERVAL_S = 86400
EVENTS_INTERVAL_S = 10  # spec §8: auth and attack events, batched every 10 s
CONNECT_TIMEOUT_S = 10
HANDSHAKE_TIMEOUT_S = 10
WELCOME_TIMEOUT_S = 10
REJECTED_WAIT_S = 300
BACKOFF_MAX_S = 60
# The hub confirms each message as soon as it has handled it.
ACK_TIMEOUT_S = 60


class _Rejected(Exception):
    pass


class _UnexpectedReply(Exception):
    pass


class _Agent:
    def __init__(
        self,
        cfg: AgentConfig,
        static_priv: bytes,
        clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[Any]],
        collect_fast: Callable[[], Dict[str, Any]],
        collect_slow: Callable[[], Dict[str, Any]],
        collect_db: Optional[Callable[[], Dict[str, Any]]],
        collect_ports: Optional[Callable[[], Dict[str, Any]]] = None,
        collect_security: Optional[Callable[[], Dict[str, Any]]] = None,
        collect_packages: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
        collect_events: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
        fixer: Optional[FixerLink] = None,
        policy: Optional[PolicyStore] = None,
        gossip: Optional[Gossip] = None,
    ) -> None:
        self.cfg = cfg
        self.static_priv = static_priv
        self.clock = clock
        self.sleep = sleep
        self.collect_fast = collect_fast
        self.collect_slow = collect_slow
        self.collect_db = collect_db
        self.collect_ports = collect_ports
        self.collect_security = collect_security
        self.collect_packages = collect_packages
        self.collect_events = collect_events
        self.fixer = fixer
        self.policy = policy or PolicyStore(None)
        self.healer = LocalHealer(self.policy)
        self.gossip = gossip
        if gossip is not None and self.policy.policy is not None:
            gossip.set_peers(self.policy.policy)
        self.gossip_transport: Any = None
        # When the hub last sent us anything; local decisions start after a minute of silence.
        self.last_hub_rx = clock()
        self.fix_ids: Deque[int] = deque(maxlen=500)
        self.tasks: Set[Any] = set()
        self.outbox = Outbox()
        # Set only once the hub has welcomed us and the outbox is resent.
        self.channel: Optional[SecureChannel] = None
        # Whether the connected hub confirms messages (hubs before acks did not).
        self.acks = False
        self.backoff = 1
        self.hello = {
            "type": "hello",
            "agent_version": __version__,
            # Trimmed to the hub's limits, so an odd system can still connect.
            "hostname": socket.gethostname()[:253],
            "os": "windows" if platform.system() == "Windows" else "linux",
            "os_detail": platform.platform()[:200],
            "device_kind": cfg.device_kind or detect_device_kind(),
        }

    # ---- collection -------------------------------------------------------

    async def collect_loop(self) -> None:
        # psutil's first cpu_percent(interval=None) is always 0.0; this primes it.
        try:
            self.collect_fast()
        except Exception:
            log.exception("collect_fast failed")
        tick = 0
        while True:
            await self.sleep(TICK_S)
            ts = self.clock()
            metrics = self._metrics(ts, slow=tick % SLOW_EVERY == 0)
            if metrics is not None:
                await self._deliver(metrics)
                self._local(self.healer.on_metrics(metrics, ts, self.hub_silent_s()))
            tick += 1

    async def db_loop(self) -> None:
        # Its own loop so a slow or hung database never delays system metrics.
        while True:
            await self.sleep(DB_INTERVAL_S)
            db = await self._in_thread(self.collect_db, "collect_db", self.clock())
            if db is not None:
                await self._deliver(db)

    async def ports_loop(self) -> None:
        await self._periodic(self.collect_ports, "collect_ports", PORTS_FIRST_S,
                             PORTS_INTERVAL_S)

    async def security_loop(self) -> None:
        await self._periodic(self.collect_security, "collect_security", SECURITY_FIRST_S,
                             SECURITY_INTERVAL_S)

    async def packages_loop(self) -> None:
        await self._periodic(self.collect_packages, "collect_packages", PACKAGES_FIRST_S,
                             PACKAGES_INTERVAL_S)

    async def events_loop(self) -> None:
        def observe(msg: Dict[str, Any]) -> None:
            self._local(self.healer.on_events(msg, self.clock(), self.hub_silent_s()))
        await self._periodic(self.collect_events, "collect_events", EVENTS_INTERVAL_S,
                             EVENTS_INTERVAL_S, observe)

    async def _periodic(self, collect: Any, what: str, first: float, every: float,
                        observe: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        delay = first
        while True:
            await self.sleep(delay)
            delay = every
            msg = await self._in_thread(collect, what, self.clock())
            if msg is not None:
                await self._deliver(msg)
                if observe is not None:
                    observe(msg)

    def _metrics(self, ts: float, slow: bool) -> Optional[Dict[str, Any]]:
        try:
            msg = {"type": "metrics", "ts": ts, **self.collect_fast(),
                   "disks": None, "uptime_s": None}
        except Exception:
            log.exception("collect_fast failed")
            return None
        if slow:
            try:
                msg.update(self.collect_slow())
            except Exception:
                log.exception("collect_slow failed")
        return msg

    async def _in_thread(self, collect: Any, what: str, ts: float) -> Optional[Dict[str, Any]]:
        try:
            # Database queries and port scans of /proc block, so keep them off the event loop.
            result = await asyncio.get_running_loop().run_in_executor(None, collect)
        except Exception:
            log.exception("%s failed", what)
            return None
        if result is None and what in ("collect_packages", "collect_events"):
            return None  # nothing to report (this OS, or nothing new)
        if not isinstance(result, dict):
            log.error("%s returned %s, not a dict; skipped", what, type(result).__name__)
            return None
        return {**result, "ts": ts}

    async def _deliver(self, msg: Dict[str, Any]) -> None:
        # Kept until the hub confirms it, whether or not we are connected right now.
        self.outbox.add(msg)
        chan = self.channel
        if chan is None:
            return
        if not await self._send(chan, msg):
            return
        oldest = self.outbox.oldest_unconfirmed_send()
        if oldest is not None and self.clock() - oldest > ACK_TIMEOUT_S:
            # Writes into a connection that died while we slept still "succeed"; only
            # the missing confirmations show it. Reconnect, and the outbox is resent.
            log.warning("hub has not confirmed messages for over %d s; reconnecting",
                        ACK_TIMEOUT_S)
            self._drop(chan)

    async def _send(self, chan: SecureChannel, msg: Dict[str, Any]) -> bool:
        """Send one outbox message; False (and the channel dropped) if the link failed."""
        now = self.clock()
        try:
            # `sent` lets the hub place a late (resent) reading at the time it was taken.
            await chan.send({**msg, "sent": now})
        except MessageTooLarge:
            log.error("dropping %s message: larger than the 1 MiB limit", msg.get("type"))
            self.outbox.discard(msg["seq"])
            return True
        except Exception as exc:
            log.warning("send to hub failed (%s); keeping it and reconnecting", exc)
            self._drop(chan)
            return False
        if self.acks:
            self.outbox.mark_sent(msg["seq"], now)
        else:
            # An older hub never confirms anything; once written, the message is gone.
            self.outbox.discard(msg["seq"])
        return True

    def _drop(self, chan: SecureChannel) -> None:
        if self.channel is chan:
            self.channel = None
        # Closing wakes the session's reader, which then reconnects.
        chan.close()

    # ---- connection -------------------------------------------------------

    async def connection_loop(self) -> None:
        while True:
            try:
                await self._session()
            except _Rejected:
                log.error("hub rejected this agent; retrying in %d s", REJECTED_WAIT_S)
                await self.sleep(REJECTED_WAIT_S)
                continue
            except HubKeyMismatch as exc:
                log.error("hub key does not match configured fingerprint (%s)", exc)
            except Exception as exc:
                log.warning("connection to hub failed: %r", exc)
            await self.sleep(self.backoff)
            self.backoff = min(self.backoff * 2, BACKOFF_MAX_S)

    async def _session(self) -> None:
        """Connect, handshake, replay, then serve until the connection is lost.

        Returns normally only after a welcomed connection was lost; raises otherwise.
        """
        host, port = self.cfg.hub_host, self.cfg.hub_port
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), CONNECT_TIMEOUT_S
        )
        try:
            chan = await asyncio.wait_for(
                client_handshake(reader, writer, self.static_priv, self.cfg.hub_fingerprint),
                HANDSHAKE_TIMEOUT_S,
            )
        except BaseException:
            # A timeout or stop cancels client_handshake without it closing the writer.
            writer.close()
            raise
        try:
            await chan.send(self._hello())
            reply = await asyncio.wait_for(chan.recv(), WELCOME_TIMEOUT_S)
            rtype = reply.get("type")
            if rtype == "rejected":
                raise _Rejected()
            if rtype != "welcome":
                raise _UnexpectedReply("expected welcome, got %r" % (rtype,))
            log.info("connected to hub %s:%d (status %s)", host, port, reply.get("status"))
            self.backoff = 1
            self.acks = reply.get("acks") is True
            self.outbox.forget_sends()
            await self._replay(chan)
            self.channel = chan
            await self._read_until_closed(chan)
        finally:
            if self.channel is chan:
                self.channel = None
            chan.close()

    async def _replay(self, chan: SecureChannel) -> None:
        # Loop: the collector may add more while we await sends. The final empty
        # check and setting self.channel happen with no await between them.
        last = 0
        while True:
            pending = self.outbox.pending(self.clock(), after=last)
            if not pending:
                return
            log.info("sending %d unconfirmed message(s)", len(pending))
            for msg in pending:
                if not await self._send(chan, msg):
                    raise ConnectionClosed("connection lost while resending")
                last = msg["seq"]

    async def _read_until_closed(self, chan: SecureChannel) -> None:
        while True:
            try:
                msg = await chan.recv()
            except (ConnectionClosed, MessageTooLarge, OSError) as exc:
                log.warning("lost connection to hub: %s", exc)
                return
            self.last_hub_rx = self.clock()
            if msg.get("type") in ("fix", "policy"):
                try:
                    validate(msg)
                except InvalidMessage as exc:
                    log.warning("ignoring invalid %s from hub: %s", msg.get("type"), exc)
                    continue
                if msg["type"] == "fix":
                    self._on_fix(msg)
                else:
                    self._on_policy(msg)
                continue
            if msg.get("type") == "ack":
                try:
                    validate(msg)
                except InvalidMessage as exc:
                    log.warning("ignoring invalid ack from hub: %s", exc)
                    continue
                self.outbox.ack(msg["seq"])
                continue
            log.debug("ignoring unexpected message from hub: %r", msg.get("type"))

    # ---- self-healing -------------------------------------------------------------

    def _hello(self) -> Dict[str, Any]:
        hello = dict(self.hello)
        hello["fixer"] = self.fixer is not None and self.fixer.available()
        if self.gossip is not None:
            hello["gossip_pub"] = self.gossip.pub_hex
            hello["gossip_port"] = self.gossip.port
        return hello

    def hub_silent_s(self) -> float:
        return self.clock() - self.last_hub_rx

    def _spawn(self, coro: Awaitable[Any]) -> None:
        task = asyncio.ensure_future(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _call_fixer(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.fixer is None:
            return {"ok": False, "detail": "there is no fixer on this device"}
        try:
            return await asyncio.get_running_loop().run_in_executor(
                None, self.fixer.call, action, params)
        except Exception as exc:
            log.exception("calling the fixer failed")
            return {"ok": False, "detail": "calling the fixer failed: %s" % exc}

    def _on_fix(self, msg: Dict[str, Any]) -> None:
        if msg["id"] in self.fix_ids:
            return  # already done (the hub resent it after a reconnect)
        self.fix_ids.append(msg["id"])
        log.info("hub asks for %s %s", msg["action"], msg["params"])

        async def run() -> None:
            reply = await self._call_fixer(msg["action"], msg["params"])
            log.info("%s: %s", msg["action"], reply["detail"])
            await self._deliver({"type": "fix_result", "ts": self.clock(), "id": msg["id"],
                                 "action": msg["action"], "ok": reply["ok"],
                                 "detail": reply["detail"][:500]})
        self._spawn(run())

    def _on_policy(self, msg: Dict[str, Any]) -> None:
        if self.policy.update(msg):
            log.info("healing policy updated (%d peer(s))",
                     sum(1 for p in msg["peers"] if p["id"] != msg["you"]))
        if self.gossip is not None:
            self.gossip.set_peers(msg)

    def _local(self, requests: List[Dict[str, Any]]) -> None:
        if self.fixer is None:
            return
        for req in requests:
            log.warning("acting without the hub: %s for %s (%s)", req["action"], req["fault"],
                        req["origin"])

            async def run(req: Dict[str, Any] = req) -> None:
                reply = await self._call_fixer(req["action"], req["params"])
                log.info("%s: %s", req["action"], reply["detail"])
                await self._deliver(result_message(req, reply, self.clock()))
            self._spawn(run())

    async def gossip_loop(self) -> None:
        gossip = self.gossip
        assert gossip is not None

        def on_packet(data: bytes) -> None:
            now = self.clock()
            for ip, seconds in gossip.receive(data, now):
                req = self.healer.on_peer_block(ip, now + seconds, now)
                if req is not None:
                    self._local([req])
        try:
            self.gossip_transport = await open_endpoint(gossip.port, on_packet)
        except OSError as exc:
            log.error("gossip is off: cannot listen on UDP port %d (%s)", gossip.port, exc)
            return
        beat = 0
        while True:
            await self.sleep(BEAT_S)
            now = self.clock()
            blocks = [[ip, int(until - now)] for ip, until in self.healer.blocks_to_share(now)]
            packet = gossip.packet(self.channel is not None, blocks)
            if packet is not None:
                for peer in gossip.peers.values():
                    try:
                        self.gossip_transport.sendto(packet, (peer["ip"], peer["port"]))
                    except OSError as exc:
                        log.debug("gossip to %s failed: %s", peer["ip"], exc)
            beat += 1
            if beat % REPORT_EVERY == 0 and gossip.peers:
                await self._deliver({**gossip.report(now), "ts": now})

    def close(self) -> None:
        for task in list(self.tasks):
            task.cancel()
        if self.gossip_transport is not None:
            self.gossip_transport.close()
            self.gossip_transport = None
        if self.channel is not None:
            self.channel.close()
            self.channel = None


async def run_agent(
    cfg: AgentConfig,
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    collect_fast: Callable[[], Dict[str, Any]] = _collect_fast,
    collect_slow: Callable[[], Dict[str, Any]] = _collect_slow,
    collect_db: Optional[Callable[[], Dict[str, Any]]] = None,
    collect_ports: Optional[Callable[[], Dict[str, Any]]] = None,
    collect_security: Optional[Callable[[], Dict[str, Any]]] = None,
    collect_packages: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    collect_events: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    fixer: Optional[FixerLink] = None,
    policy_path: Optional[Path] = None,
    gossip: Optional[Gossip] = None,
    stop: asyncio.Event | None = None,
) -> None:
    """Collect and stream metrics to the hub until `stop` is set (forever if None)."""
    if stop is None:
        stop = asyncio.Event()
    static_priv, _ = load_or_create_static_key(cfg.key_path)
    agent = _Agent(cfg, static_priv, clock, sleep, collect_fast, collect_slow, collect_db,
                   collect_ports, collect_security, collect_packages, collect_events,
                   fixer=fixer, policy=PolicyStore(policy_path), gossip=gossip)
    loops = [
        asyncio.ensure_future(agent.collect_loop()),
        asyncio.ensure_future(agent.connection_loop()),
    ]
    if collect_db is not None:
        loops.append(asyncio.ensure_future(agent.db_loop()))
    if collect_ports is not None:
        loops.append(asyncio.ensure_future(agent.ports_loop()))
    if collect_security is not None:
        loops.append(asyncio.ensure_future(agent.security_loop()))
    if collect_packages is not None:
        loops.append(asyncio.ensure_future(agent.packages_loop()))
    if collect_events is not None:
        loops.append(asyncio.ensure_future(agent.events_loop()))
    if gossip is not None:
        loops.append(asyncio.ensure_future(agent.gossip_loop()))
    stopper = asyncio.ensure_future(stop.wait())
    try:
        done, _ = await asyncio.wait(loops + [stopper], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task is not stopper:
                # The loops never return; reaching here means a bug, so surface it.
                task.result()
    finally:
        # On Python 3.9-3.11, asyncio.wait_for can swallow a cancel that arrives just as
        # what it waits on finishes, and the loop then carries on. Cancel again until
        # every task has really ended, so stopping the service never hangs.
        pending = set(loops + [stopper])
        while pending:
            for task in pending:
                task.cancel()
            _, pending = await asyncio.wait(pending, timeout=0.1)
        await asyncio.gather(*loops, stopper, return_exceptions=True)
        agent.close()
