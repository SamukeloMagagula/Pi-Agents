"""The agent's side of self-healing: talking to the fixer, keeping the hub's policy, and
deciding alone while the hub is unreachable.

The hub normally decides every action. If it has been silent for HUB_SILENT_S, the agent
uses the last policy the hub sent (kept on disk, so it survives a restart). It takes only
actions set to automatic, for these faults:
- a full disk
- overheating
- low memory
- an attacker found in its own logs

Results are queued like any other message and reach the hub's log once it is back.
"""
from __future__ import annotations

import json
import logging
import os
import socket
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from devmon.shared import netrules
from devmon.shared.messages import InvalidMessage, validate

log = logging.getLogger(__name__)

DEFAULT_FIXER_SOCKET = "/run/devmon-fixer/fixer.sock"
FIX_TIMEOUT_S = 150  # a service restart may take 90 s
MAX_REPLY = 8192
HUB_SILENT_S = 60
LOCAL_COOLDOWN_S = 600
# The hub's attack rules (hub/attacks.py), applied to this device's own events.
BRUTE_WINDOW_S, BRUTE_MIN = 300, 10
SCAN_WINDOW_S, SCAN_MIN_PORTS = 60, 15
DEFAULT_THRESHOLDS = {"mem_red": 90.0, "disk_red": 90.0, "temp_red": 80.0}

Request = Dict[str, Any]


class FixerLink:
    """A blocking client for the fixer's Unix socket; the agent calls it from a thread."""

    def __init__(self, path: str = DEFAULT_FIXER_SOCKET, timeout: float = FIX_TIMEOUT_S) -> None:
        self.path = path
        self.timeout = timeout

    def available(self) -> bool:
        return os.path.exists(self.path)

    def call(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            return {"ok": False, "detail": "there is no fixer on this kind of device"}
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                s.sendall(json.dumps({"action": action, "params": params}).encode() + b"\n")
                data = b""
                while b"\n" not in data and len(data) < MAX_REPLY:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        except FileNotFoundError:
            return {"ok": False, "detail": "the fixer is not running on this device"}
        except OSError as exc:
            return {"ok": False, "detail": "could not reach the fixer: %s" % exc}
        try:
            reply = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        except ValueError:
            return {"ok": False, "detail": "the fixer gave no answer"}
        if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
            return {"ok": False, "detail": "the fixer gave an unexpected answer"}
        return {"ok": reply["ok"], "detail": str(reply.get("detail", ""))[:500]}


class PolicyStore:
    """The last policy the hub sent, also kept on disk for local decisions after a restart."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.policy: Optional[Dict[str, Any]] = None
        if path is not None:
            self.policy = self._load(path)

    @staticmethod
    def _load(path: Path) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return validate(data) if data.get("type") == "policy" else None
        except FileNotFoundError:
            return None
        except (OSError, ValueError, InvalidMessage, AttributeError) as exc:
            log.warning("ignoring the saved healing policy (%s)", exc)
            return None

    def update(self, policy: Dict[str, Any]) -> bool:
        """Keep a new policy; True if it differs from the last one."""
        changed = policy != self.policy
        self.policy = policy
        if changed and self.path is not None:
            tmp = self.path.with_name(self.path.name + ".tmp")
            try:
                tmp.write_text(json.dumps(policy), encoding="utf-8")
                os.replace(str(tmp), str(self.path))
            except OSError as exc:
                log.warning("could not save the healing policy: %s", exc)
        return changed

    def mode(self, action: str) -> str:
        if self.policy is None:
            return "off"
        return self.policy["modes"].get(action, "off")

    def block_mode(self, ip: str) -> str:
        return self.mode("block_ip_lan" if netrules.is_internal(ip) else "block_ip")

    def trusted(self, ip: str) -> bool:
        nets = netrules.networks(self.policy["trusted"]) if self.policy else []
        return netrules.in_networks(ip, nets)

    def threshold(self, name: str) -> float:
        if self.policy is not None and name in self.policy["thresholds"]:
            return float(self.policy["thresholds"][name])
        return DEFAULT_THRESHOLDS[name]

    @property
    def block_s(self) -> int:
        return self.policy["block_s"] if self.policy else 3600


class LocalHealer:
    """Decides actions on the device itself while the hub is unreachable.

    Pure logic: it returns requests (fault, action, params, detected) and the runner carries
    them out through the fixer.
    """

    def __init__(self, policy: PolicyStore) -> None:
        self.policy = policy
        self._last: Dict[Tuple[str, str], float] = {}
        self._red_since: Dict[str, float] = {}
        self._fails: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._drops: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self.blocked: Dict[str, float] = {}  # ip -> until (local and gossiped blocks)

    def _allowed(self, action: str, target: str, now: float) -> bool:
        if self.policy.mode(action) != "auto":
            return False
        last = self._last.get((action, target))
        if last is not None and now - last < LOCAL_COOLDOWN_S:
            return False
        self._last[(action, target)] = now
        return True

    def _red(self, fault: str, is_red: bool, now: float) -> Optional[float]:
        if not is_red:
            self._red_since.pop(fault, None)
            return None
        return self._red_since.setdefault(fault, now)

    def on_metrics(self, msg: Dict[str, Any], now: float, hub_silent_s: float) -> List[Request]:
        """Called with every metrics reading; returns what to do (only if the hub is silent)."""
        p = self.policy
        checks = [("mem", "free_memory", {}, msg["mem"]["percent"] >= p.threshold("mem_red"))]
        temp = msg.get("temp_c")
        checks.append(("temp", "cool_down", {},
                       temp is not None and temp >= p.threshold("temp_red")))
        for disk in msg.get("disks") or ():
            checks.append(("disk:" + disk["mount"], "disk_cleanup", {"mount": disk["mount"]},
                           disk["percent"] >= p.threshold("disk_red")))
        out = []
        for fault, action, params, is_red in checks:
            since = self._red(fault, is_red, now)
            if since is None or hub_silent_s < HUB_SILENT_S:
                continue
            if self._allowed(action, fault, now):
                out.append({"fault": fault, "action": action, "params": params,
                            "detected": since, "origin": "local"})
        return out

    def on_events(self, msg: Dict[str, Any], now: float, hub_silent_s: float) -> List[Request]:
        """Counts this device's failed logins and firewall drops per IP, as the hub does."""
        for e in msg.get("events", ()):
            ip = e.get("ip")
            if ip is None or netrules.parse_ip(ip) is None:
                continue
            if e["kind"] == "auth_fail":
                self._fails[ip].append((e["ts"], e["count"]))
            elif e["kind"] == "fw_drop" and e.get("port") is not None:
                self._drops[ip].append((e["ts"], e["port"]))
        out = []
        for ip in set(self._fails) | set(self._drops):
            fails = self._fails[ip]
            while fails and fails[0][0] < now - BRUTE_WINDOW_S:
                fails.popleft()
            drops = self._drops[ip]
            while drops and drops[0][0] < now - SCAN_WINDOW_S:
                drops.popleft()
            if not fails and not drops:
                self._fails.pop(ip, None)
                self._drops.pop(ip, None)
                continue
            attack = (sum(c for _, c in fails) >= BRUTE_MIN or
                      len({port for _, port in drops}) >= SCAN_MIN_PORTS)
            if not attack or hub_silent_s < HUB_SILENT_S:
                continue
            first = min([t for t, _ in fails] + [t for t, _ in drops])
            req = self._block(ip, now, "local", first)
            if req is not None:
                out.append(req)
        return out

    def on_peer_block(self, ip: str, until: float, now: float) -> Optional[Request]:
        """A peer blocked an attacker while its hub was unreachable: block it here too."""
        if until <= now:
            return None
        return self._block(ip, now, "gossip", now, seconds=int(min(until - now, 7 * 86400)))

    def _block(self, ip: str, now: float, origin: str, detected: float,
               seconds: Optional[int] = None) -> Optional[Request]:
        if self.policy.trusted(ip) or self.blocked.get(ip, 0) > now:
            return None
        action = "block_ip_lan" if netrules.is_internal(ip) else "block_ip"
        if not self._allowed(action, ip, now):
            return None
        seconds = max(60, seconds if seconds is not None else self.policy.block_s)
        self.blocked[ip] = now + seconds
        return {"fault": "attack", "action": "block_ip",
                "params": {"ip": ip, "seconds": seconds}, "detected": detected, "origin": origin}

    def blocks_to_share(self, now: float) -> List[List[Any]]:
        self.blocked = {ip: until for ip, until in self.blocked.items() if until > now}
        return [[ip, until] for ip, until in sorted(self.blocked.items())][:32]


def result_message(request: Request, reply: Dict[str, Any], now: float) -> Dict[str, Any]:
    """The fix_result for a local or gossiped action."""
    return {"type": "fix_result", "ts": now, "id": None, "action": request["action"],
            "ok": reply["ok"], "detail": reply["detail"][:500], "origin": request["origin"],
            "fault": request["fault"][:100], "detected": request["detected"],
            "params": request["params"]}
