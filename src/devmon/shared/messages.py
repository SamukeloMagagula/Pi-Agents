from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, List

DEVICE_KINDS = ("pi", "linux", "windows-laptop", "windows-server")
_OS_NAMES = ("linux", "windows")
_WELCOME_STATUSES = ("approved", "pending")


class InvalidMessage(Exception):
    pass


# bool is a subclass of int, so it must be excluded explicitly. NaN and infinity are
# refused: JSON from the wire can carry them, and one would poison every average and
# threshold comparison it touches.
def _is_number(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    # Only floats can be NaN/inf (and isfinite() overflows on a huge int).
    return isinstance(v, int) or (isinstance(v, float) and math.isfinite(v))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _is_dict(v: Any) -> bool:
    return isinstance(v, dict)


def _is_list(v: Any) -> bool:
    return isinstance(v, list)


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


_CHECKS: Dict[str, Callable[[Any], bool]] = {
    "number": _is_number,
    "int": _is_int,
    "str": _is_str,
    "object": _is_dict,
    "list": _is_list,
    "bool": _is_bool,
}
_ARTICLES = {"number": "a number", "int": "an integer", "str": "a string",
             "object": "an object", "list": "a list",
             "bool": "true or false"}


def _field(obj: dict, name: str, kind: str, path: str, nullable: bool = False) -> Any:
    full = path + name
    if name not in obj:
        raise InvalidMessage(full + " is missing")
    value = obj[name]
    if value is None and nullable:
        return None
    if not _CHECKS[kind](value):
        suffix = " or null" if nullable else ""
        raise InvalidMessage(full + " must be " + _ARTICLES[kind] + suffix)
    return value


def _optional(obj: dict, name: str, kind: str, path: str, limit: int = 0) -> Any:
    """A field that may be absent or null. Validates only when present and not null."""
    if name not in obj or obj[name] is None:
        return None
    value = obj[name]
    if not _CHECKS[kind](value):
        raise InvalidMessage(path + name + " must be " + _ARTICLES[kind] + " or null")
    if limit and kind == "str" and len(value) > limit:
        raise InvalidMessage(path + name + " is too long")
    return value


def _sub(obj: dict, name: str, path: str) -> dict:
    return _field(obj, name, "object", path)


def _one_of(obj: dict, name: str, allowed: tuple, path: str = "") -> None:
    value = _field(obj, name, "str", path)
    if value not in allowed:
        raise InvalidMessage(path + name + " must be one of " + ", ".join(allowed))


def _max_len(m: dict, name: str, limit: int) -> None:
    if len(m[name]) > limit:
        raise InvalidMessage("%s must be at most %d characters" % (name, limit))


def _hello(m: dict) -> None:
    _field(m, "agent_version", "str", "")
    _max_len(m, "agent_version", 200)
    _field(m, "hostname", "str", "")
    _max_len(m, "hostname", 253)
    _one_of(m, "os", _OS_NAMES)
    _field(m, "os_detail", "str", "")
    _max_len(m, "os_detail", 200)
    _one_of(m, "device_kind", DEVICE_KINDS)
    # Phase 8, optional: older agents send none of these.
    if "fixer" in m:
        _field(m, "fixer", "bool", "")
    if "gossip_pub" in m:
        _hex_key(m, "gossip_pub", "")
    if "gossip_port" in m:
        _port_field(m, "gossip_port", "")


_HEX64 = re.compile(r"[0-9a-f]{64}")


def _hex_key(obj: dict, name: str, path: str) -> None:
    value = _field(obj, name, "str", path)
    if not _HEX64.fullmatch(value):
        raise InvalidMessage(path + name + " must be 64 lowercase hex characters")


def _port_field(obj: dict, name: str, path: str) -> int:
    value = _field(obj, name, "int", path)
    if not 1 <= value <= 65535:
        raise InvalidMessage(path + name + " must be 1-65535")
    return value


def _delivery(m: dict, path: str) -> None:
    # Added by agents that keep messages until the hub confirms them; older agents omit both.
    if "seq" in m and not (_is_int(m["seq"]) and m["seq"] >= 1):
        raise InvalidMessage(path + "seq must be a positive integer")
    if "sent" in m:
        _field(m, "sent", "number", path)


def _metrics(m: dict) -> None:
    _field(m, "ts", "number", "")
    _delivery(m, "metrics.")
    cpu = _sub(m, "cpu", "metrics.")
    _field(cpu, "percent", "number", "metrics.cpu.")
    _field(cpu, "cores", "int", "metrics.cpu.")
    _field(cpu, "load1", "number", "metrics.cpu.", nullable=True)
    mem = _sub(m, "mem", "metrics.")
    _field(mem, "percent", "number", "metrics.mem.")
    _field(mem, "swap_percent", "number", "metrics.mem.")
    _field(m, "temp_c", "number", "metrics.", nullable=True)
    net = _sub(m, "net", "metrics.")
    _field(net, "bytes_sent", "int", "metrics.net.")
    _field(net, "bytes_recv", "int", "metrics.net.")
    disks = _field(m, "disks", "list", "metrics.", nullable=True)
    for i, disk in enumerate(disks or []):
        p = "metrics.disks[%d]." % i
        if not isinstance(disk, dict):
            raise InvalidMessage("metrics.disks[%d] must be an object" % i)
        _field(disk, "mount", "str", p)
        for key in ("percent", "total_gb", "used_gb"):
            _field(disk, key, "number", p)
    _field(m, "uptime_s", "number", "metrics.", nullable=True)


def _db(m: dict) -> None:
    # Inner shapes are Task 12's concern; only the top level is checked here.
    _field(m, "ts", "number", "db.")
    _delivery(m, "db.")
    _field(m, "instance", "str", "db.")
    _field(m, "error", "str", "db.", nullable=True)
    _field(m, "overview", "object", "db.", nullable=True)
    _field(m, "long_running", "list", "db.")
    _field(m, "databases", "list", "db.")
    _field(m, "replication", "object", "db.", nullable=True)


def _ports(m: dict) -> None:
    _field(m, "ts", "number", "ports.")
    _delivery(m, "ports.")
    ports = _field(m, "ports", "list", "ports.")
    for i, entry in enumerate(ports):
        p = "ports.ports[%d]." % i
        if not isinstance(entry, dict):
            raise InvalidMessage("ports.ports[%d] must be an object" % i)
        _one_of(entry, "proto", ("tcp",), p)
        port = _field(entry, "port", "int", p)
        if not 1 <= port <= 65535:
            raise InvalidMessage(p + "port must be 1-65535")
        addresses = _field(entry, "addresses", "list", p)
        if not all(isinstance(a, str) for a in addresses):
            raise InvalidMessage(p + "addresses must be strings")
        _field(entry, "process", "str", p, nullable=True)


def _security(m: dict) -> None:
    # The helper's results are passed through as an object; the hub reads them defensively.
    _field(m, "ts", "number", "security.")
    _delivery(m, "security.")
    _field(m, "helper", "object", "security.", nullable=True)
    _field(m, "helper_error", "str", "security.", nullable=True)
    updates = _field(m, "updates", "object", "security.", nullable=True)
    if updates is not None:
        for key in ("available", "security"):
            value = _field(updates, key, "int", "security.updates.")
            if value < 0:
                raise InvalidMessage("security.updates.%s must be zero or more" % key)


MAX_PACKAGES = 20000
MAX_PACKAGE_FIELD = 200


def _packages(m: dict) -> None:
    _field(m, "ts", "number", "packages.")
    _delivery(m, "packages.")
    _field(m, "os", "object", "packages.")
    _field(m, "ecosystem", "str", "packages.", nullable=True)
    packages = _field(m, "packages", "list", "packages.")
    if len(packages) > MAX_PACKAGES:
        raise InvalidMessage("packages.packages has more than %d entries" % MAX_PACKAGES)
    for i, p in enumerate(packages):
        if not (isinstance(p, dict) and all(
                isinstance(p.get(k), str) and 0 < len(p[k]) <= MAX_PACKAGE_FIELD
                for k in ("name", "version"))):
            raise InvalidMessage("packages.packages[%d] needs a name and version "
                                 "(1-%d characters)" % (i, MAX_PACKAGE_FIELD))


MAX_EVENTS = 2000
EVENT_KINDS = ("auth_fail", "auth_ok", "fw_drop", "web_attack")
EVENT_SOURCES = ("ssh", "windows", "mariadb", "dbadmin", "firewall", "web")
MAX_EVENT_SOURCES = 20


def _events(m: dict) -> None:
    _field(m, "ts", "number", "events.")
    _delivery(m, "events.")
    events = _field(m, "events", "list", "events.")
    if len(events) > MAX_EVENTS:
        raise InvalidMessage("events.events has more than %d entries" % MAX_EVENTS)
    for i, e in enumerate(events):
        p = "events.events[%d]." % i
        if not isinstance(e, dict):
            raise InvalidMessage("events.events[%d] must be an object" % i)
        _field(e, "ts", "number", p)
        _one_of(e, "kind", EVENT_KINDS, p)
        _one_of(e, "source", EVENT_SOURCES, p)
        ip = _field(e, "ip", "str", p, nullable=True)
        if ip is not None and len(ip) > 64:
            raise InvalidMessage(p + "ip is too long")
        user = _field(e, "user", "str", p, nullable=True)
        if user is not None and len(user) > 128:
            raise InvalidMessage(p + "user is too long")
        port = _field(e, "port", "int", p, nullable=True)
        if port is not None and not 0 <= port <= 65535:
            raise InvalidMessage(p + "port must be 0-65535")
        if _field(e, "count", "int", p) < 1:
            raise InvalidMessage(p + "count must be at least 1")
        # Optional web-attack fields (Phase 9); older agents omit them entirely.
        _optional(e, "path", "str", p, 512)
        _optional(e, "method", "str", p, 16)
        _optional(e, "rule", "str", p, 64)
        score = _optional(e, "score", "number", p)
        if score is not None and not 0.0 <= score <= 1.0:
            raise InvalidMessage(p + "score must be between 0 and 1")
    sources = _field(m, "sources", "object", "events.", nullable=True)
    if sources is not None:
        if len(sources) > MAX_EVENT_SOURCES:
            raise InvalidMessage("events.sources has more than %d entries" % MAX_EVENT_SOURCES)
        for name, s in sources.items():
            if not (len(name) <= 100 and isinstance(s, dict) and isinstance(s.get("ok"), bool)
                    and isinstance(s.get("detail"), str) and len(s["detail"]) <= 300):
                raise InvalidMessage("events.sources[%r] needs ok and a short detail" % name[:100])


# ---- self-healing (Phase 8) -----------------------------------------------------------

ACTIONS = ("restart_service", "stop_process", "free_memory", "disk_cleanup", "cool_down",
           "block_ip", "unblock_ip", "reboot")
MODES = ("off", "suggest", "auto")
MAX_PARAMS = 8
MAX_PEERS = 64
MAX_TRUSTED = 200


def _params(m: dict, path: str) -> dict:
    params = _field(m, "params", "object", path)
    if len(params) > MAX_PARAMS:
        raise InvalidMessage(path + "params has more than %d entries" % MAX_PARAMS)
    for key, value in params.items():
        if len(key) > 40:
            raise InvalidMessage(path + "params has a name that is too long")
        ok = (isinstance(value, str) and len(value) <= 200) or _is_int(value) or value is None
        if not ok:
            raise InvalidMessage(path + "params.%s must be a short string or an integer" % key)
    return params


def _short_str(obj: dict, name: str, limit: int, path: str, nullable: bool = False) -> Any:
    value = _field(obj, name, "str", path, nullable=nullable)
    if value is not None and len(value) > limit:
        raise InvalidMessage("%s%s must be at most %d characters" % (path, name, limit))
    return value


def _fix(m: dict) -> None:
    if not (_is_int(m.get("id")) and m["id"] >= 1):
        raise InvalidMessage("fix.id must be a positive integer")
    _one_of(m, "action", ACTIONS, "fix.")
    _params(m, "fix.")


def _fix_result(m: dict) -> None:
    _field(m, "ts", "number", "fix_result.")
    _delivery(m, "fix_result.")
    rid = _field(m, "id", "int", "fix_result.", nullable=True)
    if rid is not None and rid < 1:
        raise InvalidMessage("fix_result.id must be a positive integer")
    _one_of(m, "action", ACTIONS, "fix_result.")
    _field(m, "ok", "bool", "fix_result.")
    _short_str(m, "detail", 500, "fix_result.")
    if rid is None:
        # Decided on the device while the hub was unreachable, or passed on by a peer.
        _one_of(m, "origin", ("local", "gossip"), "fix_result.")
        _short_str(m, "fault", 100, "fix_result.")
        _field(m, "detected", "number", "fix_result.")
        _params(m, "fix_result.")


def _policy(m: dict) -> None:
    you = _field(m, "you", "int", "policy.")
    if you < 1:
        raise InvalidMessage("policy.you must be a positive integer")
    modes = _field(m, "modes", "object", "policy.")
    for key, value in modes.items():
        if key not in ACTIONS + ("block_ip_lan",) or value not in MODES:
            raise InvalidMessage("policy.modes has an unknown action or mode")
    block_s = _field(m, "block_s", "int", "policy.")
    if not 60 <= block_s <= 7 * 86400:
        raise InvalidMessage("policy.block_s must be 60 s to 7 days")
    trusted = _field(m, "trusted", "list", "policy.")
    if len(trusted) > MAX_TRUSTED or not all(isinstance(t, str) and len(t) <= 64
                                             for t in trusted):
        raise InvalidMessage("policy.trusted must be at most %d short strings" % MAX_TRUSTED)
    thresholds = _field(m, "thresholds", "object", "policy.")
    if len(thresholds) > 40 or not all(_is_number(v) for v in thresholds.values()):
        raise InvalidMessage("policy.thresholds must hold numbers")
    peers = _field(m, "peers", "list", "policy.")
    if len(peers) > MAX_PEERS:
        raise InvalidMessage("policy.peers has more than %d entries" % MAX_PEERS)
    for i, p in enumerate(peers):
        path = "policy.peers[%d]." % i
        if not isinstance(p, dict):
            raise InvalidMessage("policy.peers[%d] must be an object" % i)
        _field(p, "id", "int", path)
        _short_str(p, "name", 253, path)
        _short_str(p, "ip", 64, path)
        _port_field(p, "port", path)
        _hex_key(p, "pub", path)


def _peers(m: dict) -> None:
    _field(m, "ts", "number", "peers.")
    _delivery(m, "peers.")
    peers = _field(m, "peers", "list", "peers.")
    if len(peers) > MAX_PEERS:
        raise InvalidMessage("peers.peers has more than %d entries" % MAX_PEERS)
    for i, p in enumerate(peers):
        path = "peers.peers[%d]." % i
        if not isinstance(p, dict):
            raise InvalidMessage("peers.peers[%d] must be an object" % i)
        _field(p, "id", "int", path)
        heard = _field(p, "heard_s", "number", path, nullable=True)
        if heard is not None and heard < 0:
            raise InvalidMessage(path + "heard_s must be zero or more")
        _field(p, "hub_ok", "bool", path, nullable=True)


def _welcome(m: dict) -> None:
    _one_of(m, "status", _WELCOME_STATUSES)


def _rejected(m: dict) -> None:
    pass


def _ack(m: dict) -> None:
    # Cumulative: the hub has handled every message up to and including seq.
    if not (_is_int(m.get("seq")) and m["seq"] >= 1):
        raise InvalidMessage("ack.seq must be a positive integer")


_VALIDATORS: Dict[str, Callable[[dict], None]] = {
    "hello": _hello,
    "metrics": _metrics,
    "db": _db,
    "ports": _ports,
    "security": _security,
    "packages": _packages,
    "events": _events,
    "welcome": _welcome,
    "rejected": _rejected,
    "ack": _ack,
    "fix": _fix,
    "fix_result": _fix_result,
    "policy": _policy,
    "peers": _peers,
}


def validate(obj: dict) -> dict:
    """Return obj unchanged, or raise InvalidMessage. Extra keys are allowed."""
    if not isinstance(obj, dict):
        raise InvalidMessage("message must be an object")
    if "type" not in obj:
        raise InvalidMessage("type is missing")
    mtype = obj["type"]
    if not isinstance(mtype, str) or mtype not in _VALIDATORS:
        raise InvalidMessage("unknown message type: %r" % (mtype,))
    _VALIDATORS[mtype](obj)
    return obj
