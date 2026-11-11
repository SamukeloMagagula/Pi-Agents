"""The fixer: carries out the hub's self-healing actions on this device, as root.

Run as a service (Linux only):

    python -I -m devmon.agent.fixer [--config /etc/devmon/fixer.ini]

Only the agent (the devmon account) and root can use its Unix socket. Each request names
one action from a fixed list, and the fixer checks it against its own rules before doing
anything:
- it never stops protected processes, root's processes (unless allowed), or devmon itself
- it never blocks its hub, its own addresses, loopback or the never_block list
- each action has a cooldown, and there is a limit per hour

A hub or agent that has been taken over can therefore at worst ask for the actions this
device's owner allowed in fixer.ini, on targets the fixer agrees to.
"""
from __future__ import annotations

import argparse
import configparser
import glob
import ipaddress
import json
import logging
import os
import posixpath
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

log = logging.getLogger("devmon.agent.fixer")

ACTIONS = ("restart_service", "stop_process", "free_memory", "disk_cleanup", "cool_down",
           "block_ip", "unblock_ip", "reboot")
DEFAULT_CONFIG = "/etc/devmon/fixer.ini"
DEFAULT_SOCKET = "/run/devmon-fixer/fixer.sock"
DEFAULT_AGENT_INI = "/etc/devmon/agent.ini"
DEFAULT_CLEANUP_DIRS = ("/var/tmp/devmon-scratch",)

# Never stopped, whatever the configuration says: the system, remote access, databases,
# and anything of devmon's (matched on the command line too).
DEFAULT_PROTECTED = frozenset((
    "systemd", "init", "sshd", "sshd-session", "ssh", "dbus-daemon", "dbus-broker",
    "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-networkd",
    "systemd-resolved", "systemd-timesyncd", "agetty", "getty", "login", "cron", "crond",
    "rsyslogd", "NetworkManager", "wpa_supplicant", "dhcpcd", "avahi-daemon", "polkitd",
    "sudo", "su", "mariadbd", "mysqld", "postgres", "Xorg", "lightdm", "nft", "ufw"))
DEFAULT_PROTECTED_UNITS = frozenset((
    "devmon-agent", "devmon-fixer", "devmon-helper", "dbus", "systemd-journald",
    "systemd-logind", "systemd-udevd"))

COOLDOWN_S = 60
REBOOT_COOLDOWN_S = 3600
HOURLY_LIMIT = 30
MIN_UPTIME_FOR_REBOOT_S = 600
REBOOT_DELAY_S = 5
COOL_DOWN_S = 900
BLOCK_MIN_S, BLOCK_MAX_S, BLOCK_DEFAULT_S = 60, 7 * 86400, 3600
TEMP_MAX_AGE_S = 7 * 86400
# A process using less than this is not worth stopping: something else is the problem.
STOP_MIN_CPU = 10.0
STOP_MIN_MEM = 2.0
STOP_GRACE_S = 5
MAX_REQUEST = 8192
REQUEST_TIMEOUT_S = 5

_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:\-]{0,98}")
_MOUNT = re.compile(r"/[^\x00-\x1f\x7f]{0,200}")

Network = Any  # ipaddress.IPv4Network | IPv6Network


class Refused(Exception):
    """The request is not allowed; nothing was done."""


# ---- configuration --------------------------------------------------------------------


@dataclass
class FixerConfig:
    enabled: Set[str] = field(default_factory=lambda: set(ACTIONS))
    protected_processes: Set[str] = field(default_factory=lambda: set(DEFAULT_PROTECTED))
    protected_units: Set[str] = field(default_factory=lambda: set(DEFAULT_PROTECTED_UNITS))
    never_block: List[Network] = field(default_factory=list)
    cleanup_dirs: List[str] = field(default_factory=lambda: list(DEFAULT_CLEANUP_DIRS))
    stop_root_processes: bool = False
    socket_path: str = DEFAULT_SOCKET
    agent_ini: str = DEFAULT_AGENT_INI
    group: str = "devmon"


def _words(text: str) -> List[str]:
    return [w for w in re.split(r"[\s,]+", text.strip()) if w]


def load_config(path: str) -> FixerConfig:
    """Read fixer.ini. A missing file means the defaults; a bad value stops the fixer."""
    cfg = FixerConfig()
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8-sig") as f:
            parser.read_file(f)
    except FileNotFoundError:
        return cfg
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise ValueError("cannot read %s: %s" % (path, exc))
    if not parser.has_section("fixer"):
        return cfg
    sec = parser["fixer"]
    if "enabled_actions" in sec:
        enabled = set(_words(sec["enabled_actions"]))
        unknown = enabled - set(ACTIONS)
        if unknown:
            raise ValueError("enabled_actions: unknown action(s) %s" % ", ".join(sorted(unknown)))
        cfg.enabled = enabled
    # Additions only: the built-in protections can't be switched off from here.
    cfg.protected_processes |= set(_words(sec.get("protected_processes", "")))
    cfg.protected_units |= {u[:-8] if u.endswith(".service") else u
                            for u in _words(sec.get("protected_units", ""))}
    for entry in _words(sec.get("never_block", "")):
        try:
            cfg.never_block.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ValueError("never_block: %r is not an IP address or network" % entry)
    if "cleanup_dirs" in sec:
        dirs = _words(sec["cleanup_dirs"])
        for d in dirs:
            if not d.startswith("/") or posixpath.normpath(d) in ("/", "/etc", "/usr", "/var",
                                                              "/home", "/root", "/boot"):
                raise ValueError("cleanup_dirs: %r is not a safe folder to empty" % d)
        cfg.cleanup_dirs = dirs
    try:
        cfg.stop_root_processes = sec.getboolean("stop_root_processes", False)
    except ValueError:
        raise ValueError("stop_root_processes must be yes or no")
    cfg.socket_path = sec.get("socket", cfg.socket_path)
    cfg.agent_ini = sec.get("agent_ini", cfg.agent_ini)
    return cfg


# ---- the system, behind one object so tests can replace it ---------------------------


Proc = Dict[str, Any]  # pid, ppid, name, user, uid, cmdline, cpu, mem, created, kernel


class System:
    """Everything the fixer does to the machine. Tests use a fake with the same methods."""

    def run(self, cmd: List[str], timeout: float = 60,
            stdin: Optional[str] = None) -> Tuple[int, str]:
        try:
            p = subprocess.run(cmd, input=None if stdin is None else stdin.encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False)
        except FileNotFoundError:
            return 127, "%s is not installed" % cmd[0]
        except subprocess.TimeoutExpired:
            return 124, "%s did not finish within %d s" % (cmd[0], timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace").strip()

    def processes(self, sample_s: float = 1.0) -> List[Proc]:
        import psutil  # only needed here; keeps the module importable for tests anywhere

        procs = list(psutil.process_iter())
        for p in procs:
            try:
                p.cpu_percent(None)
            except psutil.Error:
                pass
        time.sleep(sample_s)
        out = []
        for p in procs:
            try:
                with p.oneshot():
                    ppid = p.ppid()
                    cmdline = " ".join(p.cmdline())
                    out.append({
                        "pid": p.pid, "ppid": ppid, "name": p.name(),
                        "user": p.username(), "uid": p.uids().real,
                        "cmdline": cmdline, "cpu": p.cpu_percent(None),
                        "mem": p.memory_percent(), "created": p.create_time(),
                        # Kernel threads have no command line and hang off kthreadd (pid 2).
                        "kernel": p.pid == 2 or ppid == 2 or not cmdline,
                    })
            except psutil.Error:
                continue
        return out

    def stop(self, pid: int, created: float, grace: float) -> str:
        import psutil

        try:
            p = psutil.Process(pid)
            if p.create_time() != created:
                return "gone"  # the pid was reused: never signal a different process
            p.terminate()
            try:
                p.wait(grace)
                return "stopped"
            except psutil.TimeoutExpired:
                p.kill()
                p.wait(grace)
                return "killed"
        except psutil.NoSuchProcess:
            return "gone"

    def renice(self, pid: int, created: float, value: int) -> bool:
        import psutil

        try:
            p = psutil.Process(pid)
            if p.create_time() != created:
                return False
            p.nice(value)
            return True
        except psutil.Error:
            return False

    def mem_available_mb(self) -> Optional[float]:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) / 1024
        except OSError:
            pass
        return None

    def write_file(self, path: str, text: str) -> None:
        with open(path, "w") as f:
            f.write(text)

    def read_file(self, path: str) -> str:
        with open(path) as f:
            return f.read().strip()

    def glob(self, pattern: str) -> List[str]:
        return sorted(glob.glob(pattern))

    def free_bytes(self, path: str) -> int:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def remove_files(self, top: str, older_than: Optional[float]) -> Tuple[int, int]:
        """Delete regular files under `top` (older than the cutoff, if given).

        Walks with directory descriptors and never follows symbolic links, so a user who
        swaps a folder for a link to /etc mid-walk can't make root delete elsewhere.
        Stays on top's filesystem. Returns (files, bytes).
        """
        count = size = 0
        try:
            top_dev = os.stat(top, follow_symlinks=False).st_dev
        except OSError:
            return 0, 0
        for _, _, files, dirfd in os.fwalk(top, follow_symlinks=False):
            for name in files:
                try:
                    st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or st.st_dev != top_dev:
                        continue
                    if older_than is not None and st.st_mtime >= older_than:
                        continue
                    os.unlink(name, dir_fd=dirfd)
                    count += 1
                    size += st.st_size
                except OSError:
                    continue
        return count, size

    def uptime_s(self) -> float:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])

    def own_addresses(self) -> List[str]:
        import psutil

        out = []
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    out.append(a.address.split("%")[0])
        return out

    def resolve(self, host: str) -> List[str]:
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except OSError:
            return []

    def later(self, delay: float, fn: Callable[[], None]) -> None:
        t = threading.Timer(delay, fn)
        t.daemon = True
        t.start()


# ---- the fixer ------------------------------------------------------------------------


def _hub_host(agent_ini: str) -> Optional[str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(agent_ini, encoding="utf-8-sig") as f:
            parser.read_file(f)
        return parser.get("hub", "host", fallback=None)
    except (OSError, UnicodeError, configparser.Error):
        return None


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024
    return "%.1f GB" % n


class Fixer:
    def __init__(self, cfg: FixerConfig, system: Optional[System] = None,
                 clock: Callable[[], float] = time.time,
                 hub_host: Optional[str] = None) -> None:
        self.cfg = cfg
        self.sys = system or System()
        self.clock = clock
        self.hub_host = hub_host if hub_host is not None else _hub_host(cfg.agent_ini)
        self._last: Dict[Tuple[str, str], float] = {}
        self._recent: List[float] = []
        self._saved_governors: Optional[Dict[str, str]] = None
        self._lock = threading.Lock()

    # ---- entry point ------------------------------------------------------------------

    def handle(self, request: Any) -> Dict[str, Any]:
        """Check and carry out one request. Always returns {"ok": bool, "detail": str}."""
        with self._lock:
            try:
                action, params = self._parse(request)
                target = self._target(action, params)
                self._check_limits(action, target)
                detail = getattr(self, "_do_" + action)(params)
            except Refused as exc:
                log.warning("refused %s: %s", _describe(request), exc)
                return {"ok": False, "detail": "refused: %s" % exc}
            except Exception as exc:  # a failed action must never stop the fixer
                log.exception("%s failed", _describe(request))
                return {"ok": False, "detail": "failed: %s" % (str(exc) or type(exc).__name__)}
            log.info("%s: %s", _describe(request), detail)
            return {"ok": True, "detail": detail}

    def _parse(self, request: Any) -> Tuple[str, Dict[str, Any]]:
        if not isinstance(request, dict):
            raise Refused("not a request")
        action = request.get("action")
        params = request.get("params", {})
        if action not in ACTIONS:
            raise Refused("unknown action")
        if action not in self.cfg.enabled:
            raise Refused("%s is switched off in fixer.ini on this device" % action)
        if not isinstance(params, dict):
            raise Refused("params must be an object")
        return action, params

    def _target(self, action: str, params: Dict[str, Any]) -> str:
        if action == "restart_service":
            return self._unit(params.get("unit"))
        if action in ("block_ip", "unblock_ip"):
            return str(self._ip(params.get("ip")))
        if action == "stop_process":
            return self._by(params)
        if action == "disk_cleanup":
            return self._mount(params.get("mount"))
        return ""

    def _check_limits(self, action: str, target: str) -> None:
        now = self.clock()
        if action != "unblock_ip":
            self._recent = [t for t in self._recent if now - t < 3600]
            if len(self._recent) >= HOURLY_LIMIT:
                raise Refused("already %d actions in the last hour" % HOURLY_LIMIT)
        cooldown = {"reboot": REBOOT_COOLDOWN_S, "block_ip": 0, "unblock_ip": 0}.get(
            action, COOLDOWN_S)
        last = self._last.get((action, target))
        if last is not None and now - last < cooldown:
            raise Refused("%s was done %d s ago; wait %d s between them" % (
                action, now - last, cooldown))
        self._last[(action, target)] = now
        if action != "unblock_ip":
            self._recent.append(now)

    # ---- parameter checks -------------------------------------------------------------

    def _unit(self, unit: Any) -> str:
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
            raise Refused("not a valid service name")
        if "." in unit and not unit.endswith(".service"):
            raise Refused("only .service units can be restarted")
        base = unit[:-8] if unit.endswith(".service") else unit
        if base in self.cfg.protected_units or base.split("@")[0] in self.cfg.protected_units:
            raise Refused("%s is protected" % base)
        return base + ".service"

    def _ip(self, text: Any) -> Any:
        if not isinstance(text, str):
            raise Refused("ip is missing")
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            raise Refused("not an IP address")
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        return addr

    def _by(self, params: Dict[str, Any]) -> str:
        by = params.get("by", "cpu")
        if by not in ("cpu", "mem"):
            raise Refused("by must be cpu or mem")
        return by

    def _mount(self, mount: Any) -> str:
        if mount is None:
            return "/"
        if not isinstance(mount, str) or not _MOUNT.fullmatch(mount):
            raise Refused("not a valid mount point")
        return mount

    def _never_block(self, addr: Any) -> Optional[str]:
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            return "a loopback, link-local or multicast address"
        for net in self.cfg.never_block:
            if addr.version == net.version and addr in net:
                return "on this device's never_block list"
        if str(addr) in self.sys.own_addresses():
            return "this device's own address"
        if self.hub_host and (str(addr) == self.hub_host or
                              str(addr) in self.sys.resolve(self.hub_host)):
            return "the hub's address"
        return None

    # ---- processes ----------------------------------------------------------------------

    def _protected(self, p: Proc) -> bool:
        if p["pid"] <= 2 or p["kernel"] or p["pid"] == os.getpid() or p["pid"] == os.getppid():
            return True
        if p["name"] in self.cfg.protected_processes:
            return True
        if "devmon" in p["cmdline"] or "devmon" in p["name"]:
            return True
        return p["uid"] == 0 and not self.cfg.stop_root_processes

    def _busiest(self, by: str) -> Optional[Proc]:
        candidates = [p for p in self.sys.processes() if not self._protected(p)]
        if not candidates:
            return None
        top = max(candidates, key=lambda p: p[by])
        floor = STOP_MIN_CPU if by == "cpu" else STOP_MIN_MEM
        return top if top[by] >= floor else None

    @staticmethod
    def _who(p: Proc, by: str) -> str:
        use = "%.0f%% CPU" % p["cpu"] if by == "cpu" else "%.1f%% memory" % p["mem"]
        return "%s (pid %d, user %s, %s)" % (p["name"], p["pid"], p["user"], use)

    # ---- actions -----------------------------------------------------------------------

    def _do_restart_service(self, params: Dict[str, Any]) -> str:
        unit = self._unit(params.get("unit"))
        rc, out = self.sys.run(["systemctl", "show", "--property=LoadState", "--value", unit],
                               timeout=15)
        if rc != 0 or out.strip() != "loaded":
            raise Refused("%s is not a service on this device" % unit)
        rc, out = self.sys.run(["systemctl", "restart", unit], timeout=90)
        if rc != 0:
            raise RuntimeError("systemctl restart %s: %s" % (unit, out[-200:] or "rc %d" % rc))
        rc, state = self.sys.run(["systemctl", "is-active", unit], timeout=15)
        if state.strip() != "active":
            raise RuntimeError("restarted %s, but it is %s" % (unit, state.strip() or "not active"))
        return "restarted %s; it is running" % unit

    def _do_stop_process(self, params: Dict[str, Any]) -> str:
        by = self._by(params)
        p = self._busiest(by)
        if p is None:
            raise Refused("no unprotected process is using much %s" % (
                "CPU" if by == "cpu" else "memory"))
        result = self.sys.stop(p["pid"], p["created"], STOP_GRACE_S)
        if result == "gone":
            return "%s had already ended" % self._who(p, by)
        return "%s %s" % (result, self._who(p, by))

    def _do_free_memory(self, params: Dict[str, Any]) -> str:
        before = self.sys.mem_available_mb()
        self.sys.run(["sync"], timeout=60)
        # 3: page cache plus dentries and inodes. Only clean, rebuildable data is dropped.
        self.sys.write_file("/proc/sys/vm/drop_caches", "3")
        after = self.sys.mem_available_mb()
        if before is None or after is None:
            return "dropped the page cache"
        return "dropped the page cache: available memory %.0f MB -> %.0f MB" % (before, after)

    def _do_disk_cleanup(self, params: Dict[str, Any]) -> str:
        mount = self._mount(params.get("mount"))
        if not self.sys.is_dir(mount):
            mount = "/"
        before = self.sys.free_bytes(mount)
        done = []
        rc, _ = self.sys.run(["journalctl", "--vacuum-size=100M"], timeout=120)
        if rc == 0:
            done.append("journal trimmed to 100 MB")
        rc, _ = self.sys.run(["apt-get", "clean"], timeout=120)
        if rc == 0:
            done.append("package cache cleared")
        cutoff = self.clock() - TEMP_MAX_AGE_S
        n = 0
        for d in ("/tmp", "/var/tmp"):
            if self.sys.is_dir(d):
                n += self.sys.remove_files(d, cutoff)[0]
        if n:
            done.append("%d temporary file%s over a week old" % (n, "" if n == 1 else "s"))
        for d in self.cfg.cleanup_dirs:
            if self.sys.is_dir(d):
                count, _ = self.sys.remove_files(d, None)
                if count:
                    done.append("%d file%s in %s" % (count, "" if count == 1 else "s", d))
        freed = max(self.sys.free_bytes(mount) - before, 0)
        what = "; ".join(done) if done else "nothing to remove"
        return "freed %s on %s (%s)" % (_fmt_bytes(freed), mount, what)

    def _do_cool_down(self, params: Dict[str, Any]) -> str:
        done = []
        files = self.sys.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")
        if files:
            if self._saved_governors is None:
                self._saved_governors = {f: self.sys.read_file(f) for f in files}
                self.sys.later(COOL_DOWN_S, self._restore_governors)
            for f in files:
                self.sys.write_file(f, "powersave")
            done.append("CPU set to powersave for %d minutes" % (COOL_DOWN_S // 60))
        p = self._busiest("cpu")
        if p is not None and self.sys.renice(p["pid"], p["created"], 19):
            done.append("lowered the priority of " + self._who(p, "cpu"))
        if not done:
            raise RuntimeError("no CPU frequency control and no busy process to slow down")
        return "; ".join(done)

    def _restore_governors(self) -> None:
        with self._lock:
            saved, self._saved_governors = self._saved_governors, None
            for f, gov in (saved or {}).items():
                try:
                    self.sys.write_file(f, gov)
                except OSError as exc:
                    log.warning("could not restore %s: %s", f, exc)
            log.info("cool-down over; CPU governors restored")

    def _nft_set(self, addr: Any) -> str:
        return "blocked4" if addr.version == 4 else "blocked6"

    def _ensure_table(self) -> None:
        rc, _ = self.sys.run(["nft", "list", "table", "inet", "devmon"], timeout=15)
        if rc == 0:
            return
        if rc == 127:
            raise RuntimeError("nftables (nft) is not installed")
        script = (
            "table inet devmon {\n"
            "  set blocked4 { type ipv4_addr; flags timeout; }\n"
            "  set blocked6 { type ipv6_addr; flags timeout; }\n"
            # Before ufw/firewalld's own chains, so a block wins over their accepts.
            "  chain input { type filter hook input priority -10; policy accept;\n"
            "    ip saddr @blocked4 drop\n"
            "    ip6 saddr @blocked6 drop\n"
            "  }\n"
            "}\n")
        rc, out = self.sys.run(["nft", "-f", "-"], timeout=15, stdin=script)
        if rc != 0:
            raise RuntimeError("could not create the nftables table: %s" % out[-200:])

    def _do_block_ip(self, params: Dict[str, Any]) -> str:
        addr = self._ip(params.get("ip"))
        why = self._never_block(addr)
        if why:
            raise Refused("%s is %s" % (addr, why))
        seconds = params.get("seconds", BLOCK_DEFAULT_S)
        if not isinstance(seconds, int) or isinstance(seconds, bool):
            raise Refused("seconds must be a whole number")
        seconds = min(max(seconds, BLOCK_MIN_S), BLOCK_MAX_S)
        self._ensure_table()
        element = "{ %s timeout %ds }" % (addr, seconds)
        rc, out = self.sys.run(["nft", "add", "element", "inet", "devmon", self._nft_set(addr),
                                element], timeout=15)
        if rc != 0:
            raise RuntimeError("nft: %s" % out[-200:])
        return "blocked %s for %s" % (addr, _span(seconds))

    def _do_unblock_ip(self, params: Dict[str, Any]) -> str:
        addr = self._ip(params.get("ip"))
        rc, out = self.sys.run(["nft", "delete", "element", "inet", "devmon",
                                self._nft_set(addr), "{ %s }" % addr], timeout=15)
        if rc != 0:
            if rc == 127:
                raise RuntimeError("nftables (nft) is not installed")
            return "%s was not blocked" % addr
        return "unblocked %s" % addr

    def _do_reboot(self, params: Dict[str, Any]) -> str:
        up = self.sys.uptime_s()
        if up < MIN_UPTIME_FOR_REBOOT_S:
            raise Refused("this device started %d s ago; not rebooting again so soon" % up)
        # Answer first, so the agent can report the result before the system goes down.
        self.sys.later(REBOOT_DELAY_S, lambda: self.sys.run(["systemctl", "reboot"], timeout=30))
        return "rebooting in %d s" % REBOOT_DELAY_S


def _span(seconds: int) -> str:
    if seconds % 3600 == 0:
        h = seconds // 3600
        return "1 hour" if h == 1 else "%d hours" % h
    if seconds % 60 == 0:
        return "%d minutes" % (seconds // 60)
    return "%d s" % seconds


def _describe(request: Any) -> str:
    if not isinstance(request, dict):
        return "request"
    params = request.get("params")
    shown = ""
    if isinstance(params, dict):
        shown = ", ".join("%s=%s" % (k, str(v)[:60]) for k, v in sorted(params.items())[:4])
    return "%s(%s)" % (str(request.get("action"))[:40], shown)


# ---- the socket -----------------------------------------------------------------------


def _peer_uid(conn: socket.socket) -> Optional[int]:
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    except (OSError, AttributeError):
        return None
    _, uid, _ = struct.unpack("3i", creds)
    return uid


def read_request(conn: socket.socket) -> Any:
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_REQUEST:
            raise ValueError("request too large")
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8"))


def serve_one(fixer: Fixer, conn: socket.socket, allowed_uids: Sequence[int]) -> None:
    conn.settimeout(REQUEST_TIMEOUT_S)
    uid = _peer_uid(conn)
    if uid is None or uid not in allowed_uids:
        log.warning("refused a connection from uid %s", uid)
        return
    try:
        request = read_request(conn)
    except (ValueError, OSError) as exc:
        reply: Dict[str, Any] = {"ok": False, "detail": "bad request: %s" % exc}
    else:
        reply = fixer.handle(request)
    conn.settimeout(None)
    conn.sendall(json.dumps(reply).encode("utf-8") + b"\n")


def open_socket(path: str, group: str) -> socket.socket:
    import grp

    gid = grp.getgrnam(group).gr_gid
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    os.chown(folder, 0, gid)
    os.chmod(folder, 0o750)
    if os.path.lexists(path):
        os.unlink(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    os.chown(path, 0, gid)
    os.chmod(path, 0o660)
    sock.listen(8)
    return sock


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -I -m devmon.agent.fixer",
                                     description="devmon fixer: self-healing actions (root)")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not sys.platform.startswith("linux"):
        log.error("the fixer runs on Linux only")
        return 2
    if os.geteuid() != 0:
        log.error("the fixer must run as root")
        return 2
    try:
        cfg = load_config(args.config)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    import pwd

    try:
        allowed = [0, pwd.getpwnam(cfg.group).pw_uid]
    except KeyError:
        log.error("there is no %s account; run the agent installer first", cfg.group)
        return 2
    fixer = Fixer(cfg)
    sock = open_socket(cfg.socket_path, cfg.group)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log.info("fixer ready on %s; actions: %s", cfg.socket_path, ", ".join(sorted(cfg.enabled)))
    while True:
        conn, _ = sock.accept()
        try:
            serve_one(fixer, conn, allowed)
        except Exception:
            log.exception("request failed")
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
