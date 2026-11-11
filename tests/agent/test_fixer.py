from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import threading

import pytest

from devmon.agent import fixer as fx
from devmon.agent.fixer import Fixer, FixerConfig, load_config


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def proc(pid, name, cpu=0.0, mem=0.0, uid=1000, cmdline=None, kernel=False):
    return {"pid": pid, "ppid": 1, "name": name, "user": "pi" if uid else "root", "uid": uid,
            "cmdline": cmdline if cmdline is not None else "/usr/bin/" + name,
            "cpu": cpu, "mem": mem, "created": 5.0, "kernel": kernel}


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.replies = {}           # first word(s) of a command -> (rc, out)
        self.procs = []
        self.stopped = []
        self.reniced = []
        self.files = {}
        self.written = {}
        self.free = [1000, 5000]
        self.dirs = {"/", "/tmp", "/var/tmp", "/var/tmp/devmon-scratch"}
        self.removed = {}
        self.uptime = 3600.0
        self.addresses = ["192.168.1.20", "127.0.0.1"]
        self.later_calls = []
        self.mem = [100.0, 400.0]

    def run(self, cmd, timeout=60, stdin=None):
        self.calls.append((cmd, stdin))
        for n in (4, 3, 2, 1):
            key = " ".join(cmd[:n])
            if key in self.replies:
                return self.replies[key]
        return 0, ""

    def processes(self, sample_s=1.0):
        return list(self.procs)

    def stop(self, pid, created, grace):
        self.stopped.append(pid)
        return "stopped"

    def renice(self, pid, created, value):
        self.reniced.append((pid, value))
        return True

    def mem_available_mb(self):
        return self.mem.pop(0) if self.mem else None

    def write_file(self, path, text):
        self.written[path] = text

    def read_file(self, path):
        return self.files[path]

    def glob(self, pattern):
        return sorted(self.files)

    def free_bytes(self, path):
        return self.free.pop(0) if len(self.free) > 1 else self.free[0]

    def is_dir(self, path):
        return path in self.dirs

    def remove_files(self, top, older_than):
        return self.removed.get(top, (0, 0))

    def uptime_s(self):
        return self.uptime

    def own_addresses(self):
        return self.addresses

    def resolve(self, host):
        return ["192.168.1.10"] if host == "hub.lan" else []

    def later(self, delay, fn):
        self.later_calls.append((delay, fn))


@pytest.fixture
def env():
    system = FakeSystem()
    clock = Clock()
    f = Fixer(FixerConfig(), system=system, clock=clock, hub_host="hub.lan")
    return f, system, clock


def ok(reply):
    assert reply["ok"], reply
    return reply["detail"]


def refused(reply):
    assert not reply["ok"] and reply["detail"].startswith("refused"), reply
    return reply["detail"]


# ---- requests and limits --------------------------------------------------------------


def test_unknown_or_malformed_requests_are_refused(env):
    f, system, _ = env
    refused(f.handle({"action": "rm_rf", "params": {}}))
    refused(f.handle("reboot"))
    refused(f.handle({"action": "reboot", "params": []}))
    assert system.calls == []


def test_actions_switched_off_in_config(env):
    f, system, _ = env
    f.cfg.enabled = {"free_memory"}
    assert "switched off" in refused(f.handle({"action": "reboot", "params": {}}))


def test_cooldown_per_action_and_target(env):
    f, system, clock = env
    system.replies["systemctl show"] = (0, "loaded")
    system.replies["systemctl is-active"] = (0, "active")
    ok(f.handle({"action": "restart_service", "params": {"unit": "nginx"}}))
    assert "wait 60 s" in refused(f.handle({"action": "restart_service",
                                            "params": {"unit": "nginx"}}))
    ok(f.handle({"action": "restart_service", "params": {"unit": "apache2"}}))
    clock.now += 61
    ok(f.handle({"action": "restart_service", "params": {"unit": "nginx"}}))


def test_hourly_limit(env):
    f, _, clock = env
    for i in range(fx.HOURLY_LIMIT):
        ok(f.handle({"action": "block_ip", "params": {"ip": "203.0.113.%d" % (i + 1)}}))
    assert "last hour" in refused(f.handle({"action": "block_ip",
                                            "params": {"ip": "203.0.113.200"}}))
    ok(f.handle({"action": "unblock_ip", "params": {"ip": "203.0.113.1"}}))  # never limited
    clock.now += 3601
    ok(f.handle({"action": "block_ip", "params": {"ip": "203.0.113.200"}}))


def test_a_crashing_action_is_reported_not_raised(env):
    f, system, _ = env

    def boom():
        raise OSError("disk on fire")
    system.uptime_s = boom
    reply = f.handle({"action": "reboot", "params": {}})
    assert reply == {"ok": False, "detail": "failed: disk on fire"}


# ---- services -------------------------------------------------------------------------


def test_restart_service(env):
    f, system, _ = env
    system.replies["systemctl show"] = (0, "loaded")
    system.replies["systemctl is-active"] = (0, "active")
    assert ok(f.handle({"action": "restart_service", "params": {"unit": "nginx"}})) == \
        "restarted nginx.service; it is running"
    assert ["systemctl", "restart", "nginx.service"] in [c for c, _ in system.calls]


@pytest.mark.parametrize("unit", ["devmon-agent", "devmon-fixer.service", "dbus",
                                  "-H evil", "a;b", "x.socket", "", None, "getty@tty1"])
def test_restart_refuses_protected_and_odd_units(env, unit):
    f, system, _ = env
    f.cfg.protected_units.add("getty")
    refused(f.handle({"action": "restart_service", "params": {"unit": unit}}))
    assert not any(c[:2] == ["systemctl", "restart"] for c, _ in system.calls)


def test_restart_unknown_unit_and_failure(env):
    f, system, clock = env
    system.replies["systemctl show"] = (0, "not-found")
    assert "not a service" in refused(f.handle({"action": "restart_service",
                                                "params": {"unit": "nope"}}))
    system.replies["systemctl show"] = (0, "loaded")
    system.replies["systemctl is-active"] = (3, "failed")
    reply = f.handle({"action": "restart_service", "params": {"unit": "web"}})
    assert reply == {"ok": False, "detail": "failed: restarted web.service, but it is failed"}


# ---- processes ------------------------------------------------------------------------


def test_stop_process_picks_the_busiest_unprotected(env):
    f, system, _ = env
    system.procs = [proc(1, "systemd", cpu=99, uid=0), proc(400, "sshd", cpu=95),
                    proc(500, "python3", cpu=90, cmdline="python3 -m devmon.agent"),
                    proc(600, "kworker/0:1", cpu=99, kernel=True),
                    proc(700, "stress", cpu=88), proc(800, "vim", cpu=3),
                    proc(900, "rootjob", cpu=97, uid=0)]
    detail = ok(f.handle({"action": "stop_process", "params": {"by": "cpu"}}))
    assert system.stopped == [700]
    assert detail == "stopped stress (pid 700, user pi, 88% CPU)"


def test_stop_process_root_only_when_allowed(env):
    f, system, clock = env
    f.cfg.stop_root_processes = True
    system.procs = [proc(900, "rootjob", mem=40, uid=0), proc(700, "stress", mem=10)]
    ok(f.handle({"action": "stop_process", "params": {"by": "mem"}}))
    assert system.stopped == [900]


def test_stop_process_nothing_worth_stopping(env):
    f, system, _ = env
    system.procs = [proc(800, "vim", cpu=3)]
    assert "no unprotected process" in refused(f.handle({"action": "stop_process",
                                                         "params": {"by": "cpu"}}))
    refused(f.handle({"action": "stop_process", "params": {"by": "disk"}}))


# ---- memory, disk, temperature --------------------------------------------------------


def test_free_memory(env):
    f, system, _ = env
    detail = ok(f.handle({"action": "free_memory", "params": {}}))
    assert system.written == {"/proc/sys/vm/drop_caches": "3"}
    assert detail.endswith("100 MB -> 400 MB")


def test_disk_cleanup(env):
    f, system, _ = env
    system.removed = {"/tmp": (2, 10), "/var/tmp/devmon-scratch": (1, 4000)}
    detail = ok(f.handle({"action": "disk_cleanup", "params": {"mount": "/"}}))
    assert detail.startswith("freed 3.9 KB on /")
    assert "2 temporary files over a week old" in detail
    assert "1 file in /var/tmp/devmon-scratch" in detail
    refused(f.handle({"action": "disk_cleanup", "params": {"mount": "relative"}}))


def test_cool_down_sets_powersave_and_restores(env):
    f, system, clock = env
    gov = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    system.files = {gov: "ondemand"}
    system.procs = [proc(700, "stress", cpu=80)]
    detail = ok(f.handle({"action": "cool_down", "params": {}}))
    assert system.written[gov] == "powersave" and system.reniced == [(700, 19)]
    assert "powersave for 15 minutes" in detail
    delay, restore = system.later_calls[0]
    assert delay == fx.COOL_DOWN_S
    restore()
    assert system.written[gov] == "ondemand"


# ---- blocking -------------------------------------------------------------------------


def test_block_creates_table_once_and_adds_with_timeout(env):
    f, system, _ = env
    system.replies["nft list table"] = (1, "No such file or directory")
    detail = ok(f.handle({"action": "block_ip", "params": {"ip": "203.0.113.9",
                                                           "seconds": 3600}}))
    assert detail == "blocked 203.0.113.9 for 1 hour"
    cmds = [c for c, _ in system.calls]
    assert ["nft", "-f", "-"] in cmds
    script = [s for c, s in system.calls if c == ["nft", "-f", "-"]][0]
    assert "flags timeout" in script and "ip saddr @blocked4 drop" in script
    assert cmds[-1] == ["nft", "add", "element", "inet", "devmon", "blocked4",
                        "{ 203.0.113.9 timeout 3600s }"]
    ok(f.handle({"action": "block_ip", "params": {"ip": "2001:db8::1", "seconds": 5}}))
    assert system.calls[-1][0][5:] == ["blocked6", "{ 2001:db8::1 timeout 60s }"]


@pytest.mark.parametrize("ip,why", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("0.0.0.0", "loopback"),
    ("169.254.1.1", "link-local"), ("224.0.0.1", "multicast"),
    ("192.168.1.20", "own address"), ("192.168.1.10", "hub"), ("10.1.2.3", "never_block"),
    ("::ffff:192.168.1.10", "hub"), ("not-an-ip", "not an IP"), ("1.2.3.4; reboot", "not an IP"),
])
def test_block_refuses(env, ip, why):
    f, system, _ = env
    f.cfg.never_block = [ipaddress.ip_network("10.0.0.0/8")]
    assert why in refused(f.handle({"action": "block_ip", "params": {"ip": ip}}))
    assert not any(c[:2] == ["nft", "add"] for c, _ in system.calls)


def test_unblock(env):
    f, system, _ = env
    assert ok(f.handle({"action": "unblock_ip", "params": {"ip": "203.0.113.9"}})) == \
        "unblocked 203.0.113.9"
    system.replies["nft delete element"] = (1, "No such file")
    assert ok(f.handle({"action": "unblock_ip", "params": {"ip": "203.0.113.9"}})) == \
        "203.0.113.9 was not blocked"


def test_missing_nft_is_a_clear_failure(env):
    f, system, _ = env
    system.replies["nft"] = (127, "nft is not installed")
    reply = f.handle({"action": "block_ip", "params": {"ip": "203.0.113.9"}})
    assert reply == {"ok": False, "detail": "failed: nftables (nft) is not installed"}


# ---- reboot ---------------------------------------------------------------------------


def test_reboot_answers_first_and_not_soon_after_boot(env):
    f, system, clock = env
    assert ok(f.handle({"action": "reboot", "params": {}})) == "rebooting in 5 s"
    delay, go = system.later_calls[0]
    assert delay == 5 and system.calls == []
    go()
    assert system.calls[-1][0] == ["systemctl", "reboot"]
    clock.now += fx.REBOOT_COOLDOWN_S
    system.uptime = 120
    assert "started 120 s ago" in refused(f.handle({"action": "reboot", "params": {}}))


# ---- configuration --------------------------------------------------------------------


def test_config(tmp_path):
    assert load_config(str(tmp_path / "missing.ini")).enabled == set(fx.ACTIONS)
    path = tmp_path / "fixer.ini"
    path.write_text("﻿[fixer]\nenabled_actions = free_memory, disk_cleanup\n"
                    "protected_processes = myjob\nprotected_units = web.service\n"
                    "never_block = 10.0.0.0/8 192.168.1.5\ncleanup_dirs = /srv/scratch\n"
                    "stop_root_processes = yes\n", encoding="utf-8")
    cfg = load_config(str(path))
    assert cfg.enabled == {"free_memory", "disk_cleanup"}
    assert "myjob" in cfg.protected_processes and "sshd" in cfg.protected_processes
    assert "web" in cfg.protected_units and "devmon-agent" in cfg.protected_units
    assert [str(n) for n in cfg.never_block] == ["10.0.0.0/8", "192.168.1.5/32"]
    assert cfg.cleanup_dirs == ["/srv/scratch"] and cfg.stop_root_processes


@pytest.mark.parametrize("line", ["enabled_actions = reboot, format_disk",
                                  "never_block = everyone", "cleanup_dirs = /etc",
                                  "cleanup_dirs = relative/dir", "stop_root_processes = maybe"])
def test_bad_config_stops_with_a_message(tmp_path, line):
    path = tmp_path / "fixer.ini"
    path.write_text("[fixer]\n" + line + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(path))


def test_hub_host_read_from_agent_ini(tmp_path):
    ini = tmp_path / "agent.ini"
    ini.write_text("[hub]\nhost = 192.168.1.10\nport = 55555\n", encoding="utf-8")
    assert fx._hub_host(str(ini)) == "192.168.1.10"
    assert fx._hub_host(str(tmp_path / "none.ini")) is None


# ---- the real system pieces that are safe to run anywhere ----------------------------


@pytest.mark.skipif(not hasattr(os, "fwalk"), reason="os.fwalk is Unix-only")
def test_remove_files_never_follows_links(tmp_path):
    top = tmp_path / "scratch"
    (top / "sub").mkdir(parents=True)
    (top / "a").write_bytes(b"x" * 10)
    (top / "sub" / "b").write_bytes(b"y" * 5)
    outside = tmp_path / "keep"
    outside.mkdir()
    (outside / "important").write_text("keep me")
    os.symlink(str(outside), str(top / "link"))
    count, size = fx.System().remove_files(str(top), None)
    assert (count, size) == (2, 15)
    assert (outside / "important").exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Unix socket credentials")
def test_socket_round_trip(tmp_path, env):
    f, system, _ = env
    path = str(tmp_path / "fixer.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        fx.serve_one(f, conn, [os.getuid()])
        conn.close()
    t = threading.Thread(target=serve)
    t.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(path)
    client.sendall(json.dumps({"action": "free_memory", "params": {}}).encode() + b"\n")
    reply = json.loads(client.makefile().readline())
    t.join()
    assert reply["ok"]


def test_shipped_fixer_ini_allows_everything_with_the_defaults():
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "deploy" / "agent" / "fixer.example.ini"
    cfg = load_config(str(path))
    assert cfg.enabled == set(fx.ACTIONS) and cfg.never_block == []
    assert cfg.cleanup_dirs == ["/var/tmp/devmon-scratch"] and not cfg.stop_root_processes
