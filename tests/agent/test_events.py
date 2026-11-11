from __future__ import annotations

import calendar
import json
from pathlib import Path

import pytest

from devmon.agent.collectors import events as ev
from devmon.agent.config import AgentConfig, EventsConfig, MariaDBConfig
from devmon.shared.messages import validate

ATTACKER = "203.0.113.9"


def kinds(events):
    return [(e["kind"], e["source"], e["ip"], e["user"], e["port"]) for e in events]


def feed(parser, text):
    out = []
    for line in text.strip().splitlines():
        out.extend(parser.feed(line.strip(), 5.0))
    return out


# ---- SSH ----------------------------------------------------------------------------

PASSWORD_SERVER = """
Invalid user admin from 203.0.113.9 port 50000
Failed password for invalid user admin from 203.0.113.9 port 50000 ssh2
Failed password for invalid user admin from 203.0.113.9 port 50000 ssh2
Connection closed by invalid user admin 203.0.113.9 port 50000 [preauth]
Failed password for root from 203.0.113.9 port 50002 ssh2
PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root
Disconnected from authenticating user root 203.0.113.9 port 50002 [preauth]
"""

KEY_ONLY_SERVER = """
Invalid user oracle from 198.51.100.7 port 41000
Connection closed by invalid user oracle 198.51.100.7 port 41000 [preauth]
Connection closed by authenticating user root 198.51.100.7 port 41002 [preauth]
Disconnected from authenticating user root 198.51.100.7 port 41002 [preauth]
Connection closed by 192.0.2.1 port 40000 [preauth]
Did not receive identification string from 192.0.2.1 port 40002
"""


def test_ssh_password_server_counts_each_try_once():
    got = feed(ev.SshParser(), PASSWORD_SERVER)
    assert kinds(got) == [("auth_fail", "ssh", ATTACKER, "admin", None)] * 2 + [
        ("auth_fail", "ssh", ATTACKER, "root", None)]
    assert all(e["ts"] == 5.0 and e["count"] == 1 for e in got)


def test_ssh_key_only_server_counts_closed_connections():
    # The last two lines are a bare TCP connect, like the hub's own SSH endpoint check.
    got = feed(ev.SshParser(), KEY_ONLY_SERVER)
    assert kinds(got) == [("auth_fail", "ssh", "198.51.100.7", "oracle", None),
                          ("auth_fail", "ssh", "198.51.100.7", "root", None)]


def test_ssh_success_and_ipv4_mapped_addresses():
    got = feed(ev.SshParser(), """
        Accepted publickey for pi from 192.168.1.20 port 51000 ssh2: ED25519 SHA256:abc
        Failed password for root from ::ffff:203.0.113.9 port 1 ssh2
        Failed password for root from 2001:db8::5 port 2 ssh2
    """)
    assert kinds(got) == [("auth_ok", "ssh", "192.168.1.20", "pi", None),
                          ("auth_fail", "ssh", ATTACKER, "root", None),
                          ("auth_fail", "ssh", "2001:db8::5", "root", None)]


def test_hostile_usernames_are_cleaned():
    long = "x" * 300
    got = feed(ev.SshParser(), "Failed password for invalid user %s from 203.0.113.9 port 1 ssh2\n"
                               "Failed password for invalid user a\x1b[31mb from 203.0.113.9 port 2 ssh2"
               % long)
    assert [e["user"] for e in got] == ["x" * ev.MAX_USER, "a[31mb"]


# ---- MariaDB and firewalls ------------------------------------------------------------

def test_mariadb_access_denied():
    line = ("2024-11-04 10:00:00 31 [Warning] Access denied for user 'root'@'203.0.113.9' "
            "(using password: YES)")
    assert kinds(ev.parse_mariadb(line, 1.0)) == [("auth_fail", "mariadb", ATTACKER, "root", None)]
    local = "Access denied for user 'app'@'localhost' (using password: YES)"
    assert kinds(ev.parse_mariadb(local, 1.0)) == [
        ("auth_fail", "mariadb", "127.0.0.1", "app", None)]
    assert ev.parse_mariadb("Aborted connection 5 to db: 'x' user: 'y'", 1.0) == []


UFW = ("[UFW BLOCK] IN=eth0 OUT= MAC=dc:a6:32:00:00:00:00:11:22:33:44:55:08:00 SRC=203.0.113.9 "
       "DST=192.168.1.20 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID=0 PROTO=TCP SPT=40000 DPT=3389 "
       "WINDOW=1024 RES=0x00 SYN URGP=0")


@pytest.mark.parametrize("line,expected", [
    (UFW, [("fw_drop", "firewall", ATTACKER, None, 3389)]),
    ("Nov  4 10:00:00 pi kernel: [12345.678] " + UFW, [("fw_drop", "firewall", ATTACKER, None, 3389)]),
    ("filter_IN_public_REJECT: IN=eth0 OUT= MAC=00 SRC=203.0.113.9 DST=192.168.1.20 LEN=60 "
     "PROTO=TCP SPT=40000 DPT=23 WINDOW=64240", [("fw_drop", "firewall", ATTACKER, None, 23)]),
    (UFW.replace("UFW BLOCK", "UFW AUDIT"), []),
    (UFW.replace("UFW BLOCK", "UFW ALLOW"), []),
    ("[UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.5 DST=224.0.0.251 PROTO=UDP SPT=5353 DPT=5353", []),
    ("[UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.5 DST=255.255.255.255 PROTO=UDP SPT=68 DPT=67", []),
    ("[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=192.168.1.20 PROTO=ICMP TYPE=8 CODE=0", []),
    ("[UFW BLOCK] IN= OUT=eth0 SRC=192.168.1.20 DST=8.8.8.8 PROTO=UDP SPT=1 DPT=53", []),
    ("[UFW BLOCK] IN=eth0 OUT=eth1 SRC=203.0.113.9 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=22", []),
    ("usb 1-1: new high-speed USB device number 3", []),
])
def test_kernel_firewall_lines(line, expected):
    assert kinds(ev.parse_kernel_fw(line, 1.0)) == expected


@pytest.mark.parametrize("line,expected", [
    ("2024-11-04 10:00:00 DROP TCP 203.0.113.9 192.168.1.30 40000 445 52 S 123 0 64240 - - - RECEIVE 4",
     [("fw_drop", "firewall", ATTACKER, None, 445)]),
    ("2024-11-04 10:00:00 ALLOW TCP 203.0.113.9 192.168.1.30 40000 445 52 S 1 0 64240 - - - RECEIVE", []),
    ("2024-11-04 10:00:00 DROP TCP 192.168.1.30 203.0.113.9 40000 445 52 S 1 0 64240 - - - SEND", []),
    ("2024-11-04 10:00:01 DROP UDP 192.168.1.5 239.255.255.250 50000 1900 0 - - - - - - - RECEIVE", []),
    ("2024-11-04 10:00:02 DROP ICMP 203.0.113.9 192.168.1.30 - - 0 - - - - 8 0 - RECEIVE", []),
    ("#Fields: date time action protocol src-ip dst-ip src-port dst-port size path", []),
])
def test_windows_firewall_lines(line, expected):
    assert kinds(ev.parse_windows_fw(line, 1.0)) == expected


# ---- Windows Security log -------------------------------------------------------------

def win_event(rid, eid, user, ip, logon_type="3", when="2024-11-04T10:00:05.1234567Z"):
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>%s</EventID>"
            "<TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID></System>"
            "<EventData><Data Name='TargetUserName'>%s</Data><Data Name='LogonType'>%s</Data>"
            "<Data Name='IpAddress'>%s</Data><Data Name='IpPort'>0</Data></EventData></Event>"
            % (eid, when, rid, user, logon_type, ip))


def test_windows_events():
    xml = "\r\n".join([
        win_event(101, 4625, "Administrator", ATTACKER),
        win_event(102, 4625, "bob", "-", logon_type="2"),          # at the console
        win_event(103, 4624, "Administrator", ATTACKER),           # network logon
        win_event(104, 4624, "SYSTEM", "-", logon_type="5"),       # a service
        win_event(105, 4624, "bob", "127.0.0.1", logon_type="10"),  # RDP to itself
        win_event(106, 4624, "bob", "192.168.1.9", logon_type="10"),
        win_event(107, 4625, "&lt;x&gt;", ATTACKER, when="garbage"),
    ])
    got, top = ev.parse_windows_events(xml, 999.0)
    assert top == 107
    assert kinds(got) == [("auth_fail", "windows", ATTACKER, "Administrator", None),
                          ("auth_fail", "windows", None, "bob", None),
                          ("auth_ok", "windows", ATTACKER, "Administrator", None),
                          ("auth_ok", "windows", "192.168.1.9", "bob", None),
                          ("auth_fail", "windows", ATTACKER, "<x>", None)]
    assert got[0]["ts"] == calendar.timegm((2024, 11, 4, 10, 0, 5, 0, 0, 0))
    assert got[-1]["ts"] == 999.0
    assert ev.parse_windows_events("", 1.0) == ([], None)
    with pytest.raises(ValueError):
        ev.parse_windows_events("<Event", 1.0)


class FakeRun:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.cmds = []

    def __call__(self, cmd, timeout):
        self.cmds.append(cmd)
        return self.answers.pop(0)


def test_windows_source_starts_at_newest_record():
    run = FakeRun((0, win_event(100, 4625, "old", ATTACKER), ""),
                  (0, win_event(101, 4625, "Administrator", ATTACKER) +
                   win_event(103, 4625, "Administrator", ATTACKER), ""),
                  (0, "", ""))
    src = ev.WindowsEventSource(run)
    assert src.poll(1.0) == [] and src.last == 100 and src.status["ok"]
    assert "/rd:true" in run.cmds[0]
    assert len(src.poll(2.0)) == 2 and src.last == 103
    assert any("EventRecordID>100" in part for part in run.cmds[1])
    assert src.poll(3.0) == [] and src.last == 103
    assert any("EventRecordID>103" in part for part in run.cmds[2])


def test_windows_source_access_denied():
    src = ev.WindowsEventSource(FakeRun((5, "", "Failed to read events. Access is denied.")))
    assert src.poll(1.0) == []
    assert not src.status["ok"] and "Event Log Readers" in src.status["detail"]


# ---- journald -------------------------------------------------------------------------

def jline(ts, message, cursor, ident=None, transport="syslog"):
    entry = {"__CURSOR": cursor, "__REALTIME_TIMESTAMP": str(int(ts * 1e6)),
             "MESSAGE": message, "_TRANSPORT": transport}
    if ident:
        entry["SYSLOG_IDENTIFIER"] = ident
    return json.dumps(entry)


def test_journal_source():
    first = jline(900, "Failed password for root from 203.0.113.9 port 1 ssh2", "c1", "sshd")
    later = "\n".join([
        jline(1001, "Failed password for root from 203.0.113.9 port 2 ssh2", "c2", "sshd-session"),
        jline(1002, UFW, "c3", transport="kernel"),
        jline(1003, "Access denied for user 'root'@'203.0.113.9' (using password: YES)", "c4",
              "mariadbd"),
        json.dumps({"__CURSOR": "c5", "__REALTIME_TIMESTAMP": "1004000000",
                    "MESSAGE": [104, 105], "SYSLOG_IDENTIFIER": "sshd"}),
        "-- No entries --",
        "{not json",
    ])
    run = FakeRun((0, first, ""), (0, later, ""), (0, "", ""))
    src = ev.JournalSource(run, can_read=lambda: True, clock=lambda: 1000.0)
    assert src.poll(1000.0) == [] and src.cursor == "c1"  # history is never replayed
    assert ["-n", "1"] == run.cmds[0][5:7]
    got = src.poll(1010.0)
    assert "--after-cursor=c1" in run.cmds[1]
    assert "SYSLOG_IDENTIFIER=sshd-session" in run.cmds[1] and run.cmds[1][-2:] == [
        "+", "_TRANSPORT=kernel"]
    assert kinds(got) == [("auth_fail", "ssh", ATTACKER, "root", None),
                          ("fw_drop", "firewall", ATTACKER, None, 3389),
                          ("auth_fail", "mariadb", ATTACKER, "root", None)]
    assert [e["ts"] for e in got] == [1001.0, 1002.0, 1003.0]
    assert src.cursor == "c5" and src.status == {"ok": True, "detail": "reading the system journal"}
    src.poll(1020.0)
    assert "--after-cursor=c5" in run.cmds[2]


def test_journal_source_without_permission_or_failing():
    run = FakeRun()
    src = ev.JournalSource(run, can_read=lambda: False)
    assert src.poll(1.0) == [] and run.cmds == []
    assert not src.status["ok"] and "systemd-journal" in src.status["detail"]
    src = ev.JournalSource(FakeRun((1, "", "Failed to open journal\n")), can_read=lambda: True)
    src.poll(1.0)
    assert src.status == {"ok": False, "detail": "journalctl failed: Failed to open journal"}


# ---- file tailing ---------------------------------------------------------------------

FAIL = b"Failed password for root from 203.0.113.9 port %d ssh2\n"


def test_file_tail_starts_at_end_and_follows(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(FAIL % 1 * 3)
    tail = ev.FileTail("SSH log", str(path), ev.SshParser().feed)
    assert tail.poll(1.0) == [] and tail.status == {"ok": True, "detail": "reading %s" % path}
    with open(path, "ab") as f:
        f.write(FAIL % 2 + b"Failed password for root from 203.0.113.9 po")
    assert [e["ts"] for e in tail.poll(2.0)] == [2.0]   # the half line waits
    with open(path, "ab") as f:
        f.write(b"rt 3 ssh2\r\n")
    assert kinds(tail.poll(3.0)) == [("auth_fail", "ssh", ATTACKER, "root", None)]
    assert tail.poll(4.0) == []


def test_file_tail_rotation_and_missing(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(FAIL % 1 * 5)
    tail = ev.FileTail("SSH log", str(path), ev.SshParser().feed)
    tail.poll(1.0)
    path.write_bytes(FAIL % 9)  # rotated: a new, shorter file
    assert len(tail.poll(2.0)) == 1
    path.unlink()
    assert tail.poll(3.0) == []
    assert tail.status == {"ok": False, "detail": "%s does not exist" % path}
    missing = ev.FileTail("Firewall log", str(tmp_path / "nope.log"), ev.parse_kernel_fw)
    assert missing.poll(1.0) == [] and not missing.status["ok"]


def test_file_tail_reads_at_most_1_mib_per_poll(tmp_path, monkeypatch):
    monkeypatch.setattr(ev, "MAX_READ", 100)
    path = tmp_path / "auth.log"
    path.write_bytes(b"")
    tail = ev.FileTail("SSH log", str(path), ev.SshParser().feed)
    tail.poll(1.0)
    path.write_bytes(FAIL % 1 * 4)  # 4 lines of 53 bytes
    assert len(tail.poll(2.0)) == 1
    assert len(tail.poll(3.0)) == 2
    assert len(tail.poll(4.0)) == 1


# ---- DatabaseAdministration -----------------------------------------------------------

class FakeDb:
    def __init__(self, answers):
        self.answers = answers
        self.queries = []
        self.closed = 0

    def __call__(self, **kwargs):
        return self

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, args=None):
        self.queries.append((sql, args))
        if isinstance(self.answers, Exception):
            raise self.answers

    def fetchone(self):
        return self.answers.pop(0)[0]

    def fetchall(self):
        return self.answers.pop(0)

    def close(self):
        self.closed += 1


MARIADB = MariaDBConfig(user="monitor", password="pw")


def test_dbadmin_source():
    db = FakeDb([[{"id": 40}],
                 [{"id": 41, "username": "bob", "action_type": "LOGIN_FAIL"},
                  {"id": 42, "username": "bob", "action_type": "LOGIN_OK"},
                  {"id": 43, "username": "alice", "action_type": "MFA_FAIL"}]])
    src = ev.DbAdminSource(MARIADB, "dbadmin.audit_log", connect=db)
    assert src.poll(100.0) == [] and src.last == 40
    assert "FROM `dbadmin`.`audit_log`" in db.queries[0][0]
    assert src.poll(110.0) == []  # polled every 30 s only
    got = src.poll(130.0)
    assert kinds(got) == [("auth_fail", "dbadmin", None, "bob", None),
                          ("auth_fail", "dbadmin", None, "alice", None)]
    assert db.queries[1][1] == (40,) and src.last == 43 and db.closed == 2
    with pytest.raises(ValueError):
        ev.DbAdminSource(MARIADB, "x`; DROP TABLE y")


def test_dbadmin_source_failure_is_shown():
    src = ev.DbAdminSource(MARIADB, "dbadmin.audit_log", connect=FakeDb(RuntimeError("denied")))
    assert src.poll(1.0) == []
    assert src.status == {"ok": False, "detail": "can't read dbadmin.audit_log: denied"}


# ---- collection -----------------------------------------------------------------------

class StubSource(ev.Source):
    def __init__(self, name, batches):
        super().__init__()
        self.name = name
        self.batches = batches

    def poll(self, now):
        batch = self.batches.pop(0) if self.batches else []
        if isinstance(batch, Exception):
            raise batch
        self._ok("fine")
        return batch


def test_collector_compacts_and_sends_sources_when_changed():
    fail = ev.event(5.0, "auth_fail", "ssh", ATTACKER, "root")
    clock = [1000.0]
    ssh = StubSource("SSH", [[dict(fail), dict(fail, ts=4.0), ev.event(6.0, "auth_fail", "ssh",
                                                                     ATTACKER, "admin")]])
    broken = StubSource("Firewall", [RuntimeError("boom"), RuntimeError("boom")])
    c = ev.EventCollector([ssh, broken], clock=lambda: clock[0])
    msg = c.collect()
    assert [(e["user"], e["count"], e["ts"]) for e in msg["events"]] == [("root", 2, 4.0),
                                                                        ("admin", 1, 6.0)]
    assert msg["sources"] == {"SSH": {"ok": True, "detail": "fine"},
                              "Firewall": {"ok": False, "detail": "boom"}}
    validate(dict(msg, ts=1.0))
    assert c.collect() is None  # nothing new, sources unchanged
    clock[0] += ev.SOURCES_EVERY_S
    assert c.collect()["sources"]["SSH"]["ok"]  # hourly heartbeat


def test_collector_sources_change_is_sent_without_events():
    src = StubSource("SSH", [])
    c = ev.EventCollector([src], clock=lambda: 1.0)
    assert c.collect()["sources"] == {"SSH": {"ok": True, "detail": "fine"}}
    src.batches = [RuntimeError("gone")]
    assert c.collect() == {"type": "events", "events": [],
                           "sources": {"SSH": {"ok": False, "detail": "gone"}}}


def test_collector_caps_a_big_scan():
    scan = [ev.event(1.0, "fw_drop", "firewall", ATTACKER, None, p) for p in range(1, 2501)]
    c = ev.EventCollector([StubSource("FW", [scan + scan])], clock=lambda: 1.0)
    msg = c.collect()
    assert len(msg["events"]) == ev.MAX_ENTRIES and msg["truncated"] == 500
    assert all(e["count"] == 2 for e in msg["events"])
    validate(dict(msg, ts=1.0))


# ---- choosing sources -----------------------------------------------------------------

def cfg(**events):
    return AgentConfig(hub_host="h", hub_fingerprint="f", key_path=Path("k"),
                       events=EventsConfig(**events))


def names(sources):
    return [(s.name, getattr(s, "path", None)) for s in sources]


def test_build_sources_linux():
    got = ev.build_sources(cfg(), "Linux", which=lambda c: "/usr/bin/journalctl",
                           exists=lambda p: p == "/var/log/mysql/error.log")
    assert names(got) == [("System journal", None),
                          ("MariaDB error log", "/var/log/mysql/error.log")]
    got = ev.build_sources(cfg(mariadb_log="/srv/m.log"), "Linux", which=lambda c: None,
                           exists=lambda p: p in ("/var/log/secure", "/var/log/messages"))
    assert names(got) == [("SSH log", "/var/log/secure"), ("Firewall log", "/var/log/messages"),
                          ("MariaDB error log", "/srv/m.log")]
    got = ev.build_sources(cfg(), "Linux", which=lambda c: None, exists=lambda p: False)
    assert [s.status["ok"] for s in got] == [False, False]


def test_build_sources_windows_and_dbadmin():
    c = cfg(dbadmin_table="dbadmin.audit_log")
    assert len(ev.build_sources(c, "Windows")) == 2  # no [mariadb], so no audit log
    c.mariadb = MARIADB
    got = ev.build_sources(c, "Windows")
    assert names(got) == [("Windows Security log", None),
                          ("Windows Firewall log", ev.WINDOWS_FW_LOG),
                          ("DatabaseAdministration audit log", None)]
