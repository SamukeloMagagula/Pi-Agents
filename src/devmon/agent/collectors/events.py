"""Failed logins, successful remote logins and firewall drops, read from the device's logs.

Every source starts at the end of its log, so a restart never replays old history.
"""
from __future__ import annotations

import calendar
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

MAX_ENTRIES = 2000
MAX_USER = 64
MAX_DETAIL = 200
MAX_READ = 1 << 20
MAX_PARTIAL = 64 * 1024
SOURCES_EVERY_S = 3600
DBADMIN_EVERY_S = 30
WINDOWS_BATCH = 500
JOURNAL_IDS = ("sshd", "sshd-session", "mariadbd", "mysqld")
AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
FW_LOGS = ("/var/log/ufw.log", "/var/log/kern.log", "/var/log/messages")
MARIADB_LOGS = ("/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log")
WEB_LOGS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log",
            "/var/log/httpd/access_log")
WINDOWS_FW_LOG = r"C:\ProgramData\DevMon\fwlog\pfirewall.log"
JOURNAL_GROUPS = ("adm", "systemd-journal", "wheel")
DBADMIN_FAILS = ("LOGIN_FAIL", "LOGIN_LOCKOUT", "MFA_FAIL")

Event = Dict[str, Any]
Runner = Callable[[List[str], float], Tuple[int, str, str]]


def _run(cmd: List[str], timeout: float = 30) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, check=False)
    return (p.returncode, p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"))


def _short(text: Any) -> str:
    if isinstance(text, BaseException):
        text = str(text).strip() or type(text).__name__
    lines = str(text).strip().splitlines()
    return (lines[0] if lines else "")[:MAX_DETAIL]


def event(ts: float, kind: str, source: str, ip: Optional[str] = None,
          user: Optional[str] = None, port: Optional[int] = None) -> Event:
    return {"ts": ts, "kind": kind, "source": source, "ip": ip, "user": user,
            "port": port, "count": 1}


def clean_ip(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = text.strip().strip("[]").split("%", 1)[0]  # drop an IPv6 zone id
    if text == "localhost":
        return "127.0.0.1"
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_user(text: Optional[str]) -> Optional[str]:
    # Attackers choose these; keep them short and printable.
    if text is None:
        return None
    text = _CONTROL.sub("", text).strip()
    if not text or text == "-":
        return None
    return text[:MAX_USER]


def _unicast(text: Optional[str]) -> bool:
    ip = clean_ip(text)
    if ip is None:
        return False
    addr = ipaddress.ip_address(ip)
    return not (addr.is_multicast or ip == "255.255.255.255")


# ---- parsers ------------------------------------------------------------------------

_SSH_FAIL = re.compile(
    r"Failed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_CLOSED = re.compile(
    r"(?:Connection closed by|Disconnected from) (?:invalid|authenticating) user "
    r"(?P<user>.*?) ?(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) \[preauth\]")
_SSH_OK = re.compile(r"Accepted \S+ for (?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")


class SshParser:
    """One event per failed attempt.

    A password server logs `Failed password` for each try; a key-only server logs only
    `Connection closed by … [preauth]`. The closing line counts only for a connection
    that logged no failure, so neither kind of server is counted twice.
    """

    def __init__(self) -> None:
        self._failed: "OrderedDict[Tuple[Optional[str], str], None]" = OrderedDict()

    def _remember(self, conn: Tuple[Optional[str], str]) -> None:
        self._failed[conn] = None
        self._failed.move_to_end(conn)
        while len(self._failed) > 4096:
            self._failed.popitem(last=False)

    def feed(self, line: str, ts: float) -> List[Event]:
        m = _SSH_FAIL.search(line)
        if m:
            ip = clean_ip(m.group("ip"))
            self._remember((ip, m.group("port")))
            return [event(ts, "auth_fail", "ssh", ip, clean_user(m.group("user")))]
        m = _SSH_CLOSED.search(line)
        if m:
            ip = clean_ip(m.group("ip"))
            conn = (ip, m.group("port"))
            if conn in self._failed:
                return []
            self._remember(conn)  # "Disconnected from" can follow "Connection closed by"
            return [event(ts, "auth_fail", "ssh", ip, clean_user(m.group("user")))]
        m = _SSH_OK.search(line)
        if m:
            return [event(ts, "auth_ok", "ssh", clean_ip(m.group("ip")),
                          clean_user(m.group("user")))]
        return []


_MARIADB = re.compile(r"Access denied for user '(?P<user>[^']*)'@'(?P<host>[^']*)'")


def parse_mariadb(line: str, ts: float) -> List[Event]:
    m = _MARIADB.search(line)
    if not m:
        return []
    return [event(ts, "auth_fail", "mariadb", clean_ip(m.group("host")),
                  clean_user(m.group("user")))]


_KV = re.compile(r"\b(IN|OUT|SRC|DST|PROTO|DPT)=(\S*)")


def _port(text: Optional[str]) -> Optional[int]:
    if not text or not text.isdigit():
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def parse_kernel_fw(line: str, ts: float) -> List[Event]:
    """ufw (`[UFW BLOCK]`) and firewalld (`filter_IN_public_REJECT:`) log lines."""
    start = line.find("IN=")
    if start < 0 or "SRC=" not in line:
        return []
    if not any(w in line[:start].upper() for w in ("BLOCK", "DROP", "REJECT")):
        return []
    f = dict(_KV.findall(line[start:]))
    if not f.get("IN") or f.get("OUT"):
        return []  # outgoing or forwarded, not aimed at this device
    port = _port(f.get("DPT"))
    src = clean_ip(f.get("SRC"))
    if f.get("PROTO", "").upper() not in ("TCP", "UDP") or port is None or src is None \
            or not _unicast(f.get("DST")):
        return []
    return [event(ts, "fw_drop", "firewall", src, None, port)]


def parse_windows_fw(line: str, ts: float) -> List[Event]:
    # date time action protocol src-ip dst-ip src-port dst-port size ... path
    if line.startswith("#"):
        return []
    f = line.split()
    if len(f) < 9 or f[2] != "DROP" or "RECEIVE" not in f[8:] or f[3] not in ("TCP", "UDP"):
        return []
    port = _port(f[7])
    src = clean_ip(f[4])
    if port is None or src is None or not _unicast(f[5]):
        return []
    return [event(ts, "fw_drop", "firewall", src, None, port)]


_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_TIME = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)")


def _windows_ts(text: Optional[str], default: float) -> float:
    m = _SYSTEM_TIME.match(text or "")
    if not m:
        return default
    return float(calendar.timegm(tuple(int(g) for g in m.groups()) + (0, 0, 0)))


def parse_windows_events(text: str, now: float) -> Tuple[List[Event], Optional[int]]:
    """wevtutil /f:xml output for 4625 (failed logon) and 4624 (logon)."""
    try:
        root = ET.fromstring("<Events>%s</Events>" % text)
    except ET.ParseError as exc:
        raise ValueError("unreadable wevtutil output (%s)" % exc)
    events: List[Event] = []
    top: Optional[int] = None
    for ev in root.iter(_NS + "Event"):
        system = ev.find(_NS + "System")
        if system is None:
            continue
        rid = system.findtext(_NS + "EventRecordID") or ""
        if rid.isdigit():
            top = max(top or 0, int(rid))
        created = system.find(_NS + "TimeCreated")
        ts = _windows_ts(created.get("SystemTime") if created is not None else None, now)
        data = {d.get("Name"): d.text or "" for d in ev.iter(_NS + "Data")}
        ip = clean_ip(data.get("IpAddress"))
        user = clean_user(data.get("TargetUserName"))
        eid = system.findtext(_NS + "EventID")
        if eid == "4625":
            events.append(event(ts, "auth_fail", "windows", ip, user))
        elif eid == "4624":
            # Network (3) and Remote Desktop (10) logons from another machine only;
            # services and the console log on all the time.
            if data.get("LogonType") in ("3", "10") and ip is not None \
                    and not ipaddress.ip_address(ip).is_loopback:
                events.append(event(ts, "auth_ok", "windows", ip, user))
    return events, top


# ---- sources ------------------------------------------------------------------------


class Source:
    name = "source"

    def __init__(self) -> None:
        self.status: Dict[str, Any] = {"ok": False, "detail": "not read yet"}

    def _ok(self, detail: str) -> None:
        self.status = {"ok": True, "detail": _short(detail)}

    def _fail(self, detail: Any) -> None:
        self.status = {"ok": False, "detail": _short(detail)}

    def poll(self, now: float) -> List[Event]:
        raise NotImplementedError


class Missing(Source):
    """Shown on the dashboard so the owner can see why a kind of attack is not detected."""

    def __init__(self, name: str, detail: str) -> None:
        super().__init__()
        self.name = name
        self._fail(detail)

    def poll(self, now: float) -> List[Event]:
        return []


class FileTail(Source):
    def __init__(self, name: str, path: str, parse: Callable[[str, float], List[Event]]) -> None:
        super().__init__()
        self.name = name
        self.path = path
        self.parse = parse
        self.pos: Optional[int] = None
        self.ino: Optional[int] = None
        self.partial = b""

    def poll(self, now: float) -> List[Event]:
        try:
            st = os.stat(self.path)
            if self.pos is None:
                # Start at the end; check now that it can be read at all.
                with open(self.path, "rb"):
                    pass
                self.pos, self.ino = st.st_size, st.st_ino
                self._ok("reading %s" % self.path)
                return []
            if st.st_ino != self.ino or st.st_size < self.pos:
                self.pos, self.ino, self.partial = 0, st.st_ino, b""  # rotated
            if st.st_size == self.pos:
                self._ok("reading %s" % self.path)
                return []
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                data = f.read(MAX_READ)
        except FileNotFoundError:
            self._fail("%s does not exist" % self.path)
            return []
        except PermissionError:
            self._fail("no permission to read %s" % self.path)
            return []
        self.pos += len(data)
        lines = (self.partial + data).split(b"\n")
        self.partial = lines.pop()
        if len(self.partial) > MAX_PARTIAL:
            self.partial = b""  # a runaway line is not a log line we know
        out: List[Event] = []
        for raw in lines:
            out.extend(self.parse(raw.decode("utf-8", "replace").rstrip("\r"), now))
        self._ok("reading %s" % self.path)
        return out


def _in_journal_group() -> bool:
    if os.geteuid() == 0:
        return True
    import grp
    names = set()
    for gid in os.getgroups():
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return bool(names & set(JOURNAL_GROUPS))


class JournalSource(Source):
    name = "System journal"

    def __init__(self, run: Runner = _run, can_read: Callable[[], bool] = _in_journal_group,
                 clock: Callable[[], float] = time.time) -> None:
        super().__init__()
        self.run = run
        self.can_read = can_read
        self.cursor: Optional[str] = None
        self.started = clock()
        self.ssh = SshParser()

    def _cmd(self) -> List[str]:
        cmd = ["journalctl", "-o", "json", "--no-pager", "-q"]
        if self.cursor:
            cmd.append("--after-cursor=" + self.cursor)
        else:
            cmd += ["-n", "1"]  # only learn where the journal ends
        cmd += ["SYSLOG_IDENTIFIER=" + i for i in JOURNAL_IDS]
        return cmd + ["+", "_TRANSPORT=kernel"]

    def poll(self, now: float) -> List[Event]:
        if not self.can_read():
            self._fail("the agent can't read the system journal; re-run the installer "
                       "(it adds the devmon user to the adm and systemd-journal groups)")
            return []
        rc, out, err = self.run(self._cmd(), 30)
        if rc != 0:
            self._fail("journalctl failed: %s" % (_short(err) or "exit %d" % rc))
            return []
        events: List[Event] = []
        for line in out.splitlines():
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            cursor = entry.get("__CURSOR")
            if isinstance(cursor, str):
                self.cursor = cursor
            events.extend(self._entry(entry, now))
        self._ok("reading the system journal")
        return events

    def _entry(self, entry: Dict[str, Any], now: float) -> List[Event]:
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            return []  # binary messages arrive as a list of byte values
        try:
            ts = int(entry.get("__REALTIME_TIMESTAMP")) / 1e6
        except (TypeError, ValueError):
            ts = now
        if ts < self.started:
            return []  # the first call's entry, or older
        if entry.get("_TRANSPORT") == "kernel":
            return parse_kernel_fw(message, ts)
        ident = entry.get("SYSLOG_IDENTIFIER")
        if ident in ("mariadbd", "mysqld"):
            return parse_mariadb(message, ts)
        if ident in ("sshd", "sshd-session"):
            return self.ssh.feed(message, ts)
        return []


class WindowsEventSource(Source):
    name = "Windows Security log"

    def __init__(self, run: Runner = _run) -> None:
        super().__init__()
        self.run = run
        self.last: Optional[int] = None

    def poll(self, now: float) -> List[Event]:
        if self.last is None:
            cmd = ["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:xml"]
        else:
            cmd = ["wevtutil", "qe", "Security",
                   "/q:*[System[(EventID=4624 or EventID=4625) and EventRecordID>%d]]"
                   % self.last, "/c:%d" % WINDOWS_BATCH, "/f:xml"]
        rc, out, err = self.run(cmd, 30)
        if rc != 0:
            detail = _short(err) or "exit %d" % rc
            if "denied" in detail.lower():
                detail = ("the agent can't read the Security log; re-run the installer "
                          "(it adds LocalService to Event Log Readers)")
            self._fail(detail)
            return []
        events, top = parse_windows_events(out, now)
        if self.last is None:
            self.last = top or 0
            self._ok("reading the Security log")
            return []
        if top is not None:
            self.last = max(self.last, top)
        self._ok("reading the Security log")
        return events


_TABLE = re.compile(r"^[A-Za-z0-9_$]+\.[A-Za-z0-9_$]+$")


class DbAdminSource(Source):
    """DatabaseAdministration's audit log: failed sign-ins, by id. It records no client
    IP, so these feed only the per-username rule."""

    name = "DatabaseAdministration audit log"

    def __init__(self, cfg: Any, table: str, connect: Optional[Callable[..., Any]] = None) -> None:
        super().__init__()
        if not _TABLE.match(table):
            raise ValueError("dbadmin_audit_table must look like database.table")
        self.cfg = cfg
        self.db, self.table = table.split(".")
        self.connect = connect
        self.last: Optional[int] = None
        self.next_at = 0.0

    def poll(self, now: float) -> List[Event]:
        if now < self.next_at:
            return []
        self.next_at = now + DBADMIN_EVERY_S
        connect = self.connect
        if connect is None:
            import pymysql  # only on devices that use this
            connect = pymysql.connect
            cursorclass = pymysql.cursors.DictCursor
        else:
            cursorclass = None
        name = "`%s`.`%s`" % (self.db, self.table)
        try:
            kwargs = dict(host=self.cfg.host, port=self.cfg.port, user=self.cfg.user,
                          password=self.cfg.password, connect_timeout=10, read_timeout=10,
                          charset="utf8mb4")
            if cursorclass is not None:
                kwargs["cursorclass"] = cursorclass
            conn = connect(**kwargs)
            try:
                with conn.cursor() as cur:
                    if self.last is None:
                        cur.execute("SELECT COALESCE(MAX(id), 0) AS id FROM " + name)
                        self.last = int(cur.fetchone()["id"])
                        rows: List[Dict[str, Any]] = []
                    else:
                        cur.execute("SELECT id, username, action_type FROM " + name +
                                    " WHERE id > %s ORDER BY id LIMIT 1000", (self.last,))
                        rows = list(cur.fetchall())
            finally:
                conn.close()
        except Exception as exc:
            self._fail("can't read %s.%s: %s" % (self.db, self.table, _short(exc)))
            return []
        out = []
        for r in rows:
            self.last = max(self.last or 0, int(r["id"]))
            if r.get("action_type") in DBADMIN_FAILS:
                out.append(event(now, "auth_fail", "dbadmin", None,
                                 clean_user(str(r.get("username") or ""))))
        self._ok("reading %s.%s" % (self.db, self.table))
        return out


# ---- collection ---------------------------------------------------------------------


def compact(events: List[Event]) -> List[Event]:
    """Merge identical events: counts add up, the earliest time is kept."""
    merged: "OrderedDict[tuple, Event]" = OrderedDict()
    for e in events:
        key = (e["kind"], e["source"], e["ip"], e["user"], e["port"])
        if key in merged:
            m = merged[key]
            m["count"] += e["count"]
            m["ts"] = min(m["ts"], e["ts"])
            # For web attacks, keep the most confident probe's score and details.
            if e.get("score") is not None and (m.get("score") is None or e["score"] > m["score"]):
                for f in ("score", "path", "method", "rule"):
                    m[f] = e.get(f)
        else:
            merged[key] = dict(e)
    return list(merged.values())


class EventCollector:
    def __init__(self, sources: List[Source], clock: Callable[[], float] = time.time) -> None:
        self.sources = sources
        self.clock = clock
        self._sent: Optional[Dict[str, Any]] = None
        self._sent_at = 0.0

    def collect(self) -> Optional[Dict[str, Any]]:
        """An `events` message (without ts), or None when there is nothing to send."""
        now = self.clock()
        events: List[Event] = []
        status: Dict[str, Any] = {}
        for s in self.sources:
            try:
                events.extend(s.poll(now))
            except Exception as exc:
                log.warning("reading %s failed: %s", s.name, exc)
                s.status = {"ok": False, "detail": _short(exc)}
            status[s.name] = dict(s.status)
        merged = compact(events)
        msg: Dict[str, Any] = {"type": "events", "events": merged[:MAX_ENTRIES], "sources": None}
        if len(merged) > MAX_ENTRIES:
            msg["truncated"] = len(merged) - MAX_ENTRIES
        if status != self._sent or now - self._sent_at >= SOURCES_EVERY_S:
            msg["sources"] = status
            self._sent, self._sent_at = status, now
        if not merged and msg["sources"] is None:
            return None
        return msg


def _first(paths: Tuple[str, ...], exists: Callable[[str], bool]) -> Optional[str]:
    return next((p for p in paths if exists(p)), None)


def build_sources(cfg: Any, system: str, which: Callable[[str], Optional[str]] = shutil.which,
                  exists: Callable[[str], bool] = os.path.exists) -> List[Source]:
    ev = cfg.events
    sources: List[Source] = []
    if system == "Windows":
        sources.append(WindowsEventSource())
        sources.append(FileTail("Windows Firewall log", ev.firewall_log or WINDOWS_FW_LOG,
                                parse_windows_fw))
    else:
        if which("journalctl"):
            sources.append(JournalSource())
        else:
            auth = _first(AUTH_LOGS, exists)
            sources.append(FileTail("SSH log", auth, SshParser().feed) if auth else
                           Missing("SSH log", "no system journal or auth log found"))
            fw = _first(FW_LOGS, exists)
            sources.append(FileTail("Firewall log", fw, parse_kernel_fw) if fw else
                           Missing("Firewall log", "no kernel log found"))
        mlog = ev.mariadb_log or _first(MARIADB_LOGS, exists)
        if mlog:
            sources.append(FileTail("MariaDB error log", mlog, parse_mariadb))
    wlog = ev.web_log or (None if system == "Windows" else _first(WEB_LOGS, exists))
    if wlog:
        from devmon.agent.collectors import weblog
        sources.append(FileTail("Web access log", wlog, weblog.parse_access))
    if cfg.mariadb is not None and ev.dbadmin_table:
        sources.append(DbAdminSource(cfg.mariadb, ev.dbadmin_table))
    return sources
