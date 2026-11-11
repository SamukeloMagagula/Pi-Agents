from __future__ import annotations

import configparser
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from devmon.shared.messages import DEVICE_KINDS


@dataclass
class MariaDBConfig:
    user: str
    password: str
    host: str = "127.0.0.1"
    port: int = 3306
    instance: str = ""
    exclude_schemas: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.instance:
            self.instance = "%s:%d" % (self.host, self.port)


@dataclass
class EventsConfig:
    """[events]: attack detection. Paths left empty use the OS's usual logs."""
    enabled: bool = True
    mariadb_log: Optional[str] = None
    # DatabaseAdministration's audit table, as database.table (read with [mariadb]'s account).
    dbadmin_table: Optional[str] = None
    firewall_log: Optional[str] = None  # Windows; default C:\ProgramData\DevMon\fwlog\pfirewall.log
    web_log: Optional[str] = None       # web server access log; empty tries the common paths


_TABLE = re.compile(r"^[A-Za-z0-9_$]+\.[A-Za-z0-9_$]+$")


@dataclass
class AgentConfig:
    hub_host: str
    hub_fingerprint: str
    key_path: Path
    hub_port: int = 55555
    device_kind: Optional[str] = None
    mariadb: Optional[MariaDBConfig] = None
    # Where the security helper writes its results; None means the OS default.
    helper_file: Optional[str] = None
    events: EventsConfig = field(default_factory=EventsConfig)
    # Self-healing (Linux): the fixer's socket (None: no fixer) and gossip between agents.
    fixer_socket: Optional[str] = None
    gossip_enabled: bool = False
    gossip_port: int = 55556

    @property
    def state_dir(self) -> Path:
        """Where the agent keeps its own files: next to its key."""
        return self.key_path.parent


def _required(parser: configparser.ConfigParser, section: str, key: str) -> str:
    value = parser.get(section, key, fallback="").strip()
    if not value:
        raise ValueError("%s.%s is missing from the config" % (section, key))
    return value


def load_config(path: Path) -> AgentConfig:
    # No interpolation: a "%" in a password must be read literally.
    parser = configparser.ConfigParser(interpolation=None)
    # utf-8-sig: a file saved by Notepad starts with a BOM.
    try:
        found = parser.read(str(path), encoding="utf-8-sig")
    except (configparser.Error, UnicodeDecodeError) as exc:
        raise ValueError("cannot read config file %s: %s" % (
            path, str(exc).splitlines()[0][:200]))
    if not found:
        raise ValueError("cannot read config file: %s" % path)

    host = _required(parser, "hub", "host")
    # Only presence is checked here; the format is validated where it is used.
    fingerprint = _required(parser, "hub", "fingerprint")
    key_path = Path(_required(parser, "agent", "key_path"))
    port = parser.getint("hub", "port", fallback=55555)

    kind = parser.get("agent", "device_kind", fallback="").strip() or None
    if kind is not None and kind not in DEVICE_KINDS:
        raise ValueError("agent.device_kind must be one of " + ", ".join(DEVICE_KINDS))

    mariadb = None
    if parser.has_section("mariadb"):
        excluded = parser.get("mariadb", "exclude_schemas", fallback="")
        mariadb = MariaDBConfig(
            user=_required(parser, "mariadb", "user"),
            password=parser.get("mariadb", "password", fallback=""),
            host=parser.get("mariadb", "host", fallback="127.0.0.1").strip(),
            port=parser.getint("mariadb", "port", fallback=3306),
            instance=parser.get("mariadb", "instance", fallback="").strip(),
            exclude_schemas=tuple(s.strip() for s in excluded.split(",") if s.strip()),
        )

    def opt(key: str) -> Optional[str]:
        return parser.get("events", key, fallback="").strip() or None

    events = EventsConfig(
        enabled=parser.getboolean("events", "enabled", fallback=True),
        mariadb_log=opt("mariadb_log"),
        dbadmin_table=opt("dbadmin_audit_table"),
        firewall_log=opt("firewall_log"),
        web_log=opt("web_log"),
    )
    if events.dbadmin_table is not None and not _TABLE.match(events.dbadmin_table):
        raise ValueError("events.dbadmin_audit_table must look like database.table")

    linux = platform.system() == "Linux"
    fixer_socket = parser.get("healing", "fixer_socket",
                              fallback="/run/devmon-fixer/fixer.sock" if linux else "").strip()
    gossip_port = parser.getint("gossip", "port", fallback=55556)
    if not 1 <= gossip_port <= 65535:
        raise ValueError("gossip.port must be 1-65535")

    return AgentConfig(
        hub_host=host,
        hub_fingerprint=fingerprint,
        key_path=key_path,
        hub_port=port,
        device_kind=kind,
        mariadb=mariadb,
        helper_file=parser.get("agent", "helper_file", fallback="").strip() or None,
        events=events,
        fixer_socket=fixer_socket or None,
        gossip_enabled=parser.getboolean("gossip", "enabled", fallback=linux),
        gossip_port=gossip_port,
    )
