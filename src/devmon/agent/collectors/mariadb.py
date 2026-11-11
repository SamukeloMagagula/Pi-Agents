"""MariaDB/MySQL metrics, ported from Database-Analyser/includes/metrics.php
(db_overview, db_processlist, db_sizes, db_replication_status)."""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

import pymysql
import pymysql.cursors

from devmon.agent.config import MariaDBConfig

CONNECT_TIMEOUT_S = 5
READ_TIMEOUT_S = 10
LONG_RUNNING_S = 60
INFO_MAX = 500
SYSTEM_SCHEMAS = ("mysql", "information_schema", "performance_schema", "sys")
STATUS_NAMES = ("Threads_connected", "Threads_running", "Uptime", "Questions",
                "Slow_queries", "Aborted_connects")
# Server-internal threads that sit in the processlist for hours by design; counting them
# as long-running queries would keep the database permanently red.
_IDLE_COMMANDS = {"Sleep", "Daemon", "Binlog Dump", "Binlog Dump GTID", "Slave_IO",
                  "Slave_SQL", "Slave_worker", "Killed"}
_SYSTEM_USERS = {"system user", "event_scheduler"}


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _overview(cur) -> Dict[str, Any]:
    placeholders = ",".join(["%s"] * len(STATUS_NAMES))
    cur.execute("SHOW GLOBAL STATUS WHERE Variable_name IN (%s)" % placeholders, STATUS_NAMES)
    status = {r["Variable_name"]: r["Value"] for r in cur.fetchall()}
    # One round trip: @@max_connections reads the variable directly (as in the PHP).
    cur.execute("SELECT @@max_connections AS max_connections, VERSION() AS version")
    extra = cur.fetchone() or {}
    return {
        "version": str(extra.get("version") or "unknown"),
        "uptime_s": _int(status.get("Uptime")) or 0,
        "threads_connected": _int(status.get("Threads_connected")) or 0,
        "threads_running": _int(status.get("Threads_running")) or 0,
        "max_connections": _int(extra.get("max_connections")),
        "questions": _int(status.get("Questions")) or 0,
        "slow_queries": _int(status.get("Slow_queries")) or 0,
        "aborted_connects": _int(status.get("Aborted_connects")) or 0,
    }


def _long_running(cur) -> List[Dict[str, Any]]:
    cur.execute("SHOW FULL PROCESSLIST")
    out = []
    for r in cur.fetchall():
        secs = _int(r.get("Time")) or 0
        if (secs < LONG_RUNNING_S or r.get("Command") in _IDLE_COMMANDS
                or r.get("User") in _SYSTEM_USERS):
            continue
        info = r.get("Info")
        out.append({
            "id": _int(r.get("Id")),
            "user": r.get("User"),
            "host": r.get("Host"),
            "db": r.get("db"),
            "command": r.get("Command"),
            "time_s": secs,
            "state": r.get("State"),
            "info": None if info is None else str(info)[:INFO_MAX],
        })
    out.sort(key=lambda q: q["time_s"], reverse=True)
    return out


def _databases(cur, exclude: tuple) -> List[Dict[str, Any]]:
    skip = SYSTEM_SCHEMAS + tuple(exclude)
    placeholders = ",".join(["%s"] * len(skip))
    cur.execute(
        "SELECT table_schema AS db_name, COUNT(*) AS table_count, "
        "SUM(data_length + index_length) AS size_bytes, SUM(table_rows) AS approx_rows "
        "FROM information_schema.TABLES WHERE table_schema NOT IN (%s) "
        "GROUP BY table_schema ORDER BY size_bytes DESC" % placeholders,
        skip,
    )
    return [
        {
            "name": r["db_name"],
            "tables": _int(r.get("table_count")) or 0,
            "size_mb": round((_int(r.get("size_bytes")) or 0) / 1048576, 2),
            "approx_rows": _int(r.get("approx_rows")),
        }
        for r in cur.fetchall()
        if r["db_name"] not in skip
    ]


def _yes(row: Dict[str, Any], *names: str) -> bool:
    for n in names:
        if n in row:
            return str(row[n]).lower() == "yes"
    return True


def _replication(cur) -> Optional[Dict[str, Any]]:
    # SHOW REPLICA STATUS is MariaDB 10.5.1+/MySQL 8.0.22+; older servers only know SLAVE.
    row = None
    for sql in ("SHOW REPLICA STATUS", "SHOW SLAVE STATUS"):
        try:
            cur.execute(sql)
            row = cur.fetchone()
            break
        except pymysql.MySQLError:
            continue
    if not row:
        return None
    behind = row.get("Seconds_Behind_Master", row.get("Seconds_Behind_Source"))
    return {
        "io_running": _yes(row, "Slave_IO_Running", "Replica_IO_Running"),
        "sql_running": _yes(row, "Slave_SQL_Running", "Replica_SQL_Running"),
        "seconds_behind": _int(behind),
    }


def collect_mariadb(cfg: MariaDBConfig, connect: Callable[..., Any] = pymysql.connect,
                    clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """A complete `db` message. Never raises: a failure becomes `error`, so the hub can
    show the database as unreachable instead of it silently disappearing."""
    msg: Dict[str, Any] = {
        "type": "db", "ts": clock(), "instance": cfg.instance, "error": None,
        "overview": None, "long_running": [], "databases": [], "replication": None,
    }
    conn = None
    try:
        # A fresh connection each time: a long-lived one would hide a server restart.
        conn = connect(host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password,
                       connect_timeout=CONNECT_TIMEOUT_S, read_timeout=READ_TIMEOUT_S,
                       write_timeout=READ_TIMEOUT_S, cursorclass=pymysql.cursors.DictCursor,
                       charset="utf8mb4")
        with conn.cursor() as cur:
            overview = _overview(cur)
            long_running = _long_running(cur)
            databases = _databases(cur, cfg.exclude_schemas)
            replication = _replication(cur)
        msg.update(overview=overview, long_running=long_running, databases=databases,
                   replication=replication)
    except Exception as exc:
        msg["error"] = (str(exc) or type(exc).__name__)[:500]
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return msg
