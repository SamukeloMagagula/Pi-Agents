from __future__ import annotations

import json
from pathlib import Path

import pymysql

from devmon.agent.collectors.mariadb import collect_mariadb
from devmon.agent.config import MariaDBConfig
from devmon.shared.messages import validate

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mariadb"


def _fixture(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeCursor:
    """Replays recorded rows by matching the start of each SQL statement."""

    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, args=None):
        self.conn.executed.append((sql, args))
        for prefix, result in self.conn.answers:
            if sql.startswith(prefix):
                if isinstance(result, Exception):
                    raise result
                self.rows = result if isinstance(result, list) else [result]
                return
        raise AssertionError("unexpected SQL: " + sql)

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    def __init__(self, answers):
        self.answers = answers
        self.executed = []
        self.closed = False
        self.kwargs = None

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


def _answers(replica=None, slave=None):
    return [
        ("SHOW GLOBAL STATUS", _fixture("status.json")),
        ("SELECT @@max_connections", _fixture("extra.json")),
        ("SHOW FULL PROCESSLIST", _fixture("processlist.json")),
        ("SELECT table_schema", _fixture("sizes.json")),
        ("SHOW REPLICA STATUS", replica if replica is not None else _fixture("replica.json")),
        ("SHOW SLAVE STATUS", slave if slave is not None else []),
    ]


def _collect(answers, cfg=None):
    conn = FakeConn(answers)

    def connect(**kwargs):
        conn.kwargs = kwargs
        return conn

    cfg = cfg or MariaDBConfig(user="mon", password="pw", exclude_schemas=("scratch",))
    return collect_mariadb(cfg, connect=connect, clock=lambda: 1234.0), conn


def test_overview_from_recorded_rows():
    msg, conn = _collect(_answers())
    validate(msg)
    assert msg["error"] is None
    assert msg["instance"] == "127.0.0.1:3306" and msg["ts"] == 1234.0
    ov = msg["overview"]
    assert ov["threads_connected"] == 38
    assert ov["max_connections"] == 151
    assert ov["uptime_s"] == 86400 and ov["slow_queries"] == 7
    assert ov["version"].startswith("10.11.6")
    assert conn.closed
    assert conn.kwargs["connect_timeout"] == 5 and conn.kwargs["read_timeout"] == 10


def test_long_running_skips_sleep_and_server_threads():
    msg, _ = _collect(_answers())
    ids = [q["id"] for q in msg["long_running"]]
    assert ids == [15, 11]  # longest first; the 500 s Sleep and 9000 s Daemon are left out
    assert msg["long_running"][1]["time_s"] == 75
    assert msg["long_running"][1]["command"] == "Query"


def test_info_is_truncated():
    rows = [{"Id": 1, "User": "a", "Host": "h", "db": None, "Command": "Query",
             "Time": 61, "State": "", "Info": "x" * 2000}]
    answers = _answers()
    answers[2] = ("SHOW FULL PROCESSLIST", rows)
    msg, _ = _collect(answers)
    assert len(msg["long_running"][0]["info"]) == 500


def test_databases_exclude_system_and_configured_schemas():
    msg, conn = _collect(_answers())
    names = [d["name"] for d in msg["databases"]]
    assert names == ["shop", "wiki"]
    assert msg["databases"][0] == {"name": "shop", "tables": 12, "size_mb": 50.0,
                                   "approx_rows": 120000}
    assert msg["databases"][1]["approx_rows"] is None
    sizes_args = [a for sql, a in conn.executed if sql.startswith("SELECT table_schema")][0]
    assert "mysql" in sizes_args and "scratch" in sizes_args


def test_replication_stopped_io_thread():
    msg, _ = _collect(_answers())
    assert msg["replication"] == {"io_running": False, "sql_running": True,
                                  "seconds_behind": None}


def test_replica_syntax_error_falls_back_to_slave_status():
    slave = [{"Slave_IO_Running": "Yes", "Slave_SQL_Running": "Yes",
              "Seconds_Behind_Master": 12}]
    err = pymysql.err.ProgrammingError(1064, "You have an error in your SQL syntax")
    msg, _ = _collect(_answers(replica=err, slave=slave))
    assert msg["replication"] == {"io_running": True, "sql_running": True, "seconds_behind": 12}


def test_not_a_replica_gives_none():
    msg, _ = _collect(_answers(replica=[]))
    assert msg["replication"] is None


def test_access_denied_is_reported_not_raised():
    def connect(**kwargs):
        raise pymysql.err.OperationalError(1045, "Access denied for user 'mon'@'localhost'")

    msg = collect_mariadb(MariaDBConfig(user="mon", password="bad"), connect=connect)
    validate(msg)
    assert "Access denied" in msg["error"]
    assert msg["overview"] is None
    assert msg["long_running"] == [] and msg["databases"] == [] and msg["replication"] is None


def test_query_failure_midway_is_reported_and_connection_closed():
    answers = _answers()
    answers[2] = ("SHOW FULL PROCESSLIST", pymysql.err.OperationalError(2013, "Lost connection"))
    msg, conn = _collect(answers)
    assert "Lost connection" in msg["error"]
    assert msg["overview"] is None
    assert conn.closed
