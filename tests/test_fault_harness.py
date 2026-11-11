from __future__ import annotations

import argparse
import csv
import importlib.util
import socket
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "tools" / "fault-inject.py"
spec = importlib.util.spec_from_file_location("inject", PATH)
inject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject)


def test_wait_until():
    t = {"now": 0.0}

    def clock():
        return t["now"]

    def sleep(d):
        t["now"] += d
    assert inject.wait_until(lambda: t["now"] >= 3, 10, sleep, clock) == 3.0
    t["now"] = 0.0
    assert inject.wait_until(lambda: False, 2, sleep, clock) is None


def test_record_and_summary(tmp_path, capsys):
    path = str(tmp_path / "faults.csv")
    args = argparse.Namespace(csv=path, timeout=900)
    for i, heal in enumerate([20.0, 40.0, 90.0, None]):
        inject.record(args, i + 1, "disk", "/var/tmp", 1000.0, None if heal is None
                      else 1000.0 + heal)
    inject.record(args, 1, "cpu", "pi-1", 1000.0, 1010.0)
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    assert [r["healed"] for r in rows] == ["yes", "yes", "yes", "no", "yes"]
    assert rows[0]["heal_s"] == "20.0" and rows[3]["heal_s"] == ""
    summary = dict(inject.summarize(rows))
    assert summary["disk"]["success"] == 75.0 and summary["disk"]["median"] == 40.0
    assert summary["disk"]["mean"] == pytest.approx(50.0) and summary["disk"]["under_60"] == 2
    inject.show_summary(argparse.Namespace(csv=path))
    out = capsys.readouterr().out
    assert "ALL" in out and "not supported" in out    # 80% success


def test_parse_ports():
    assert inject.parse_ports("10-12,20") == [10, 11, 12, 20]
    with pytest.raises(argparse.ArgumentTypeError):
        inject.parse_ports("0-2")


def test_blocked_tells_refused_from_dropped():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    assert not inject.blocked("127.0.0.1", port)     # answering
    server.close()
    assert not inject.blocked("127.0.0.1", port)     # refused: still answering


def test_hog_code_never_mentions_devmon():
    # The fixer never stops anything whose command line mentions devmon.
    assert "devmon" not in inject.CPU_HOG and "devmon" not in inject.MEM_HOG
