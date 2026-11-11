from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from devmon.agent.config import load_config

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "agent" / "write_agent_ini.py"
FP = "FEE5-43BA-D38A-658D-0D56-775E-852F-0485"


def _write(ini, *extra):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--path", str(ini), "--hub", "10.0.0.5",
         "--fingerprint", FP, "--key-path", "/var/lib/devmon/agent.key", *extra],
        capture_output=True, text=True)


def test_new_file_loads(tmp_path):
    ini = tmp_path / "agent.ini"
    assert _write(ini, "--kind", "pi").returncode == 0
    cfg = load_config(ini)
    assert (cfg.hub_host, cfg.hub_port, cfg.hub_fingerprint) == ("10.0.0.5", 55555, FP)
    assert cfg.device_kind == "pi" and cfg.mariadb is None


def test_rerun_keeps_mariadb_section(tmp_path):
    ini = tmp_path / "agent.ini"
    _write(ini)
    with open(ini, "a", encoding="utf-8") as f:
        f.write("\n[mariadb]\nuser = mon\npassword = p%ss\n")
    assert _write(ini, "--port", "6000").returncode == 0
    cfg = load_config(ini)
    assert cfg.hub_port == 6000 and cfg.device_kind is None
    assert (cfg.mariadb.user, cfg.mariadb.password) == ("mon", "p%ss")


def test_bad_fingerprint_is_refused(tmp_path):
    ini = tmp_path / "agent.ini"
    r = subprocess.run([sys.executable, str(SCRIPT), "--path", str(ini), "--hub", "h",
                        "--fingerprint", "ABCD", "--key-path", "k"], capture_output=True, text=True)
    assert r.returncode == 2 and not ini.exists()
