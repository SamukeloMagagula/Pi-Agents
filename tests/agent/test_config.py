from __future__ import annotations

from pathlib import Path

import pytest

from devmon.agent.config import load_config

EXAMPLE = Path(__file__).resolve().parents[2] / "deploy" / "agent" / "agent.example.ini"


def test_parses_example_ini():
    cfg = load_config(EXAMPLE)
    assert cfg.hub_host == "hub.example.lan"
    assert cfg.hub_port == 55555
    assert cfg.hub_fingerprint == "PASTE-HUB-FINGERPRINT-HERE"
    assert cfg.key_path == Path("/var/lib/devmon/agent.key")
    assert cfg.device_kind is None
    assert cfg.mariadb is None


def test_mariadb_section_parsed(tmp_path):
    ini = tmp_path / "a.ini"
    ini.write_text(
        "[hub]\nhost = h\nfingerprint = fp\n"
        "[agent]\nkey_path = k.key\ndevice_kind = pi\n"
        "[mariadb]\nuser = u\npassword = p\nexclude_schemas = a, b\n",
        encoding="utf-8",
    )
    cfg = load_config(ini)
    assert cfg.device_kind == "pi"
    assert cfg.mariadb.user == "u"
    assert cfg.mariadb.instance == "127.0.0.1:3306"
    assert cfg.mariadb.exclude_schemas == ("a", "b")


def test_missing_fingerprint_raises(tmp_path):
    ini = tmp_path / "a.ini"
    ini.write_text("[hub]\nhost = h\n[agent]\nkey_path = k.key\n", encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint"):
        load_config(ini)


def test_percent_in_password_is_literal(tmp_path):
    ini = tmp_path / "a.ini"
    ini.write_text(
        "[hub]\nhost = h\nfingerprint = fp\n"
        "[agent]\nkey_path = k.key\n"
        "[mariadb]\nuser = u\npassword = p%ss\n",
        encoding="utf-8",
    )
    assert load_config(ini).mariadb.password == "p%ss"


def test_helper_file_setting(tmp_path):
    ini = tmp_path / "a.ini"
    ini.write_text("[hub]\nhost = h\nfingerprint = fp\n[agent]\nkey_path = k.key\n",
                   encoding="utf-8")
    assert load_config(ini).helper_file is None
    ini.write_text("[hub]\nhost = h\nfingerprint = fp\n"
                   "[agent]\nkey_path = k.key\nhelper_file = /tmp/s.json\n", encoding="utf-8")
    assert load_config(ini).helper_file == "/tmp/s.json"


def test_events_section(tmp_path):
    base = "[hub]\nhost = h\nfingerprint = fp\n[agent]\nkey_path = k.key\n"
    ini = tmp_path / "a.ini"
    ini.write_text(base, encoding="utf-8")
    ev = load_config(ini).events
    assert ev.enabled and ev.mariadb_log is None and ev.dbadmin_table is None
    ini.write_text(base + "[events]\nenabled = no\nmariadb_log = /var/log/m.log\n"
                   "dbadmin_audit_table = dbadmin.audit_log\n", encoding="utf-8")
    ev = load_config(ini).events
    assert not ev.enabled and ev.mariadb_log == "/var/log/m.log"
    assert ev.dbadmin_table == "dbadmin.audit_log"
    ini.write_text(base + "[events]\ndbadmin_audit_table = x; DROP TABLE y\n", encoding="utf-8")
    with pytest.raises(ValueError, match="database.table"):
        load_config(ini)


def test_notepad_bom_is_accepted(tmp_path):
    ini = tmp_path / "a.ini"
    ini.write_bytes(b"\xef\xbb\xbf[hub]\nhost = h\nfingerprint = f\n[agent]\nkey_path = k.key\n")
    assert load_config(ini).hub_host == "h"


@pytest.mark.parametrize("body", [b"host = h\n", b"[hub]\n[hub]\n", b"[hub]\nhost = \xff\n"])
def test_unreadable_config_is_a_value_error(tmp_path, body):
    ini = tmp_path / "a.ini"
    ini.write_bytes(body)
    with pytest.raises(ValueError, match="cannot read config file"):
        load_config(ini)


def test_agent_cli_damaged_key_is_one_plain_line(tmp_path, capsys):
    from devmon.agent.__main__ import main
    key = tmp_path / "k.key"
    key.write_bytes(b"short")
    ini = tmp_path / "a.ini"
    ini.write_text("[hub]\nhost = h\nfingerprint = f\n[agent]\nkey_path = %s\n" % key.as_posix(),
                   encoding="utf-8")
    assert main(["--config", str(ini), "--show-fingerprint"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("devmon agent: ") and "damaged" in err


def test_healing_and_gossip_defaults_follow_the_os(tmp_path, monkeypatch):
    import platform
    ini = tmp_path / "a.ini"
    base = "[hub]\nhost = h\nfingerprint = fp\n[agent]\nkey_path = /var/lib/devmon/k.key\n"
    ini.write_text(base, encoding="utf-8")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    cfg = load_config(ini)
    assert cfg.fixer_socket == "/run/devmon-fixer/fixer.sock"
    assert cfg.gossip_enabled and cfg.gossip_port == 55556
    assert cfg.state_dir == Path("/var/lib/devmon")
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    cfg = load_config(ini)
    assert cfg.fixer_socket is None and not cfg.gossip_enabled
    ini.write_text(base + "[healing]\nfixer_socket =\n[gossip]\nenabled = no\nport = 6000\n",
                   encoding="utf-8")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    cfg = load_config(ini)
    assert cfg.fixer_socket is None and not cfg.gossip_enabled and cfg.gossip_port == 6000
    ini.write_text(base + "[gossip]\nport = 70000\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(ini)
