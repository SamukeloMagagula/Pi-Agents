from __future__ import annotations

from devmon.agent import helper


def test_classify_detects_remote_access_tools():
    procs = [
        {"pid": 1, "comm": "systemd", "exe": "/usr/lib/systemd/systemd"},
        {"pid": 2, "comm": "anydesk", "exe": "/usr/bin/anydesk"},
        {"pid": 3, "comm": "TeamViewer", "exe": "/opt/teamviewer/tv_bin/TeamViewer"},
    ]
    out = helper.classify_processes(procs)
    names = {p["name"] for p in out["remote_access"]}
    assert "anydesk" in names and "teamviewer" in names
    assert out["suspicious_processes"] == []


def test_classify_detects_tmp_and_deleted_binaries():
    procs = [
        {"pid": 10, "comm": "miner", "exe": "/tmp/xmrig"},
        {"pid": 11, "comm": "sh", "exe": "/dev/shm/payload"},
        {"pid": 12, "comm": "bash", "exe": "/usr/bin/bash (deleted)"},
        {"pid": 13, "comm": "nginx", "exe": "/usr/sbin/nginx"},
    ]
    out = helper.classify_processes(procs)
    pids = {p["pid"] for p in out["suspicious_processes"]}
    assert pids == {10, 11, 12}


def test_classify_caps_output():
    procs = [{"pid": i, "comm": "x", "exe": "/tmp/x%d" % i} for i in range(100)]
    assert len(helper.classify_processes(procs)["suspicious_processes"]) == helper.MAX_THREAT


def test_collect_persistence_hashes_watched_paths():
    files = {"/etc/crontab": "0 * * * * root backup",
             "/etc/cron.d/job": "* * * * * root x",
             "/root/.ssh/authorized_keys": "ssh-ed25519 AAAA key"}
    dirs = {"/etc/cron.d": ["job"], "/etc/cron.daily": [], "/etc/cron.hourly": [],
            "/etc/cron.weekly": [], "/etc/systemd/system": [], "/root/.ssh": ["authorized_keys"],
            "/home": []}

    def read_file(p):
        return files[p]  # raises KeyError? no - raise OSError for missing

    def rf(p):
        if p not in files:
            raise OSError("no such file")
        return files[p]

    def listdir(p):
        if p not in dirs:
            raise OSError("no dir")
        return dirs[p]

    items = helper.collect_persistence(rf, listdir)
    assert "/etc/crontab" in items and "/root/.ssh/authorized_keys" in items
    assert all(isinstance(h, str) and h for h in items.values())


def test_persistence_changes_first_run_is_baseline():
    assert helper.persistence_changes({"a": "1"}, None) == []
    assert helper.persistence_changes({"a": "1"}, {}) == []


def test_persistence_changes_detects_added_changed_removed():
    prev = {"/etc/crontab": "h1", "/root/.ssh/authorized_keys": "k1"}
    cur = {"/etc/crontab": "h1", "/root/.ssh/authorized_keys": "k2", "/etc/cron.d/new": "h9"}
    changes = {c["item"]: c["change"] for c in helper.persistence_changes(cur, prev)}
    assert changes == {"/root/.ssh/authorized_keys": "changed", "/etc/cron.d/new": "added"}
    gone = {c["item"]: c["change"] for c in helper.persistence_changes({"/etc/crontab": "h1"}, prev)}
    assert gone["/root/.ssh/authorized_keys"] == "removed"


def test_threat_checks_integrates_and_sets_baseline():
    errors = {}
    procs = [{"pid": 5, "comm": "anydesk", "exe": "/usr/bin/anydesk"}]
    files = {"/etc/crontab": "x"}

    def rf(p):
        if p not in files:
            raise OSError
        return files[p]

    out = helper.threat_checks(None, errors, list_processes=lambda: procs, read_file=rf,
                               listdir=lambda p: [] if p != "/home" else [])
    assert out["remote_access"][0]["name"] == "anydesk"
    assert out["persistence"] == []  # first run
    assert out["persistence_state"]["/etc/crontab"]
    # second run with a changed crontab reports the change
    files["/etc/crontab"] = "y"
    out2 = helper.threat_checks({"persistence_state": out["persistence_state"]}, errors,
                                list_processes=lambda: [], read_file=rf, listdir=lambda p: [])
    assert {"item": "/etc/crontab", "change": "changed"} in out2["persistence"]
    assert errors == {}
