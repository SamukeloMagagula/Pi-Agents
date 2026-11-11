from __future__ import annotations

import json
import os

import pytest

from devmon.agent import helper as h

SSHD_T = """port 22
permitrootlogin without-password
passwordauthentication yes
kbdinteractiveauthentication no
usepam yes
"""

NFT_EMPTY = "table inet filter {\n}\n"
NFT_ACCEPT_ONLY = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy drop;
\t}
}
"""
NFT_RULES = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t}
}
"""
NFT_DROP = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t}
}
"""


class FakeRun:
    """Answers commands by their first words; a missing entry means 'not installed'."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        key = " ".join(cmd[:2]) if cmd[0] != "powershell" else cmd[-1]
        for k, v in self.answers.items():
            if key.startswith(k) or k in key:
                if isinstance(v, Exception):
                    raise v
                return v
        raise h.NotInstalled(cmd[0])


# ---- Linux ---------------------------------------------------------------------------


def test_sshd_t_parsing():
    assert h.parse_sshd_t(SSHD_T) == {"permit_root_login": "without-password",
                                       "password_authentication": True}
    keys_only = "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\n"
    assert h.parse_sshd_t(keys_only) == {"permit_root_login": "yes",
                                         "password_authentication": False}
    # Keyboard-interactive through PAM is a password login too.
    kbd = "passwordauthentication no\nkbdinteractiveauthentication yes\nusepam yes\n"
    assert h.parse_sshd_t(kbd)["password_authentication"] is True


@pytest.mark.parametrize("answers,active,name", [
    ({"ufw status": (0, "Status: active\n\nTo Action From\n")}, True, "ufw"),
    ({"ufw status": (0, "Status: inactive\n"), "nft list": (0, NFT_EMPTY)}, False, "ufw"),
    ({"firewall-cmd --state": (0, "running\n")}, True, "firewalld"),
    ({"firewall-cmd --state": (252, "not running\n"), "nft list": (0, NFT_ACCEPT_ONLY)},
     False, "firewalld"),
    ({"nft list": (0, NFT_RULES)}, True, "nftables"),
    ({"nft list": (0, NFT_DROP)}, True, "nftables"),
    ({"nft list": (0, NFT_ACCEPT_ONLY)}, False, "nftables"),
    ({"iptables -S": (0, "-P INPUT DROP\n")}, True, "iptables"),
    ({"iptables -S": (0, "-P INPUT ACCEPT\n")}, False, "iptables"),
    ({}, False, "none"),
])
def test_firewall(answers, active, name):
    fw = h.check_firewall(FakeRun(answers))
    assert (fw["active"], fw["name"]) == (active, name)
    assert fw["detail"]


@pytest.mark.parametrize("name,answers,conf,expected", [
    ("ufw", {}, "ENABLED=yes\nLOGLEVEL=low\n", True),
    ("ufw", {}, 'ENABLED=yes\nLOGLEVEL="off"\n', False),
    ("ufw", {}, "ENABLED=yes\n", True),                     # ufw's default
    ("ufw", {}, PermissionError("denied"), None),
    ("firewalld", {"firewall-cmd --get-log-denied": (0, "unicast\n")}, "", True),
    ("firewalld", {"firewall-cmd --get-log-denied": (0, "off\n")}, "", False),
    ("firewalld", {"firewall-cmd --get-log-denied": (1, "")}, "", None),
    ("nftables", {}, "", None),
])
def test_firewall_logging(name, answers, conf, expected):
    def read_file(path):
        assert path == "/etc/ufw/ufw.conf"
        if isinstance(conf, Exception):
            raise conf
        return conf

    assert h.firewall_logging(name, FakeRun(answers), read_file) is expected


def test_windows_firewall_logging():
    on = [{"Name": n, "Enabled": True, "LogBlocked": "True"} for n in ("Domain", "Private")]
    assert h.parse_firewall_profiles(on)["logging"] is True
    on[1]["LogBlocked"] = "NotConfigured"
    assert h.parse_firewall_profiles(on)["logging"] is False
    assert h.parse_firewall_profiles([])["logging"] is None


def _fake_crypt(word, setting):
    # Pretend hash: "$x$salt$" + word reversed.
    salt = setting.split("$")[2]
    return "$x$%s$%s" % (salt, word[::-1])


SHADOW = "root:*:19000:0:99999:7:::\npi:{}:19000:0:99999:7:::\n"


@pytest.mark.parametrize("hashed,expected", [
    ("$x$abc$yrrebpsar", True),        # "raspberry"
    ("$x$abc$terces", False),          # another password
    ("!$x$abc$yrrebpsar", False),      # locked
    ("*", False), ("", False),
])
def test_default_password(hashed, expected):
    got = h.check_default_password(SHADOW.format(hashed), _fake_crypt)
    assert got == {"user": "pi", "default": expected}


def test_default_password_never_says_safe_when_it_cannot_check():
    assert h.check_default_password("root:*:1::::::\n", None) is None  # no pi user
    with pytest.raises(RuntimeError, match="libcrypt"):
        h.check_default_password(SHADOW.format("$y$j9T$abc$def"), None)
    with pytest.raises(RuntimeError, match="format"):
        h.check_default_password(SHADOW.format("$9$abc$def"), lambda w, s: "*0")


def test_linux_checks_collect_errors_instead_of_raising():
    def boom(path):
        raise PermissionError("Permission denied: '/etc/shadow'")

    run = FakeRun({"sshd -T": (255, "sshd: no hostkeys available -- exiting."),
                   "ufw status": RuntimeError("timed out")})
    result = h.run_checks("Linux", run=run, read_file=boom, crypt=None, now=5.0)
    assert result["version"] == 1 and result["ran_at"] == 5.0
    assert result["ssh"] is None and result["default_password"] is None
    assert set(result["errors"]) == {"ssh", "firewall", "default_password"}
    assert "Permission denied" in result["errors"]["default_password"]
    json.dumps(result)  # serialisable


def test_linux_checks_happy_path():
    run = FakeRun({"sshd -T": (0, SSHD_T), "ufw status": (0, "Status: active")})
    result = h.run_checks("Linux", run=run, read_file=lambda p: SHADOW.format("$x$s$terces"),
                          crypt=_fake_crypt, now=1.0)
    assert result["errors"] == {}
    assert result["ssh"]["password_authentication"] is True
    assert result["firewall"]["active"] is True
    assert result["firewall"]["logging"] is True  # no LOGLEVEL line: ufw's default
    assert result["default_password"] == {"user": "pi", "default": False}
    # Results only: no hash or file content anywhere in the output.
    assert "terces" not in json.dumps(result)


# ---- Windows -------------------------------------------------------------------------


DEFENDER_ON = {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
               "AntivirusSignatureAge": 1, "AMRunningMode": "Normal"}
AV_LIST = [{"displayName": "Windows Defender", "productState": 397568},
           {"displayName": "Other AV", "productState": 266240}]  # 0x41000: on


def _win(answers):
    return FakeRun({("Get-MpComputerStatus" if k == "def" else
                     "SecurityCenter2" if k == "av" else
                     "Get-NetFirewallProfile" if k == "fw" else
                     "Microsoft.Update.Session"): v for k, v in answers.items()})


def test_windows_checks():
    run = _win({"def": (0, json.dumps(DEFENDER_ON)), "av": (0, json.dumps(AV_LIST)),
                "fw": (0, json.dumps([{"Name": "Domain", "Enabled": 1},
                                      {"Name": "Private", "Enabled": True},
                                      {"Name": "Public", "Enabled": False}])),
                "upd": (0, json.dumps({"available": 3, "security": 1}))})
    result = h.run_checks("Windows", run=run, now=1000.0)
    assert result["errors"] == {}
    assert result["defender"] == {"enabled": True, "realtime": True, "signature_age_days": 1.0,
                                  "other_av": "Other AV"}
    assert result["firewall"] == {"active": False, "name": "windows", "logging": None,
                                  "detail": "Windows Firewall is off for the Public profile"}
    assert result["windows_update"] == {"available": 3, "security": 1, "checked_at": 1000.0}
    assert all(c[:3] == ["powershell", "-NoProfile", "-NonInteractive"] for c in run.calls)


def test_windows_update_is_searched_every_6_hours_only():
    previous = {"windows_update": {"available": 2, "security": 0, "checked_at": 1000.0}}
    run = _win({"def": (0, "{}"), "fw": (0, "[]"), "upd": (0, '{"available": 9, "security": 9}')})
    got = h.run_checks("Windows", run=run, previous=previous, now=1000.0 + 3600)
    assert got["windows_update"]["available"] == 2
    got = h.run_checks("Windows", run=run, previous=previous, now=1000.0 + 6 * 3600 + 1)
    assert got["windows_update"]["available"] == 9
    # A failed search keeps the last result; garbage history is ignored.
    run = _win({"def": (0, "{}"), "fw": (0, "[]"), "upd": (1, "COM error 0x8024402C")})
    got = h.run_checks("Windows", run=run, previous=previous, now=1e9)
    assert got["windows_update"]["available"] == 2 and "0x8024402C" in got["errors"]["windows_update"]
    got = h.run_checks("Windows", run=run, previous={"windows_update": {"checked_at": "x"}},
                       now=1e9)
    assert got["windows_update"] is None


def test_defender_signatures_never_updated():
    got = h.parse_defender(dict(DEFENDER_ON, AntivirusSignatureAge=65535), None)
    assert got["signature_age_days"] is None and got["other_av"] is None


def test_windows_server_without_security_center():
    run = _win({"def": (0, json.dumps(DEFENDER_ON)), "av": (1, "Invalid namespace"),
                "fw": (0, json.dumps({"Name": "Domain", "Enabled": True})),
                "upd": (0, '{"available": 0, "security": 0}')})
    got = h.run_checks("Windows", run=run, now=1.0)
    assert got["errors"] == {} and got["defender"]["other_av"] is None
    assert got["firewall"]["active"] is True


# ---- writing -------------------------------------------------------------------------


def test_write_status_is_atomic(tmp_path):
    out = tmp_path / "helper" / "status.json"
    h.write_status(str(out), {"a": 1})
    h.write_status(str(out), {"a": 2})
    assert json.loads(out.read_text()) == {"a": 2}
    assert not (tmp_path / "helper" / "status.json.tmp").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes")
def test_write_refuses_a_folder_others_can_write(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir()
    folder.chmod(0o777)
    with pytest.raises(h.UnsafeFolder):
        h.write_status(str(folder / "status.json"), {})


@pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
def test_write_refuses_a_symlinked_folder(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o755)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(h.UnsafeFolder):
        h.write_status(str(link / "status.json"), {})


def test_main_writes_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "run_checks", lambda previous=None: {"version": 1, "errors": {"x": "y"}})
    out = tmp_path / "s.json"
    assert h.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text())["version"] == 1
