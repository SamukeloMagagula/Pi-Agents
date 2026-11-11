from __future__ import annotations

import json

import pytest

from devmon.agent.collectors import security as sec
from devmon.shared.messages import InvalidMessage, validate

APT = """Listing...
libssl3/bookworm-security 3.0.15-1~deb12u1 arm64 [upgradable from: 3.0.11-1~deb12u2]
openssl/bookworm-security,bookworm 3.0.15-1~deb12u1 arm64 [upgradable from: 3.0.11-1~deb12u2]
raspi-firmware/stable 1:1.20240924-1 all [upgradable from: 1:1.20240529-1]
vim/stable-updates 2:9.0.1378-2+deb12u1 arm64 [upgradable from: 2:9.0.1378-2]

"""

DNF_CHECK = """
openssl.x86_64                     1:3.0.7-27.el9_4                 baseos
kernel.x86_64                      5.14.0-427.40.1.el9_4            baseos
Obsoleting Packages
grub2-tools.x86_64                 1:2.06-80.el9                    baseos
"""

DNF_SECURITY = """RLSA-2024:6356 Important/Sec. openssl-1:3.0.7-27.el9_4.x86_64
RLSA-2024:6356 Important/Sec. openssl-libs-1:3.0.7-27.el9_4.x86_64
RLSA-2024:6356 Important/Sec. openssl-libs-1:3.0.7-27.el9_4.x86_64
"""

DPKG = (
    "openssl\t3.0.11-1~deb12u2\tii \n"
    "openssl\t3.0.11-1~deb12u2\tii \n"           # libssl3 comes from the same source
    "glibc\t2.36-9+deb12u7\tii \n"
    "oldpkg\t1.0\trc \n"                         # removed, config left: not installed
    "\t\tii \n"
)
RPM = "openssl\t1:3.0.7-25.el9\nbash\t0:5.1.8-9.el9\ngpg-pubkey\t0:abc-def\n"


def test_apt_upgradable():
    assert sec.parse_apt_upgradable(APT) == (4, 2)
    assert sec.parse_apt_upgradable("Listing...\n") == (0, 0)


def test_dnf_parsing():
    assert sec.parse_dnf_check_update(DNF_CHECK) == 2
    assert sec.parse_dnf_security(DNF_SECURITY) == 2


class FakeRun:
    def __init__(self, answers):
        self.answers = answers

    def __call__(self, cmd, timeout):
        key = " ".join(cmd[:2])
        if key not in self.answers:
            raise FileNotFoundError(cmd[0])
        return self.answers[key]


def test_linux_updates_apt_dnf_and_neither():
    assert sec.linux_updates(FakeRun({"apt list": (0, APT)})) == {
        "source": "apt", "available": 4, "security": 2, "error": None}
    got = sec.linux_updates(FakeRun({"dnf -q": (100, DNF_CHECK)}))
    assert got["source"] == "dnf" and got["available"] == 2
    assert sec.linux_updates(FakeRun({"dnf -q": (1, "Cache-only enabled but no cache")}))["error"]
    assert sec.linux_updates(FakeRun({})) is None


def test_updates_cache_runs_every_6_hours():
    calls = []

    def check():
        calls.append(1)
        return {"source": "apt", "available": len(calls), "security": 0, "error": None}

    cache = sec.UpdatesCache(check)
    assert cache.get(0.0)["available"] == 1
    assert cache.get(6 * 3600 - 1)["available"] == 1
    got = cache.get(6 * 3600)
    assert got["available"] == 2 and got["checked_at"] == 6 * 3600

    def boom():
        raise OSError("apt is locked")

    assert sec.UpdatesCache(boom).get(0.0)["error"] == "apt is locked"


def test_helper_file_reading(tmp_path):
    path = tmp_path / "status.json"
    data, err = sec.read_helper(str(path))
    assert data is None and "has not run yet" in err
    path.write_text('{"version": 1, "firewall": {"active": true}}')
    assert sec.read_helper(str(path)) == ({"version": 1, "firewall": {"active": True}}, None)
    path.write_text("[1, 2]")
    assert "not a JSON object" in sec.read_helper(str(path))[1]
    path.write_text("{broken")
    assert "can't read" in sec.read_helper(str(path))[1]
    path.write_text(" " * (sec.HELPER_MAX_BYTES + 1))
    assert "too large" in sec.read_helper(str(path))[1]


def test_collect_security_message(tmp_path):
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"version": 1, "ran_at": 5.0}))
    cache = sec.UpdatesCache(lambda: {"source": "apt", "available": 1, "security": 1,
                                      "error": None})
    msg = sec.collect_security(str(path), cache, clock=lambda: 10.0)
    assert msg["helper"] == {"version": 1, "ran_at": 5.0} and msg["helper_error"] is None
    assert msg["updates"]["available"] == 1
    validate(dict(msg, ts=10.0))
    windows = sec.collect_security(str(tmp_path / "none.json"), None)
    assert windows["updates"] is None and windows["helper"] is None
    validate(dict(windows, ts=1.0))


@pytest.mark.parametrize("osr,eco", [
    ('ID=debian\nVERSION_ID="12"\n', "Debian:12"),
    ('ID=raspbian\nVERSION_ID="12"\nID_LIKE=debian\n', "Debian:12"),
    ('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n', "Ubuntu:22.04:LTS"),
    ('ID=ubuntu\nVERSION_ID="23.10"\nVERSION="23.10 (Mantic Minotaur)"\n', "Ubuntu:23.10"),
    ('ID="rocky"\nVERSION_ID="9.4"\n', "Rocky Linux:9"),
    ('ID="almalinux"\nVERSION_ID="9.4"\n', "AlmaLinux:9"),
    ('ID="rhel"\nVERSION_ID="9.4"\n', None),
    ('ID=debian\n', None),
])
def test_ecosystems(osr, eco):
    assert sec.ecosystem(sec.parse_os_release(osr)) == eco


def test_dpkg_and_rpm_parsing():
    assert sec.parse_dpkg_sources(DPKG) == [
        {"name": "openssl", "version": "3.0.11-1~deb12u2"},
        {"name": "glibc", "version": "2.36-9+deb12u7"}]
    assert sec.parse_rpm(RPM) == [{"name": "openssl", "version": "1:3.0.7-25.el9"},
                                  {"name": "bash", "version": "5.1.8-9.el9"}]


def test_collect_packages():
    run = FakeRun({"dpkg-query -W": (0, DPKG)})
    msg = sec.collect_packages(run, lambda p: 'ID=raspbian\nVERSION_ID="12"\n', "Linux")
    assert msg["ecosystem"] == "Debian:12" and msg["os"] == {"id": "raspbian", "version_id": "12"}
    assert [p["name"] for p in msg["packages"]] == ["glibc", "openssl"]
    validate(dict(msg, ts=1.0))
    rpm = sec.collect_packages(FakeRun({"rpm -qa": (0, RPM)}),
                               lambda p: 'ID="rocky"\nVERSION_ID="9.4"\n', "Linux")
    assert rpm["ecosystem"] == "Rocky Linux:9" and len(rpm["packages"]) == 2
    assert sec.collect_packages(FakeRun({}), lambda p: "", "Linux") is None
    assert sec.collect_packages(system="Windows") is None


def test_message_validation_limits():
    base = {"type": "packages", "ts": 1.0, "os": {}, "ecosystem": None, "packages": []}
    validate(base)
    for bad in ([{"name": "x"}], [{"name": "", "version": "1"}],
                [{"name": "x" * 201, "version": "1"}], ["x"],
                [{"name": "a", "version": "1"}] * 20001):
        with pytest.raises(InvalidMessage):
            validate(dict(base, packages=bad))
    sec_msg = {"type": "security", "ts": 1.0, "helper": None, "helper_error": None,
               "updates": None}
    validate(sec_msg)
    for bad in ({"helper": []}, {"helper_error": 3},
                {"updates": {"available": -1, "security": 0}},
                {"updates": {"available": 1}}):
        with pytest.raises(InvalidMessage):
            validate(dict(sec_msg, **bad))
