"""Security posture the unprivileged agent can see for itself, plus the helper's results.

- pending updates (apt / dnf), refreshed every 6 hours
- the installed package list, for CVE matching on the hub (Linux only)
- the root/SYSTEM helper's status file, passed on as it is (bounded and type-checked)
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from devmon.agent.helper import DEFAULT_OUT

HELPER_MAX_BYTES = 256 * 1024
UPDATES_EVERY_S = 6 * 3600
MAX_PACKAGES = 20000
MAX_FIELD = 200

Runner = Callable[[List[str], float], Tuple[int, str]]


def default_helper_file() -> str:
    return DEFAULT_OUT.get(platform.system(), DEFAULT_OUT["Linux"])


def _run(cmd: List[str], timeout: float = 120) -> Tuple[int, str]:
    """stdout only: apt warns on stderr that its CLI is unstable."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=timeout, check=False)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def _short(exc: BaseException) -> str:
    return (str(exc).strip() or type(exc).__name__).splitlines()[0][:150]


# ---- the helper's file --------------------------------------------------------------


def read_helper(path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        size = os.stat(path).st_size
    except FileNotFoundError:
        return None, "the security helper has not run yet (no %s)" % path
    except OSError as exc:
        return None, "can't read the security helper's results: %s" % _short(exc)
    if size > HELPER_MAX_BYTES:
        return None, "the security helper's results are too large (%d bytes)" % size
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        return None, "can't read the security helper's results: %s" % _short(exc)
    if not isinstance(data, dict):
        return None, "the security helper's results are not a JSON object"
    return data, None


# ---- pending updates ----------------------------------------------------------------


def parse_apt_upgradable(text: str) -> Tuple[int, int]:
    """(available, security) from `apt list --upgradable`."""
    available = security = 0
    for line in text.splitlines():
        if "/" not in line or "[upgradable" not in line:
            continue  # "Listing..." and blank lines
        available += 1
        suites = line.split("/", 1)[1].split(" ", 1)[0]
        if any("security" in s for s in suites.split(",")):
            security += 1
    return available, security


def parse_dnf_check_update(text: str) -> int:
    count = 0
    for line in text.splitlines():
        if line.startswith("Obsoleting") or line.startswith("Security:"):
            break
        parts = line.split()
        if len(parts) == 3 and "." in parts[0]:
            count += 1
    return count


def parse_dnf_security(text: str) -> int:
    names = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and "/" in parts[1]:
            names.add(parts[-1])
    return len(names)


def linux_updates(run: Runner = _run) -> Optional[Dict[str, Any]]:
    try:
        rc, out = run(["apt", "list", "--upgradable"], 300)
    except FileNotFoundError:
        pass
    else:
        if rc != 0:
            return {"source": "apt", "available": 0, "security": 0,
                    "error": "apt list failed (exit %d)" % rc}
        available, security = parse_apt_upgradable(out)
        return {"source": "apt", "available": available, "security": security, "error": None}
    try:
        # -C: use the cache the system's own timer refreshes; never download as this user.
        rc, out = run(["dnf", "-q", "-C", "check-update"], 300)
    except FileNotFoundError:
        return None
    if rc not in (0, 100):
        return {"source": "dnf", "available": 0, "security": 0,
                "error": "dnf check-update failed (exit %d); is the dnf cache filled?" % rc}
    available = parse_dnf_check_update(out)
    security = 0
    try:
        rc, out = run(["dnf", "-q", "-C", "updateinfo", "list", "--security"], 300)
        if rc == 0:
            security = parse_dnf_security(out)
    except FileNotFoundError:
        pass
    return {"source": "dnf", "available": available, "security": security, "error": None}


class UpdatesCache:
    """Runs the (slow) updates check at most every 6 hours."""

    def __init__(self, check: Callable[[], Optional[Dict[str, Any]]] = linux_updates,
                 every_s: float = UPDATES_EVERY_S) -> None:
        self.check = check
        self.every_s = every_s
        self.value: Optional[Dict[str, Any]] = None
        self.at: Optional[float] = None

    def get(self, now: float) -> Optional[Dict[str, Any]]:
        if self.at is None or now - self.at >= self.every_s:
            try:
                self.value = self.check()
            except Exception as exc:
                self.value = {"source": "unknown", "available": 0, "security": 0,
                              "error": _short(exc)}
            if self.value is not None:
                self.value = dict(self.value, checked_at=now)
            self.at = now
        return self.value


def collect_security(helper_path: str, cache: Optional[UpdatesCache],
                     clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    helper, error = read_helper(helper_path)
    return {
        "type": "security",
        "helper": helper,
        "helper_error": error,
        # On Windows the helper reports Windows Update instead.
        "updates": cache.get(clock()) if cache is not None else None,
    }


# ---- installed packages -------------------------------------------------------------


def parse_os_release(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def ecosystem(osr: Dict[str, str]) -> Optional[str]:
    """OSV.dev ecosystem name for this OS, or None if OSV has no data for it."""
    os_id = osr.get("ID", "").lower()
    version = osr.get("VERSION_ID", "")
    major = version.split(".")[0]
    if not major:
        return None
    if os_id in ("debian", "raspbian"):
        return "Debian:%s" % major
    if os_id == "ubuntu":
        lts = "LTS" in osr.get("VERSION", "")
        return "Ubuntu:%s%s" % (version, ":LTS" if lts else "")
    if os_id == "rocky":
        return "Rocky Linux:%s" % major
    if os_id == "almalinux":
        return "AlmaLinux:%s" % major
    return None


def _clip(text: str) -> str:
    return text[:MAX_FIELD]


def parse_dpkg_sources(text: str) -> List[Dict[str, str]]:
    """Installed packages as (source package, source version), de-duplicated.

    OSV's Debian and Ubuntu records are keyed by source package.
    """
    seen = set()
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].startswith("ii"):
            continue
        key = (parts[0], parts[1])
        if parts[0] and parts[1] and key not in seen:
            seen.add(key)
            out.append({"name": _clip(parts[0]), "version": _clip(parts[1])})
    return out


def parse_rpm(text: str) -> List[Dict[str, str]]:
    out = []
    seen = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or parts[0] == "gpg-pubkey":
            continue
        version = parts[1]
        if version.startswith("0:"):
            version = version[2:]
        if (parts[0], version) not in seen:
            seen.add((parts[0], version))
            out.append({"name": _clip(parts[0]), "version": _clip(version)})
    return out


def collect_packages(run: Runner = _run,
                     read_file: Callable[[str], str] = lambda p: open(p, encoding="utf-8").read(),
                     system: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if (system or platform.system()) != "Linux":
        return None  # Windows is covered by Windows Update and Defender (spec §10)
    try:
        osr = parse_os_release(read_file("/etc/os-release"))
    except OSError:
        osr = {}
    packages: List[Dict[str, str]] = []
    try:
        rc, out = run(["dpkg-query", "-W", "-f",
                       "${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"], 300)
        if rc == 0:
            packages = parse_dpkg_sources(out)
    except FileNotFoundError:
        try:
            rc, out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"],
                          300)
            if rc == 0:
                packages = parse_rpm(out)
        except FileNotFoundError:
            return None
    return {
        "type": "packages",
        "os": {"id": _clip(osr.get("ID", "")), "version_id": _clip(osr.get("VERSION_ID", ""))},
        "ecosystem": ecosystem(osr),
        "packages": sorted(packages, key=lambda p: (p["name"], p["version"]))[:MAX_PACKAGES],
    }
