"""The security helper: the few checks that need root (Linux) or SYSTEM (Windows).

Run hourly by a systemd timer or a scheduled task, as

    python -I -m devmon.agent.helper [--out PATH]

It writes only results (yes/no, counts, dates) to a JSON file the unprivileged agent
reads. It never outputs a password hash or file contents, and never writes in a folder
the agent's account could write to.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import logging
import os
import platform
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("devmon.agent.helper")

VERSION = 1
DEFAULT_OUT = {
    "Linux": "/var/lib/devmon-helper/status.json",
    "Windows": r"C:\ProgramData\DevMon\helper\status.json",
}
DEFAULT_PASSWORDS = {"pi": "raspberry"}

# Remote-access / RAT tools worth flagging when they are running. Legitimate IT support may
# use some of these, so the finding is a warning, not an automatic block.
RAT_NAMES = {
    "anydesk", "teamviewer", "teamviewerd", "rustdesk", "ngrok", "dwagent", "dwservice",
    "x11vnc", "tigervnc", "vncserver", "chrome-remote-desktop", "chromoting", "supremo",
    "ammyy", "gotohttp", "nomachine", "nxserver", "remotepc", "splashtop",
}
# A process whose executable lives in one of these, or was deleted after it started, is a
# classic sign of malware.
SUSPICIOUS_EXE_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/run/shm/")
# Startup / persistence locations watched for new or changed entries.
PERSIST_FILES = ("/etc/crontab",)
PERSIST_DIRS = ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
                "/etc/systemd/system", "/root/.ssh")
HOME_SSH = "/home"
MAX_THREAT = 25
WINDOWS_UPDATE_EVERY_S = 6 * 3600

Runner = Callable[[List[str], float], Tuple[int, str]]


class NotInstalled(Exception):
    pass


def _run(cmd: List[str], timeout: float = 60) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, check=False)
    except FileNotFoundError:
        raise NotInstalled(cmd[0])
    return p.returncode, p.stdout.decode("utf-8", "replace")


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


# ---- Linux ---------------------------------------------------------------------------


def parse_sshd_t(text: str) -> Dict[str, Any]:
    conf: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            conf.setdefault(parts[0].lower(), parts[1].strip().lower())
    # Keyboard-interactive through PAM asks for the same password.
    kbd = conf.get("kbdinteractiveauthentication",
                   conf.get("challengeresponseauthentication", "no"))
    password = conf.get("passwordauthentication", "yes") == "yes" or (
        kbd == "yes" and conf.get("usepam", "no") == "yes")
    return {"permit_root_login": conf.get("permitrootlogin", "prohibit-password"),
            "password_authentication": password}


def _nft_active(ruleset: str) -> bool:
    """True if any input-hook chain drops by default or has rules."""
    chain_lines: List[str] = []
    in_chain = False
    for raw in ruleset.splitlines():
        line = raw.strip()
        if line.startswith("chain ") and line.endswith("{"):
            in_chain, chain_lines = True, []
            continue
        if in_chain and line == "}":
            in_chain = False
            head = " ".join(chain_lines[:1])
            if "hook input" in head and (
                    "policy drop" in head or any(l for l in chain_lines[1:] if l)):
                return True
            continue
        if in_chain:
            chain_lines.append(line)
    return False


def check_firewall(run: Runner) -> Dict[str, Any]:
    tried = []
    try:
        rc, out = run(["ufw", "status"], 30)
        tried.append("ufw")
        if "status: active" in out.lower():
            return {"active": True, "name": "ufw", "detail": "ufw is active"}
    except NotInstalled:
        pass
    try:
        rc, out = run(["firewall-cmd", "--state"], 30)
        tried.append("firewalld")
        if out.strip().lower() == "running":
            return {"active": True, "name": "firewalld", "detail": "firewalld is running"}
    except NotInstalled:
        pass
    try:
        rc, out = run(["nft", "list", "ruleset"], 30)
        tried.append("nftables")
        if rc == 0 and _nft_active(out):
            return {"active": True, "name": "nftables", "detail": "nftables filters incoming traffic"}
    except NotInstalled:
        pass
    try:
        rc, out = run(["iptables", "-S", "INPUT"], 30)
        tried.append("iptables")
        lines = out.splitlines()
        if rc == 0 and ("-P INPUT DROP" in lines or any(l.startswith("-A INPUT") for l in lines)):
            return {"active": True, "name": "iptables", "detail": "iptables filters incoming traffic"}
    except NotInstalled:
        pass
    if not tried:
        return {"active": False, "name": "none", "detail": "no firewall is installed"}
    return {"active": False, "name": tried[0],
            "detail": "no active firewall (checked %s)" % ", ".join(tried)}


def firewall_logging(name: str, run: Runner, read_file: Callable[[str], str]) -> Optional[bool]:
    """Whether dropped packets are logged (port-scan detection needs it); None if unknown."""
    try:
        if name == "ufw":
            for line in read_file("/etc/ufw/ufw.conf").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "LOGLEVEL":
                    return value.strip().strip("\"'").lower() not in ("off", "")
            return True  # ufw's default is "low"
        if name == "firewalld":
            rc, out = run(["firewall-cmd", "--get-log-denied"], 30)
            return out.strip().lower() != "off" if rc == 0 else None
    except Exception:
        return None
    return None


def libcrypt() -> Optional[Callable[[str, str], str]]:
    """crypt(3) from libcrypt (libxcrypt knows yescrypt); None if it can't be loaded."""
    names = [ctypes.util.find_library("crypt"), "libcrypt.so.1", "libcrypt.so.2"]
    for name in names:
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        fn = lib.crypt
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        fn.restype = ctypes.c_char_p

        def crypt(word: str, setting: str, _fn: Any = fn) -> str:
            out = _fn(word.encode("utf-8"), setting.encode("ascii"))
            return (out or b"").decode("ascii", "replace")

        return crypt
    return None


def check_default_password(shadow: str,
                           crypt: Optional[Callable[[str, str], str]]) -> Optional[Dict[str, Any]]:
    """{"user", "default"} for the first default account present; None if none exists."""
    for line in shadow.splitlines():
        fields = line.split(":")
        if len(fields) < 2 or fields[0] not in DEFAULT_PASSWORDS:
            continue
        user, hashed = fields[0], fields[1]
        if not hashed or hashed[0] in "!*":
            return {"user": user, "default": False}  # locked or no password login
        if crypt is None:
            raise RuntimeError("libcrypt is not available, so the password can't be checked")
        result = crypt(DEFAULT_PASSWORDS[user], hashed)
        if not result or result.startswith("*"):
            raise RuntimeError("this password hash format can't be checked")
        return {"user": user, "default": result == hashed}
    return None


def linux_checks(run: Runner, read_file: Callable[[str], str],
                 crypt: Optional[Callable[[str, str], str]],
                 errors: Dict[str, str],
                 previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ssh": None, "firewall": None, "default_password": None}
    try:
        rc, text = run(["sshd", "-T"], 30)
        if rc == 0:
            out["ssh"] = parse_sshd_t(text)
        else:
            errors["ssh"] = "sshd -T failed: %s" % text.strip()[:150]
    except NotInstalled:
        pass  # no SSH server: nothing to report
    except Exception as exc:
        errors["ssh"] = _short(exc)
    try:
        out["firewall"] = check_firewall(run)
        out["firewall"]["logging"] = firewall_logging(out["firewall"]["name"], run, read_file)
    except Exception as exc:
        errors["firewall"] = _short(exc)
    try:
        out["default_password"] = check_default_password(read_file("/etc/shadow"), crypt)
    except Exception as exc:
        errors["default_password"] = _short(exc)
    out.update(threat_checks(previous, errors, read_file=read_file))
    return out


# ---- threats: suspicious processes, remote-access tools, persistence -----------------


def _proc_name(comm: str, exe: str) -> str:
    base = comm.strip() or os.path.basename(exe.replace(" (deleted)", ""))
    return base.lower().replace(".exe", "")


def classify_processes(procs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split a process list into remote-access tools and suspicious (temp/deleted) binaries.

    `procs` are {pid, comm, exe}. Pure, so it is unit-tested without a real /proc.
    """
    rat: List[Dict[str, Any]] = []
    suspicious: List[Dict[str, Any]] = []
    for p in procs:
        exe = p.get("exe") or ""
        name = _proc_name(p.get("comm") or "", exe)
        entry = {"pid": p.get("pid"), "name": name, "exe": exe[:200]}
        if name in RAT_NAMES or any(k in name for k in ("teamviewer", "anydesk", "rustdesk")):
            rat.append(entry)
        if exe.endswith("(deleted)") or any(exe.startswith(d) for d in SUSPICIOUS_EXE_DIRS):
            suspicious.append(entry)
    return {"remote_access": rat[:MAX_THREAT], "suspicious_processes": suspicious[:MAX_THREAT]}


def _list_processes() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return out  # no /proc (not Linux, or restricted): nothing to scan
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % pid)  # "/path (deleted)" if the file was removed
        except OSError:
            continue  # kernel thread, or the process has gone
        try:
            with open("/proc/%s/comm" % pid, encoding="utf-8", errors="replace") as f:
                comm = f.read().strip()
        except OSError:
            comm = ""
        out.append({"pid": int(pid), "comm": comm, "exe": exe})
    return out


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def collect_persistence(read_file: Callable[[str], str],
                        listdir: Callable[[str], List[str]]) -> Dict[str, str]:
    """A name -> content-hash map of the watched startup locations. Only hashes leave the
    helper, never the file contents."""
    items: Dict[str, str] = {}

    def add(path: str) -> None:
        try:
            items[path] = _digest(read_file(path))
        except OSError:
            pass

    for path in PERSIST_FILES:
        add(path)
    for folder in PERSIST_DIRS:
        try:
            names = sorted(listdir(folder))
        except OSError:
            continue
        for name in names:
            add(folder + "/" + name)
    try:
        homes = sorted(listdir(HOME_SSH))
    except OSError:
        homes = []
    for home in homes:
        add("%s/%s/.ssh/authorized_keys" % (HOME_SSH, home))
    return items


def persistence_changes(current: Dict[str, str],
                        previous: Optional[Dict[str, str]]) -> List[Dict[str, str]]:
    """New or changed startup items since the last run. The first run (no baseline) reports
    nothing: it only sets the baseline."""
    if not previous:
        return []
    changes: List[Dict[str, str]] = []
    for name, h in sorted(current.items()):
        if name not in previous:
            changes.append({"item": name, "change": "added"})
        elif previous[name] != h:
            changes.append({"item": name, "change": "changed"})
    for name in sorted(previous):
        if name not in current:
            changes.append({"item": name, "change": "removed"})
    return changes[:MAX_THREAT]


def threat_checks(previous: Optional[Dict[str, Any]], errors: Dict[str, str],
                  list_processes: Callable[[], List[Dict[str, Any]]] = _list_processes,
                  read_file: Callable[[str], str] = _read_file,
                  listdir: Callable[[str], List[str]] = os.listdir) -> Dict[str, Any]:
    out: Dict[str, Any] = {"remote_access": None, "suspicious_processes": None,
                           "persistence": None, "persistence_state": None}
    try:
        cls = classify_processes(list_processes())
        out["remote_access"] = cls["remote_access"]
        out["suspicious_processes"] = cls["suspicious_processes"]
    except Exception as exc:
        errors["processes"] = _short(exc)
    try:
        current = collect_persistence(read_file, listdir)
        prev_state = previous.get("persistence_state") if isinstance(previous, dict) else None
        out["persistence"] = persistence_changes(current, prev_state)
        out["persistence_state"] = current
    except Exception as exc:
        errors["persistence"] = _short(exc)
    return out


# ---- Windows -------------------------------------------------------------------------

_PS_DEFENDER = ("Get-MpComputerStatus | Select-Object AntivirusEnabled,"
                "RealTimeProtectionEnabled,AntivirusSignatureAge,AMRunningMode | ConvertTo-Json")
_PS_AV = ("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
          "Select-Object displayName,productState | ConvertTo-Json")
# LogBlocked is an enum that ConvertTo-Json would turn into a number; ask for its name.
_PS_FIREWALL = ("Get-NetFirewallProfile | Select-Object Name,Enabled,"
                "@{n='LogBlocked';e={[string]$_.LogBlocked}} | ConvertTo-Json")
_PS_UPDATE = (
    "$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); "
    "$r = $s.Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\"); $sec = 0; "
    "foreach ($u in $r.Updates) { if ($u.MsrcSeverity -in 'Critical','Important' -or "
    "($u.Categories | Where-Object { $_.Name -eq 'Security Updates' })) { $sec++ } }; "
    "@{available = $r.Updates.Count; security = $sec} | ConvertTo-Json")


def _ps(run: Runner, script: str, timeout: float = 120) -> Any:
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)
    if rc != 0:
        raise RuntimeError(out.strip().splitlines()[-1][:150] if out.strip() else "failed")
    out = out.strip()
    return json.loads(out) if out else None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _truthy(value: Any) -> bool:
    return value is True or value == 1 or str(value).lower() == "true"


def other_antivirus(products: Any) -> Optional[str]:
    """Name of an active antivirus that isn't Defender, from SecurityCenter2."""
    for p in _as_list(products):
        if not isinstance(p, dict):
            continue
        name = str(p.get("displayName") or "")
        try:
            state = int(p.get("productState") or 0)
        except (TypeError, ValueError):
            continue
        if (state >> 12) & 0xF == 1 and "defender" not in name.lower():
            return name[:80]
    return None


def parse_defender(status: Any, products: Any) -> Dict[str, Any]:
    status = status if isinstance(status, dict) else {}
    age = status.get("AntivirusSignatureAge")
    return {
        "enabled": _truthy(status.get("AntivirusEnabled")),
        "realtime": _truthy(status.get("RealTimeProtectionEnabled")),
        # 65535 means "never updated".
        "signature_age_days": float(age) if isinstance(age, (int, float)) and age < 65535 else None,
        "other_av": other_antivirus(products),
    }


def parse_firewall_profiles(profiles: Any) -> Dict[str, Any]:
    items = [p for p in _as_list(profiles) if isinstance(p, dict)]
    off = [str(p.get("Name")) for p in items if not _truthy(p.get("Enabled"))]
    logged = [p.get("LogBlocked") for p in items]
    logging_on = (None if not items or any(v is None for v in logged)
                  else all(str(v) == "True" for v in logged))
    if off:
        return {"active": False, "name": "windows", "logging": logging_on,
                "detail": "Windows Firewall is off for the %s profile%s" % (
                    ", ".join(off), "s" if len(off) > 1 else "")}
    return {"active": True, "name": "windows", "detail": "Windows Firewall is on",
            "logging": logging_on}


def windows_checks(run: Runner, previous: Optional[Dict[str, Any]], now: float,
                   errors: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"defender": None, "firewall": None, "windows_update": None}
    try:
        status = _ps(run, _PS_DEFENDER)
        try:
            products = _ps(run, _PS_AV)
        except Exception:
            products = None  # Windows Server has no Security Center
        out["defender"] = parse_defender(status, products)
    except Exception as exc:
        errors["defender"] = _short(exc)
    try:
        out["firewall"] = parse_firewall_profiles(_ps(run, _PS_FIREWALL))
    except Exception as exc:
        errors["firewall"] = _short(exc)
    last = (previous or {}).get("windows_update")
    try:
        last_at = float(last.get("checked_at") or 0) if isinstance(last, dict) else 0.0
    except (TypeError, ValueError):
        last, last_at = None, 0.0
    if last is not None and now - last_at < WINDOWS_UPDATE_EVERY_S:
        out["windows_update"] = last
    else:
        try:
            found = _ps(run, _PS_UPDATE, timeout=900) or {}
            out["windows_update"] = {"available": int(found.get("available") or 0),
                                     "security": int(found.get("security") or 0),
                                     "checked_at": now}
        except Exception as exc:
            errors["windows_update"] = _short(exc)
            out["windows_update"] = last if isinstance(last, dict) else None
    return out


# ---- running and writing -------------------------------------------------------------


def _short(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text.splitlines()[0][:150]


def run_checks(system: Optional[str] = None, run: Runner = _run,
               read_file: Callable[[str], str] = _read_file,
               crypt: Any = "auto", previous: Optional[Dict[str, Any]] = None,
               now: Optional[float] = None) -> Dict[str, Any]:
    system = system or platform.system()
    now = time.time() if now is None else now
    errors: Dict[str, str] = {}
    result: Dict[str, Any] = {"version": VERSION, "ran_at": now, "errors": errors}
    if system == "Windows":
        result.update(windows_checks(run, previous, now, errors))
    else:
        result.update(linux_checks(run, read_file, libcrypt() if crypt == "auto" else crypt,
                                   errors, previous))
    return result


class UnsafeFolder(Exception):
    pass


def write_status(path: str, data: Dict[str, Any]) -> None:
    """Write atomically, refusing a folder someone else could have tampered with."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, mode=0o755, exist_ok=True)
    if os.path.islink(folder):
        raise UnsafeFolder("%s is a symbolic link" % folder)
    if os.name == "posix":
        st = os.lstat(folder)
        if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UnsafeFolder("%s must be owned by this user and not writable by others"
                               % folder)
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, path)


def _previous(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -I -m devmon.agent.helper",
                                     description="devmon security helper (run as root/SYSTEM)")
    parser.add_argument("--out", help="where to write the results")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = args.out or DEFAULT_OUT.get(platform.system(), DEFAULT_OUT["Linux"])
    result = run_checks(previous=_previous(out))
    try:
        write_status(out, result)
    except (OSError, UnsafeFolder) as exc:
        log.error("could not write %s: %s", out, exc)
        return 1
    for check, err in sorted(result["errors"].items()):
        log.warning("%s: %s", check, err)
    log.info("wrote %s", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
