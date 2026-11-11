#!/usr/bin/env python3
"""Fault-injection harness for the self-healing experiments (docs/RUNNING.md, Checkpoint 8).

Each run:
1. injects one fault
2. waits until it is gone, as seen from where it was caused
3. appends a row to a CSV file

The result is the healing time end to end, from injection to healed. The hub's
Self-healing page exports its own log (detected -> healed); the two can be joined on time.

Standard library only (Python 3.9+), so it runs on a Pi or a laptop without installing
anything. Faults on a device:

    python3 inject.py cpu        [--runs 10]          # as your normal user, not root
    python3 inject.py mem        [--percent 93]       # as your normal user, not root
    python3 inject.py disk       [--percent 92] [--dir /var/tmp/devmon-scratch]
    sudo python3 inject.py service --unit nginx

Attacks, from another machine:

    python3 inject.py bruteforce --target 192.168.1.21 [--attempts 12]
    python3 inject.py portscan   --target 192.168.1.21 [--ports 10000-10019]

Then:

    python3 inject.py summary [--csv faults.csv]
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import socket
import statistics
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

FIELDS = ("run", "fault", "target", "injected_at", "healed_at", "heal_s", "healed", "note")
POLL_S = 0.5

# The CPU hog: one process, one thread per core. hashlib releases the GIL on large buffers,
# so the threads really use every core while staying a single process for the fixer to stop.
CPU_HOG = """
import hashlib, os, threading
buf = os.urandom(1 << 20)
def spin():
    while True:
        hashlib.sha256(buf).digest()
for _ in range(max(1, os.cpu_count() or 1) - 1):
    threading.Thread(target=spin, daemon=True).start()
spin()
"""

# The memory hog: grows in 32 MB steps (each page written, so it is really used) until the
# whole system is at the target, then holds it.
MEM_HOG = """
import sys, time
target = float(sys.argv[1])
def used():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0])
    return 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
hold = []
while used() < target:
    b = bytearray(32 << 20)
    b[::4096] = b"\\x01" * len(range(0, len(b), 4096))
    hold.append(b)
print("holding", len(hold) * 32, "MB", flush=True)
while True:
    time.sleep(1)
"""


def now_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) + ".%03d" % int((ts % 1) * 1000)


def wait_until(healed: Callable[[], bool], timeout: float,
               sleep: Callable[[float], None] = time.sleep,
               clock: Callable[[], float] = time.time) -> Optional[float]:
    """Poll until healed() is true; the time it became true, or None after the timeout."""
    end = clock() + timeout
    while clock() < end:
        if healed():
            return clock()
        sleep(POLL_S)
    return None


def append_row(path: str, row: Dict[str, object]) -> None:
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def record(args: argparse.Namespace, run: int, fault: str, target: str, injected: float,
           healed: Optional[float], note: str = "") -> None:
    row = {"run": run, "fault": fault, "target": target, "injected_at": now_iso(injected),
           "healed_at": now_iso(healed) if healed else "",
           "heal_s": "%.1f" % (healed - injected) if healed else "",
           "healed": "yes" if healed else "no", "note": note}
    append_row(args.csv, row)
    print("run %d %s: %s" % (run, fault, ("healed in %.1f s" % (healed - injected))
                             if healed else "NOT healed within %d s" % args.timeout), flush=True)


# ---- faults on this device ------------------------------------------------------------


def _hog(code: str, *argv: str) -> "subprocess.Popen[bytes]":
    return subprocess.Popen([sys.executable, "-c", code] + list(argv))


def _stop(p: "subprocess.Popen[bytes]") -> None:
    if p.poll() is None:
        p.kill()
        p.wait()


def fault_process(args: argparse.Namespace, run: int, fault: str, code: str,
                  *argv: str) -> None:
    """CPU and memory: healed when the fixer stops the hog."""
    if os.geteuid() == 0:
        sys.exit("Run the %s fault as your normal user: the fixer never stops root's "
                 "processes unless fixer.ini allows it." % fault)
    p = _hog(code, *argv)
    injected = time.time()
    healed = wait_until(lambda: p.poll() is not None, args.timeout)
    _stop(p)
    record(args, run, fault, socket.gethostname(), injected, healed,
           "" if healed else "the hog was still running; stopped by the harness")


def disk_percent(path: str) -> float:
    u = shutil.disk_usage(path)
    return 100.0 * u.used / u.total


def fault_disk(args: argparse.Namespace, run: int) -> None:
    """Disk: fill the scratch folder's file system; healed when the fixer clears it."""
    os.makedirs(args.dir, exist_ok=True)
    path = os.path.join(args.dir, "fill-%d-%d.bin" % (os.getpid(), run))
    chunk = b"\0" * (64 << 20)
    injected = time.time()
    with open(path, "wb") as f:
        while disk_percent(args.dir) < args.percent:
            u = shutil.disk_usage(args.dir)
            if u.free < (256 << 20):
                break  # never fill a disk completely
            f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
    print("disk at %.0f%%; waiting for the cleanup" % disk_percent(args.dir), flush=True)
    healed = wait_until(lambda: not os.path.exists(path), args.timeout)
    if os.path.exists(path):
        os.unlink(path)
    record(args, run, "disk", args.dir, injected, healed)


def fault_service(args: argparse.Namespace, run: int) -> None:
    """A stopped service: healed when it is running again."""
    if os.geteuid() != 0:
        sys.exit("Stopping a service needs root: run this with sudo.")

    def active() -> bool:
        p = subprocess.run(["systemctl", "is-active", args.unit], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False)
        return p.stdout.decode().strip() == "active"
    if not active():
        sys.exit("%s is not running to begin with." % args.unit)
    subprocess.run(["systemctl", "stop", args.unit], check=True)
    injected = time.time()
    healed = wait_until(active, args.timeout)
    if not healed:
        subprocess.run(["systemctl", "start", args.unit], check=False)
    record(args, run, "service", args.unit, injected, healed,
           "" if healed else "started again by the harness")


# ---- attacks from another machine ------------------------------------------------------


def blocked(target: str, port: int, timeout: float = 4.0) -> bool:
    """True when connections are silently dropped (blocked), not answered or refused.

    The timeout is longer than the 2 s Windows spends retrying a refused connection.
    """
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return False
    except socket.timeout:
        return True
    except OSError:
        return False  # refused or unreachable: the host is answering


def fault_bruteforce(args: argparse.Namespace, run: int) -> None:
    if blocked(args.target, args.port):
        sys.exit("%s:%d is already blocked from here; unblock it on the Self-healing page "
                 "first." % (args.target, args.port))
    null = "NUL" if os.name == "nt" else "/dev/null"
    user = "devmon-test-%d" % run
    injected = time.time()
    for _ in range(args.attempts):
        # An unknown user with no key: each try is logged as a failed login.
        subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=" + null, "-o", "ConnectTimeout=5",
                        "-p", str(args.port), "%s@%s" % (user, args.target), "true"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    healed = wait_until(lambda: blocked(args.target, args.port), args.timeout)
    record(args, run, "bruteforce", args.target, injected, healed)


def parse_ports(text: str) -> List[int]:
    out: List[int] = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            out.extend(range(lo, hi + 1))
        elif part.strip():
            out.append(int(part))
    if not out or not all(1 <= p <= 65535 for p in out):
        raise argparse.ArgumentTypeError("ports must be 1-65535, e.g. 10000-10019")
    return out


def fault_portscan(args: argparse.Namespace, run: int) -> None:
    if blocked(args.target, args.port):
        sys.exit("%s:%d is already blocked from here; unblock it on the Self-healing page "
                 "first." % (args.target, args.port))
    injected = time.time()
    for port in args.ports:
        try:
            with socket.create_connection((args.target, port), timeout=0.5):
                pass
        except OSError:
            pass
    healed = wait_until(lambda: blocked(args.target, args.port), args.timeout)
    record(args, run, "portscan", args.target, injected, healed)


# ---- summary -----------------------------------------------------------------------------


def summarize(rows: List[Dict[str, str]]) -> List[Tuple[str, Dict[str, object]]]:
    out = []
    for fault in sorted({r["fault"] for r in rows}):
        sel = [r for r in rows if r["fault"] == fault]
        times = sorted(float(r["heal_s"]) for r in sel if r["healed"] == "yes" and r["heal_s"])
        healed = len(times)
        p95 = times[min(len(times) - 1, int(round(0.95 * (len(times) - 1))))] if times else None
        out.append((fault, {
            "runs": len(sel), "healed": healed,
            "success": 100.0 * healed / len(sel) if sel else 0.0,
            "mean": statistics.mean(times) if times else None,
            "median": statistics.median(times) if times else None,
            "p95": p95, "max": times[-1] if times else None,
            "under_60": sum(1 for t in times if t < 60),
        }))
    return out


def show_summary(args: argparse.Namespace) -> None:
    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("No runs in %s yet." % args.csv)
        return

    def s(v: object) -> str:
        return "-" if v is None else "%.1f" % v  # type: ignore[str-format]
    print("%-11s %5s %7s %8s %8s %8s %8s %8s %8s" % (
        "fault", "runs", "healed", "success", "mean s", "median", "p95", "max", "<60 s"))
    all_rows = summarize(rows) + [("ALL", summarize([dict(r, fault="ALL") for r in rows])[0][1])]
    for fault, st in all_rows:
        print("%-11s %5d %7d %7.0f%% %8s %8s %8s %8s %8d" % (
            fault, st["runs"], st["healed"], st["success"], s(st["mean"]), s(st["median"]),
            s(st["p95"]), s(st["max"]), st["under_60"]))
    total = all_rows[-1][1]
    print()
    print("Hypothesis (mean healing time under 60 s, success over 90%%): %s" % (
        "supported" if total["mean"] is not None and total["mean"] < 60 and
        total["success"] > 90 else "not supported by these runs"))


# ---- command line ------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inject faults and time the self-healing.")
    sub = parser.add_subparsers(dest="fault", required=True)

    def common(p: argparse.ArgumentParser, pause: int) -> None:
        p.add_argument("--runs", type=int, default=1, help="how many times (default 1)")
        p.add_argument("--pause", type=int, default=pause,
                       help="seconds between runs (default %d)" % pause)
        p.add_argument("--timeout", type=int, default=900,
                       help="give up on a run after this many seconds (default 900)")
        p.add_argument("--csv", default="faults.csv", help="results file (appended)")

    common(sub.add_parser("cpu", help="all cores busy in one process"), 180)
    p = sub.add_parser("mem", help="use memory until the system is this full")
    common(p, 180)
    p.add_argument("--percent", type=float, default=93.0)
    p = sub.add_parser("disk", help="fill the scratch folder's disk")
    common(p, 180)
    p.add_argument("--percent", type=float, default=92.0)
    p.add_argument("--dir", default="/var/tmp/devmon-scratch")
    p = sub.add_parser("service", help="stop a systemd service (sudo)")
    common(p, 180)
    p.add_argument("--unit", required=True)
    for name in ("bruteforce", "portscan"):
        # The incident must end (30 quiet minutes) before the same attacker counts again.
        p = sub.add_parser(name, help="attack a device from this machine")
        common(p, 1900)
        p.add_argument("--target", required=True)
        p.add_argument("--port", type=int, default=22,
                       help="an open port on the target, used to see the block (default 22)")
        if name == "bruteforce":
            p.add_argument("--attempts", type=int, default=12)
        else:
            p.add_argument("--ports", type=parse_ports, default=parse_ports("10000-10019"))
    p = sub.add_parser("summary", help="healing time and success rate from the CSV")
    p.add_argument("--csv", default="faults.csv")
    args = parser.parse_args(argv)

    if args.fault == "summary":
        show_summary(args)
        return 0
    if args.fault in ("cpu", "mem", "disk", "service") and not sys.platform.startswith("linux"):
        sys.exit("This fault is injected on a Linux device (the Pi).")
    for run in range(1, args.runs + 1):
        if args.fault == "cpu":
            fault_process(args, run, "cpu", CPU_HOG)
        elif args.fault == "mem":
            fault_process(args, run, "mem", MEM_HOG, str(args.percent))
        elif args.fault == "disk":
            fault_disk(args, run)
        elif args.fault == "service":
            fault_service(args, run)
        elif args.fault == "bruteforce":
            fault_bruteforce(args, run)
        else:
            fault_portscan(args, run)
        if run < args.runs:
            time.sleep(args.pause)
    return 0


if __name__ == "__main__":
    sys.exit(main())
