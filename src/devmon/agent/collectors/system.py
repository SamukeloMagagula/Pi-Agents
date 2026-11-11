from __future__ import annotations

import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

_SKIP_FSTYPES = ("squashfs", "tmpfs", "devtmpfs", "overlay")
_SENSOR_PREFERENCE = ("cpu_thermal", "coretemp", "k10temp")


def _run_vcgencmd() -> Optional[str]:
    try:
        result = subprocess.run(
            ["vcgencmd", "measure_temp"],
            capture_output=True, text=True, timeout=2,
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _parse_vcgencmd(output: Optional[str]) -> Optional[float]:
    # Looks like: temp=48.3'C
    if not output or "temp=" not in output:
        return None
    try:
        return float(output.split("temp=", 1)[1].split("'", 1)[0])
    except ValueError:
        return None


def _sensor_reading(ps: Any) -> Optional[float]:
    try:
        sensors = ps.sensors_temperatures()
    except Exception:
        return None
    if not sensors:
        return None
    names = [n for n in _SENSOR_PREFERENCE if sensors.get(n)]
    names += [n for n in sensors if sensors[n] and n not in names]
    if not names:
        return None
    return float(sensors[names[0]][0].current)


def read_temperature(ps: Any = psutil, vcgencmd: Callable[[], Optional[str]] = _run_vcgencmd,
                     platform_mod: Any = platform) -> Optional[float]:
    # Windows has no unprivileged thermal source; see the plan's recorded deviation.
    if platform_mod.system() == "Windows":
        return None
    temp = _sensor_reading(ps)
    if temp is not None:
        return temp
    return _parse_vcgencmd(vcgencmd())


def _load1() -> Optional[float]:
    if not hasattr(os, "getloadavg"):
        return None
    try:
        return os.getloadavg()[0]
    except OSError:
        return None


def collect_fast(ps: Any = psutil, load1: Callable[[], Optional[float]] = _load1,
                 temperature: Optional[Callable[[], Optional[float]]] = None) -> Dict[str, Any]:
    net = ps.net_io_counters()
    return {
        "cpu": {
            "percent": ps.cpu_percent(interval=None),
            "cores": ps.cpu_count(logical=True) or 1,
            "load1": load1(),
        },
        "mem": {
            "percent": ps.virtual_memory().percent,
            "swap_percent": ps.swap_memory().percent,
        },
        "temp_c": temperature() if temperature else read_temperature(ps),
        "net": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv},
    }


def _gb(n: float) -> float:
    return round(n / 1024 ** 3, 1)


def collect_slow(ps: Any = psutil, clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    disks: List[Dict[str, Any]] = []
    seen = set()
    for part in ps.disk_partitions(all=False):
        if part.fstype in _SKIP_FSTYPES or part.mountpoint in seen:
            continue
        try:
            usage = ps.disk_usage(part.mountpoint)
        except OSError:
            # Empty card readers on Windows raise here.
            continue
        seen.add(part.mountpoint)
        disks.append({
            "mount": part.mountpoint,
            "percent": usage.percent,
            "total_gb": _gb(usage.total),
            "used_gb": _gb(usage.used),
        })
    return {"disks": disks, "uptime_s": clock() - ps.boot_time()}


def detect_device_kind(platform_mod: Any = platform,
                       model_path: Path = Path("/proc/device-tree/model")) -> str:
    system = platform_mod.system()
    if system == "Windows":
        edition = platform_mod.win32_edition() or ""
        return "windows-server" if "Server" in edition else "windows-laptop"
    if system == "Linux":
        try:
            model = Path(model_path).read_bytes().decode("utf-8", "ignore")
        except OSError:
            model = ""
        if "Raspberry Pi" in model:
            return "pi"
    return "linux"
