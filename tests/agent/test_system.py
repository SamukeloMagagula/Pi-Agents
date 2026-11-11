from __future__ import annotations

from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace

from devmon.agent.collectors.system import (
    collect_fast, collect_slow, detect_device_kind, read_temperature,
)

Part = namedtuple("Part", "mountpoint fstype")
GB = 1024 ** 3
LINUX = SimpleNamespace(system=lambda: "Linux")


class FakePsutil:
    def __init__(self, sensors="missing", partitions=None, usage=None):
        if sensors != "missing":
            self._sensors = sensors
            self.sensors_temperatures = lambda: self._sensors
        self._partitions = partitions or []
        self._usage = usage or {}

    def cpu_percent(self, interval=None):
        return 12.5

    def cpu_count(self, logical=True):
        return 4

    def virtual_memory(self):
        return SimpleNamespace(percent=40.0)

    def swap_memory(self):
        return SimpleNamespace(percent=5.0)

    def net_io_counters(self):
        return SimpleNamespace(bytes_sent=10, bytes_recv=20)

    def disk_partitions(self, all=False):
        return self._partitions

    def disk_usage(self, mount):
        value = self._usage[mount]
        if isinstance(value, Exception):
            raise value
        return value

    def boot_time(self):
        return 900.0


def _failing_vcgencmd():
    return None


def _reading(v):
    return [SimpleNamespace(current=v)]


def test_collect_fast_values():
    out = collect_fast(FakePsutil(), load1=lambda: 0.5, temperature=lambda: None)
    assert out["cpu"] == {"percent": 12.5, "cores": 4, "load1": 0.5}
    assert out["mem"] == {"percent": 40.0, "swap_percent": 5.0}
    assert out["net"] == {"bytes_sent": 10, "bytes_recv": 20}
    assert out["temp_c"] is None


def test_temp_none_when_sensors_missing():
    assert read_temperature(FakePsutil(), _failing_vcgencmd, platform_mod=LINUX) is None


def test_temp_none_when_sensors_empty():
    ps = FakePsutil(sensors={})
    assert read_temperature(ps, _failing_vcgencmd, platform_mod=LINUX) is None


def test_temp_prefers_cpu_thermal_then_coretemp():
    both = FakePsutil(sensors={"coretemp": _reading(55.0), "cpu_thermal": _reading(48.0)})
    assert read_temperature(both, _failing_vcgencmd, platform_mod=LINUX) == 48.0
    core = FakePsutil(sensors={"other": _reading(30.0), "coretemp": _reading(55.0)})
    assert read_temperature(core, _failing_vcgencmd, platform_mod=LINUX) == 55.0


def test_temp_falls_back_to_vcgencmd():
    assert read_temperature(FakePsutil(), lambda: "temp=48.3'C\n", platform_mod=LINUX) == 48.3


def test_temp_none_on_windows():
    win = SimpleNamespace(system=lambda: "Windows")
    ps = FakePsutil(sensors={"coretemp": _reading(55.0)})
    assert read_temperature(ps, lambda: "temp=48.3'C", platform_mod=win) is None


def test_disks_skip_pseudo_and_failing():
    ps = FakePsutil(
        partitions=[
            Part("/", "ext4"), Part("/snap/core", "squashfs"), Part("/run", "tmpfs"),
            Part("/dev", "devtmpfs"), Part("/var/lib/docker", "overlay"),
            Part("/", "ext4"), Part("E:\\", "ext4"),
        ],
        usage={
            "/": SimpleNamespace(percent=63.0, total=100 * GB, used=63 * GB),
            "E:\\": OSError("not ready"),
        },
    )
    out = collect_slow(ps, clock=lambda: 1000.0)
    assert out["disks"] == [
        {"mount": "/", "percent": 63.0, "total_gb": 100.0, "used_gb": 63.0}
    ]
    assert out["uptime_s"] == 100.0


def _plat(system, edition=""):
    return SimpleNamespace(system=lambda: system, win32_edition=lambda: edition)


def test_kind_pi(tmp_path):
    model = tmp_path / "model"
    model.write_bytes(b"Raspberry Pi 4 Model B\x00")
    assert detect_device_kind(_plat("Linux"), model) == "pi"


def test_kind_linux_without_model(tmp_path):
    assert detect_device_kind(_plat("Linux"), tmp_path / "absent") == "linux"


def test_kind_windows():
    missing = Path("nope")
    assert detect_device_kind(_plat("Windows", "ServerStandard"), missing) == "windows-server"
    assert detect_device_kind(_plat("Windows", "Professional"), missing) == "windows-laptop"
