from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

import psutil

log = logging.getLogger(__name__)


def _process_name(pid: Optional[int]) -> Optional[str]:
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.Error, OSError):
        # A non-root agent cannot see other users' processes; the port is still reported.
        return None


def collect_ports(
    net_connections: Callable[..., Any] = psutil.net_connections,
    process_name: Callable[[Optional[int]], Optional[str]] = _process_name,
) -> Dict[str, Any]:
    """The TCP ports this device listens on, one entry per port (IPv4 and IPv6 merged)."""
    by_port: Dict[int, Dict[str, Any]] = {}
    names: Dict[Optional[int], Optional[str]] = {}
    for conn in net_connections(kind="tcp"):
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        ip, port = conn.laddr[0], conn.laddr[1]
        entry = by_port.setdefault(port, {"proto": "tcp", "port": port,
                                          "addresses": [], "process": None})
        if ip not in entry["addresses"]:
            entry["addresses"].append(ip)
        if entry["process"] is None:
            if conn.pid not in names:
                names[conn.pid] = process_name(conn.pid)
            entry["process"] = names[conn.pid]
    ports: List[Dict[str, Any]] = []
    for port in sorted(by_port):
        entry = by_port[port]
        entry["addresses"].sort()
        ports.append(entry)
    return {"type": "ports", "ports": ports}
