"""Address rules shared by the hub and the agents (the agents decide alone when the hub is
unreachable, so both must agree on what "internal" and "trusted" mean)."""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable, List, Optional

# Explicit ranges: Python's is_private also counts documentation and reserved ranges.
INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",  # private, CGNAT
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")]


def parse_ip(text: Optional[str]) -> Optional[Any]:
    """The address, with IPv4-mapped IPv6 turned into IPv4; None if it isn't one."""
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr


def in_networks(ip: str, nets: Iterable[Any]) -> bool:
    addr = parse_ip(ip)
    return addr is not None and any(addr.version == n.version and addr in n for n in nets)


def is_internal(ip: str) -> bool:
    return in_networks(ip, INTERNAL)


def networks(entries: Iterable[str]) -> List[Any]:
    out = []
    for entry in entries:
        try:
            out.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return out
