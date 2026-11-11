"""Web-application attack detection from the web server's access log (Phase 9).

Tails an nginx/apache *combined* access log and flags requests that carry SQL-injection or
cross-site-scripting payloads, using a signature set. Each flagged request becomes a
`web_attack` event carrying the client IP, method, path, the rule that matched and a
confidence score; the hub correlates these into a web-attack incident.

Signatures only (standard library, Python 3.9+), so it is light enough for a Pi. The classifier
is deliberately conservative: it scores obvious attack strings high and leaves ordinary traffic
alone. It is a detector, not a WAF — it never blocks a request itself.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

MAX_PATH = 512
MAX_RULE = 64

# Each rule: a compiled pattern, a short name, and a confidence score in [0, 1].
# Scores >= 0.9 open an incident on a single hit (hub WEB_SCORE_HIGH); lower scores need
# several hits in the window.
_RULES: List[Tuple["re.Pattern[str]", str, float]] = [
    (re.compile(r"\bunion\b[\s\S]{0,40}\bselect\b", re.I), "sqli:union-select", 0.97),
    (re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I), "sqli:time", 0.95),
    (re.compile(r"\binformation_schema\b", re.I), "sqli:schema", 0.95),
    (re.compile(r"\bselect\b[\s\S]{0,80}\bfrom\b", re.I), "sqli:select-from", 0.9),
    (re.compile(r"'\s*or\s*'?\d+'?\s*=\s*'?\d+", re.I), "sqli:tautology", 0.9),
    (re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.I), "sqli:tautology", 0.9),
    (re.compile(r"\b(drop|truncate)\b\s+\btable\b", re.I), "sqli:ddl", 0.9),
    (re.compile(r"<\s*script\b", re.I), "xss:script-tag", 0.95),
    (re.compile(r"on(error|load|mouseover|focus)\s*=", re.I), "xss:event-handler", 0.9),
    (re.compile(r"<\s*(svg|img|iframe|body)\b[^>]*\bon\w+\s*=", re.I), "xss:tag-handler", 0.9),
    (re.compile(r"javascript:\s*\w", re.I), "xss:js-uri", 0.7),
    (re.compile(r"\balert\s*\(", re.I), "xss:alert", 0.6),
]

# combined log line: IP ... "METHOD path HTTP/x.y" status size "referer" "ua"
_REQUEST = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]+)\s+HTTP/[0-9.]+"')


def classify(text: str) -> Optional[Tuple[str, float]]:
    """The highest-scoring rule that matches `text`, or None. `text` should be URL-decoded."""
    best: Optional[Tuple[str, float]] = None
    for pattern, name, score in _RULES:
        if pattern.search(text) and (best is None or score > best[1]):
            best = (name, score)
    return best


def _client_ip(line: str) -> Optional[str]:
    from devmon.agent.collectors.events import clean_ip
    token = line.split(" ", 1)[0] if line else ""
    return clean_ip(token)


def web_event(ts: float, ip: Optional[str], method: str, path: str, rule: str,
              score: float) -> Dict[str, Any]:
    return {"ts": ts, "kind": "web_attack", "source": "web", "ip": ip, "user": None,
            "port": None, "count": 1, "method": method[:16], "path": path[:MAX_PATH],
            "rule": rule[:MAX_RULE], "score": score}


def parse_access(line: str, ts: float) -> List[Dict[str, Any]]:
    """One web_attack event when a request carries an attack payload, else nothing."""
    m = _REQUEST.search(line)
    if not m:
        return []
    method, path = m.group("method"), m.group("path")
    # Decode once so %27/%3C etc. are seen; match on both decoded and raw to catch either.
    decoded = urllib.parse.unquote_plus(path)
    hit = classify(decoded) or classify(path)
    if hit is None:
        return []
    rule, score = hit
    return [web_event(ts, _client_ip(line), method, path, rule, score)]
