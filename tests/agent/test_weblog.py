from __future__ import annotations

from devmon.agent.collectors import weblog


def line(request, ip="203.0.113.9"):
    return '%s - - [10/Nov/2026:10:00:00 +0000] "%s" 200 123 "-" "ua"' % (ip, request)


def test_benign_requests_ignored():
    for req in ("GET /index.html HTTP/1.1", "GET /app?id=42&page=2 HTTP/1.1",
                "POST /login HTTP/1.1", "GET /search?q=hello+world HTTP/1.1"):
        assert weblog.parse_access(line(req), 1.0) == []


def test_sqli_union_detected_decoded():
    evs = weblog.parse_access(line("GET /p?id=1%20UNION%20SELECT%20pw%20FROM%20u HTTP/1.1"), 5.0)
    assert len(evs) == 1
    e = evs[0]
    assert e["kind"] == "web_attack" and e["source"] == "web"
    assert e["ip"] == "203.0.113.9" and e["method"] == "GET"
    assert e["rule"].startswith("sqli") and e["score"] >= 0.9


def test_sqli_tautology_detected():
    evs = weblog.parse_access(line("GET /login?user=admin'%20OR%20'1'='1 HTTP/1.1"), 5.0)
    assert evs and evs[0]["rule"].startswith("sqli")


def test_xss_script_tag_detected():
    evs = weblog.parse_access(line("GET /q?s=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1"), 5.0)
    assert evs and evs[0]["rule"].startswith("xss") and evs[0]["score"] >= 0.9


def test_classify_picks_highest_score():
    # contains both an alert() (0.6) and a <script> (0.95); the higher wins
    hit = weblog.classify("<script>alert(1)</script>")
    assert hit == ("xss:script-tag", 0.95)


def test_unparseable_line_is_safe():
    assert weblog.parse_access("garbage with no request", 1.0) == []
    assert weblog.parse_access("", 1.0) == []


def test_path_and_rule_truncated():
    long_path = "/x?q=" + "A" * 1000 + "<script>"
    evs = weblog.parse_access(line("GET %s HTTP/1.1" % long_path), 1.0)
    assert evs and len(evs[0]["path"]) <= weblog.MAX_PATH


def test_compact_keeps_highest_web_score():
    from devmon.agent.collectors.events import compact
    low = weblog.web_event(1.0, "203.0.113.9", "GET", "/a", "xss:alert", 0.6)
    high = weblog.web_event(2.0, "203.0.113.9", "GET", "/b", "sqli:union-select", 0.97)
    merged = compact([low, high])
    assert len(merged) == 1
    e = merged[0]
    assert e["count"] == 2 and e["score"] == 0.97 and e["rule"] == "sqli:union-select"
    assert e["ts"] == 1.0  # earliest time kept
