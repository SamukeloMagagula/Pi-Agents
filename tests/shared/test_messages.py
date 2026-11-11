from __future__ import annotations

import copy

import pytest

from devmon.shared.messages import DEVICE_KINDS, InvalidMessage, validate

HELLO = {
    "type": "hello",
    "agent_version": "0.1.0",
    "hostname": "pi-1",
    "os": "linux",
    "os_detail": "Debian 12",
    "device_kind": "pi",
}

METRICS = {
    "type": "metrics",
    "ts": 1700000000.5,
    "cpu": {"percent": 12.5, "cores": 4, "load1": 0.4},
    "mem": {"percent": 40.0, "swap_percent": 0.0},
    "temp_c": 51.2,
    "net": {"bytes_sent": 100, "bytes_recv": 200},
    "disks": [{"mount": "/", "percent": 50.0, "total_gb": 100.0, "used_gb": 50.0}],
    "uptime_s": 1234.0,
}

DB = {
    "type": "db",
    "ts": 1700000000.0,
    "instance": "main",
    "error": None,
    "overview": {"threads": 3},
    "long_running": [],
    "databases": [],
    "replication": None,
}


def test_valid_messages_pass_and_are_returned_unchanged():
    for msg in (HELLO, METRICS, DB,
                {"type": "welcome", "status": "approved"},
                {"type": "welcome", "status": "pending"},
                {"type": "rejected"}):
        original = copy.deepcopy(msg)
        assert validate(msg) is msg
        assert msg == original


def test_metrics_with_optional_fields_none_passes():
    m = copy.deepcopy(METRICS)
    m["cpu"]["load1"] = None
    m["temp_c"] = None
    m["disks"] = None
    m["uptime_s"] = None
    validate(m)


def test_ints_accepted_for_float_fields_and_extra_keys_allowed():
    m = copy.deepcopy(METRICS)
    m["cpu"]["percent"] = 10
    m["future_field"] = "ok"
    validate(m)


def test_all_device_kinds_accepted():
    for kind in DEVICE_KINDS:
        validate(dict(HELLO, device_kind=kind))


def test_missing_type_rejected():
    with pytest.raises(InvalidMessage):
        validate({"hostname": "x"})


def test_unknown_type_rejected():
    with pytest.raises(InvalidMessage):
        validate({"type": "bogus"})


def test_unhashable_type_rejected_cleanly():
    with pytest.raises(InvalidMessage):
        validate({"type": ["hello"]})


def test_non_dict_rejected():
    for bad in (None, [], "hello", 5):
        with pytest.raises(InvalidMessage):
            validate(bad)


def test_wrong_device_kind_rejected():
    with pytest.raises(InvalidMessage):
        validate(dict(HELLO, device_kind="toaster"))


def test_wrong_os_rejected():
    with pytest.raises(InvalidMessage):
        validate(dict(HELLO, os="macos"))


def test_hello_missing_hostname_rejected():
    m = dict(HELLO)
    del m["hostname"]
    with pytest.raises(InvalidMessage, match="hostname"):
        validate(m)


def test_non_numeric_cpu_percent_rejected_naming_field():
    m = copy.deepcopy(METRICS)
    m["cpu"]["percent"] = "high"
    with pytest.raises(InvalidMessage, match=r"metrics\.cpu\.percent must be a number"):
        validate(m)


def test_bool_not_accepted_as_number_or_int():
    m = copy.deepcopy(METRICS)
    m["cpu"]["percent"] = True
    with pytest.raises(InvalidMessage):
        validate(m)
    m = copy.deepcopy(METRICS)
    m["cpu"]["cores"] = True
    with pytest.raises(InvalidMessage):
        validate(m)


def test_float_not_accepted_for_int_field():
    m = copy.deepcopy(METRICS)
    m["net"]["bytes_sent"] = 1.5
    with pytest.raises(InvalidMessage):
        validate(m)


def test_non_dict_sections_raise_invalid_message_not_other_errors():
    for section in ("cpu", "mem", "net"):
        for bad in (None, 5, "x", []):
            m = copy.deepcopy(METRICS)
            m[section] = bad
            with pytest.raises(InvalidMessage):
                validate(m)


def test_disks_must_be_list_of_valid_dicts():
    for bad in ("x", {}, [5], [{"mount": "/"}],
                [{"mount": 1, "percent": 1, "total_gb": 1, "used_gb": 1}],
                [{"mount": "/", "percent": "x", "total_gb": 1, "used_gb": 1}]):
        m = copy.deepcopy(METRICS)
        m["disks"] = bad
        with pytest.raises(InvalidMessage):
            validate(m)


def test_metrics_missing_required_field_rejected():
    m = copy.deepcopy(METRICS)
    del m["temp_c"]
    with pytest.raises(InvalidMessage, match="temp_c"):
        validate(m)


def test_db_top_level_checked():
    for key, bad in (("ts", "x"), ("instance", 1), ("error", 5), ("overview", []),
                     ("long_running", {}), ("databases", None), ("replication", "r")):
        m = copy.deepcopy(DB)
        m[key] = bad
        with pytest.raises(InvalidMessage, match=key):
            validate(m)


def test_db_with_error_string_and_populated_inner_values_passes():
    m = copy.deepcopy(DB)
    m["error"] = "connection refused"
    m["overview"] = None
    m["long_running"] = [{"anything": 1}]
    m["replication"] = {"lag": 0}
    validate(m)


def test_welcome_bad_status_rejected():
    for bad in ("denied", None, 1):
        with pytest.raises(InvalidMessage):
            validate({"type": "welcome", "status": bad})
    with pytest.raises(InvalidMessage):
        validate({"type": "welcome"})


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_refused(bad):
    m = copy.deepcopy(METRICS)
    m["cpu"]["percent"] = bad
    with pytest.raises(InvalidMessage):
        validate(m)
    m = copy.deepcopy(METRICS)
    m["ts"] = bad
    with pytest.raises(InvalidMessage):
        validate(m)


def test_nan_from_the_wire_is_refused():
    import json
    m = json.loads(json.dumps(METRICS).replace("12.5", "NaN"))
    with pytest.raises(InvalidMessage):
        validate(m)


def test_huge_integer_is_still_a_number():
    m = copy.deepcopy(METRICS)
    m["net"]["bytes_sent"] = 10 ** 400
    validate(m)


def test_seq_and_sent_are_optional_but_checked():
    for base in (METRICS, DB):
        validate(dict(copy.deepcopy(base), seq=7, sent=1700.5))
        for bad in ({"seq": 0}, {"seq": 1.5}, {"seq": True}, {"seq": "3"},
                    {"sent": None}, {"sent": "now"}, {"sent": float("nan")}):
            with pytest.raises(InvalidMessage):
                validate(dict(copy.deepcopy(base), **bad))


def test_ack_needs_a_positive_integer_seq():
    assert validate({"type": "ack", "seq": 12}) == {"type": "ack", "seq": 12}
    for bad in ({}, {"seq": 0}, {"seq": -1}, {"seq": 2.0}, {"seq": False}, {"seq": None}):
        with pytest.raises(InvalidMessage):
            validate(dict({"type": "ack"}, **bad))


def _ports(**entry):
    base = {"proto": "tcp", "port": 22, "addresses": ["0.0.0.0"], "process": None}
    base.update(entry)
    return {"type": "ports", "ts": 1.0, "ports": [base]}


def test_ports_message():
    validate(_ports())
    validate(_ports(process="sshd"))
    validate({"type": "ports", "ts": 1.0, "ports": [], "seq": 3, "sent": 2.0})
    for bad in ({"port": 0}, {"port": 70000}, {"port": "22"}, {"proto": "udp"},
                {"addresses": "0.0.0.0"}, {"addresses": [1]}, {"process": 5}):
        with pytest.raises(InvalidMessage):
            validate(_ports(**bad))
    with pytest.raises(InvalidMessage):
        validate({"type": "ports", "ts": 1.0, "ports": ["x"]})


def _events(**entry):
    base = {"ts": 1.0, "kind": "auth_fail", "source": "ssh", "ip": "203.0.113.9",
            "user": "root", "port": None, "count": 1}
    base.update(entry)
    return {"type": "events", "ts": 2.0, "events": [base], "sources": None}


def test_events_message():
    validate(_events())
    validate(_events(kind="fw_drop", source="firewall", user=None, port=3389, count=40))
    validate(_events(ip=None, source="dbadmin"))
    validate({"type": "events", "ts": 1.0, "events": [], "seq": 2, "sent": 3.0,
              "sources": {"System journal": {"ok": True, "detail": "reading"}}})
    # Web attack events (Phase 9) with the optional path/method/rule/score fields.
    validate(_events(kind="web_attack", source="web", user=None,
                     path="/p?id=1 UNION SELECT pw", method="GET", rule="sqli:union", score=0.97))
    validate(_events(kind="web_attack", source="web", user=None, score=0.5))  # score only
    for bad in ({"kind": "web_attack", "source": "web", "score": 1.5},
                {"kind": "web_attack", "source": "web", "score": -0.1},
                {"kind": "web_attack", "source": "web", "path": "p" * 513},
                {"kind": "web_attack", "source": "web", "score": "high"}):
        with pytest.raises(InvalidMessage):
            validate(_events(**bad))
    for bad in ({"kind": "login"}, {"source": "telnet"}, {"ip": "x" * 65}, {"user": "u" * 129},
                {"port": 70000}, {"port": -1}, {"count": 0}, {"count": 1.5}, {"ts": "now"},
                {"ip": 5}):
        with pytest.raises(InvalidMessage):
            validate(_events(**bad))
    too_many = _events()
    too_many["events"] = too_many["events"] * 2001
    with pytest.raises(InvalidMessage, match="more than 2000"):
        validate(too_many)
    for sources in ({"a": {"ok": "yes", "detail": ""}}, {"a": {"ok": True}},
                    {"a": {"ok": True, "detail": "d" * 301}}, {"a": "fine"},
                    {str(i): {"ok": True, "detail": ""} for i in range(21)}):
        with pytest.raises(InvalidMessage):
            validate(dict(_events(), sources=sources))


# ---- Phase 8 -----------------------------------------------------------------------------

PUB = "ab" * 32


def test_hello_optional_phase8_fields():
    validate({**HELLO, "fixer": True, "gossip_pub": PUB, "gossip_port": 55556})
    for bad in ({"fixer": 1}, {"gossip_pub": "AB" * 32}, {"gossip_pub": "ab"},
                {"gossip_port": 0}):
        with pytest.raises(InvalidMessage):
            validate({**HELLO, **bad})


def test_fix_and_result():
    validate({"type": "fix", "id": 3, "action": "block_ip",
              "params": {"ip": "203.0.113.9", "seconds": 3600}})
    for bad in ({"id": 0}, {"action": "rm_rf"}, {"params": {"x": [1]}},
                {"params": {"k%d" % i: 1 for i in range(9)}}):
        with pytest.raises(InvalidMessage):
            validate({"type": "fix", "id": 3, "action": "reboot", "params": {}, **bad})
    ok = {"type": "fix_result", "ts": 1.0, "seq": 4, "id": 3, "action": "reboot", "ok": True,
          "detail": "rebooting"}
    validate(ok)
    with pytest.raises(InvalidMessage):
        validate({**ok, "detail": "x" * 501})
    with pytest.raises(InvalidMessage):
        validate({**ok, "ok": "yes"})
    local = {**ok, "id": None, "origin": "local", "fault": "disk", "detected": 0.5,
             "params": {}}
    validate(local)
    with pytest.raises(InvalidMessage):
        validate({**local, "origin": "hub"})
    with pytest.raises(InvalidMessage):
        validate({**ok, "id": None})                    # local results say what they fixed


def test_policy_and_peers():
    pol = {"type": "policy", "you": 2, "modes": {"reboot": "suggest", "block_ip_lan": "off"},
           "block_s": 3600, "trusted": ["10.0.0.0/8"], "thresholds": {"disk_red": 90},
           "peers": [{"id": 1, "name": "pi-1", "ip": "192.168.1.5", "port": 55556,
                      "pub": PUB}]}
    validate(pol)
    for bad in ({"modes": {"reboot": "always"}}, {"block_s": 10}, {"you": 0},
                {"thresholds": {"x": "1"}}, {"peers": [{"id": 1}]}):
        with pytest.raises(InvalidMessage):
            validate({**pol, **bad})
    rep = {"type": "peers", "ts": 2.0, "peers": [{"id": 1, "heard_s": 4.5, "hub_ok": True},
                                                 {"id": 3, "heard_s": None, "hub_ok": None}]}
    validate(rep)
    with pytest.raises(InvalidMessage):
        validate({**rep, "peers": [{"id": 1, "heard_s": -1, "hub_ok": None}]})
