#!/usr/bin/env python3
"""Run on a Pi. Lets the hub's /demo page take this Pi offline (or bring it back) with a
button, instead of an SSH session, so the cloud-failover story can be demoed live.

Polls the hub's /api/demo/pending like any agent would (the hub cannot reach a Pi behind a
NAT or hotspot), restricted to pi_down/pi_recover only (`scenarios=` filter) so this can
never be handed one of Kali-agent's attack-tool requests from the same shared queue. Only
acts when the request names *this* Pi's own device_id, matched by hostname.

Stopping/starting its own windpulse-agent service needs root; rather than run this whole
poller as root, grant NOPASSWD sudo for just those two exact commands (see the setup note
in the sudoers snippet below) so the blast radius of this script running on an internet-
facing poll loop is "can toggle one named service," nothing more.

  python3 demo-poll.py --hub-url https://sxmukelo.co.za --api-key <key> [--unit windpulse-agent]
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

SCENARIOS = ("pi_down", "pi_recover")


def _request(url: str, api_key: str, method: str = "GET", body: dict = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "X-Api-Key": api_key, "X-Kali-Id": socket.gethostname()[:60],
        "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def run(unit: str, action: str) -> str:
    cmd = ["sudo", "-n", "systemctl", "stop" if action == "pi_down" else "start", unit]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if proc.returncode != 0:
        return ((proc.stderr or proc.stdout or "systemctl failed").strip())[:300]
    return "ok: %s %s" % (unit, "stopped" if action == "pi_down" else "started")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub-url", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--unit", default="windpulse-agent")
    ap.add_argument("--poll-s", type=float, default=4.0)
    args = ap.parse_args()
    hub_url = args.hub_url.rstrip("/")
    host = socket.gethostname()

    print("demo-poll: watching %s every %gs as %s (unit: %s)"
          % (hub_url, args.poll_s, host, args.unit))
    while True:
        try:
            resp = _request("%s/api/demo/pending?scenarios=%s" % (hub_url, ",".join(SCENARIOS)),
                            args.api_key)
            pending = resp.get("pending")
            if pending is None:
                time.sleep(args.poll_s)
                continue
            # The hub names the device by its own display_name; only act if it matches us.
            # (A device's display_name is usually its reported hostname, same as here.)
            if (pending.get("target_name") or "").split(".")[0] != host.split(".")[0]:
                result = "not for this device (%s); ignored" % pending.get("target_name")
            else:
                result = run(args.unit, pending["scenario"])
            print("[%s] %s -> %s" % (time.strftime("%H:%M:%S"), pending["scenario"], result))
            _request("%s/api/demo/done" % hub_url, args.api_key, method="POST",
                     body={"id": pending["id"], "result": result})
        except urllib.error.URLError as exc:
            print("poll failed: %s" % exc, file=sys.stderr)
        except KeyboardInterrupt:
            print("\nstopped.")
            return 0
        except Exception as exc:  # a bad response must not kill the loop mid-demo
            print("unexpected error: %s" % exc, file=sys.stderr)
        time.sleep(args.poll_s)


if __name__ == "__main__":
    sys.exit(main())
