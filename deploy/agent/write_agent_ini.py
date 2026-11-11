"""Write or update agent.ini for the install scripts.

Re-running an install only replaces the hub address, port, fingerprint, key path and
device kind; anything else already in the file (such as a [mariadb] section) is kept.
Runs on Python 3.9+ with the standard library only.
"""
from __future__ import annotations

import argparse
import configparser
import os
import re
import sys

HEADER = """\
# devmon agent settings. Written by the install script; safe to edit.
# To also monitor MariaDB on this machine, add:
# [mariadb]
# host = 127.0.0.1
# port = 3306
# user = devmon_monitor
# password = CHANGE-ME
# instance = main-db
# exclude_schemas = test, scratch

"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--path", required=True)
    p.add_argument("--hub", required=True)
    p.add_argument("--port", type=int, default=55555)
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--key-path", required=True)
    p.add_argument("--kind", default="")
    a = p.parse_args(argv)

    if len(re.sub(r"[^0-9A-Fa-f]", "", a.fingerprint)) != 32:
        print("The fingerprint should be 32 hex digits, like the one on the hub's "
              "Add device page.", file=sys.stderr)
        return 2
    if not 0 < a.port < 65536:
        print("The port must be between 1 and 65535.", file=sys.stderr)
        return 2

    cfg = configparser.ConfigParser(interpolation=None)
    if os.path.exists(a.path):
        cfg.read(a.path, encoding="utf-8")
    for section in ("hub", "agent"):
        if not cfg.has_section(section):
            cfg.add_section(section)
    cfg.set("hub", "host", a.hub)
    cfg.set("hub", "port", str(a.port))
    cfg.set("hub", "fingerprint", a.fingerprint.strip())
    cfg.set("agent", "key_path", a.key_path)
    cfg.set("agent", "device_kind", a.kind)

    tmp = a.path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(HEADER)
        cfg.write(f)
    os.replace(tmp, a.path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
