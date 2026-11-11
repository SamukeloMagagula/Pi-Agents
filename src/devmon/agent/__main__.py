from __future__ import annotations

import argparse
import asyncio
import functools
import platform
import sys
from pathlib import Path
from typing import List, Optional

from devmon.agent.collectors.events import EventCollector, build_sources
from devmon.agent.collectors.ports import collect_ports
from devmon.agent.collectors.security import (
    UpdatesCache, collect_packages, collect_security, default_helper_file,
)
from devmon.agent.config import load_config
from devmon.agent.gossip import Gossip, load_key
from devmon.agent.healing import FixerLink
from devmon.agent.runner import run_agent
from devmon.shared.keys import fingerprint, load_or_create_static_key
from devmon.shared.logsetup import setup_logging


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m devmon.agent",
                                     description="devmon monitoring agent")
    parser.add_argument("--config", required=True, type=Path, help="path to the agent .ini file")
    parser.add_argument("--show-fingerprint", action="store_true",
                        help="print this agent's key fingerprint and exit")
    parser.add_argument("--log-file", type=Path,
                        help="log to this file (rotated at 1 MB) instead of stderr")
    args = parser.parse_args(argv)

    # stderr is what the systemd journal captures; Windows passes --log-file.
    setup_logging(args.log_file)
    try:
        cfg = load_config(args.config)
    except ValueError as exc:
        print("devmon agent: %s" % exc, file=sys.stderr)
        return 2

    try:
        _, pub = load_or_create_static_key(cfg.key_path)
    except (ValueError, OSError) as exc:
        print("devmon agent: %s" % exc, file=sys.stderr)
        return 2
    if args.show_fingerprint:
        print(fingerprint(pub))
        return 0

    collect_db = None
    if cfg.mariadb is not None:
        # Imported only when configured, so devices without MariaDB never load PyMySQL.
        from devmon.agent.collectors.mariadb import collect_mariadb
        collect_db = functools.partial(collect_mariadb, cfg.mariadb)
    try:
        security = functools.partial(
            collect_security, cfg.helper_file or default_helper_file(),
            # Windows Update is counted by the helper; apt/dnf by the agent itself.
            UpdatesCache() if platform.system() == "Linux" else None)
        collect_events = None
        if cfg.events.enabled:
            collect_events = EventCollector(build_sources(cfg, platform.system())).collect
        fixer = FixerLink(cfg.fixer_socket) if cfg.fixer_socket else None
        gossip = None
        if cfg.gossip_enabled:
            gossip = Gossip(load_key(cfg.state_dir / "gossip.key"), cfg.gossip_port)
        asyncio.run(run_agent(cfg, collect_db=collect_db, collect_ports=collect_ports,
                              collect_security=security, collect_packages=collect_packages,
                              collect_events=collect_events, fixer=fixer,
                              policy_path=cfg.state_dir / "policy.json", gossip=gossip))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
