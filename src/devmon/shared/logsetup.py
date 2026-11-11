from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup_logging(log_file: Optional[Path] = None) -> None:
    """Log to stderr (systemd journal), or to a size-capped file where nothing captures stderr
    (Windows Task Scheduler, pythonw)."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    if log_file is None:
        handler: logging.Handler = logging.StreamHandler(sys.stderr)
    else:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            str(log_file), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        # Under pythonw there is no console: send stray prints and tracebacks to the log too.
        if sys.stderr is None or sys.stdout is None:
            stream = open(str(log_file) + ".console", "a", encoding="utf-8", buffering=1)
            sys.stderr = sys.stderr or stream
            sys.stdout = sys.stdout or stream
    handler.setFormatter(logging.Formatter(FORMAT))
    root.addHandler(handler)
