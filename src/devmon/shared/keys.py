from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def public_from_private(priv: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(priv)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _create_key_file(path: Path) -> None:
    """Write a new key so that a power cut leaves either no key or a whole one."""
    priv = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    # Temp files left by a power cut hold a key that was never used: remove them.
    for old in path.parent.glob(path.name + ".*.tmp"):
        try:
            old.unlink()
        except OSError:
            pass
    # mkstemp: a random name opened with O_EXCL and mode 0o600, so the key is never
    # briefly world-readable (POSIX; Windows ACLs come from the folder the installer
    # locks down) and a leftover name can never block the start.
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(priv)
            f.flush()
            os.fsync(f.fileno())
        try:
            # A hard link never overwrites: if another process made a key meanwhile, keep it.
            os.link(str(tmp), str(path))
        except FileExistsError:
            pass
        except OSError:
            # File systems without hard links (e.g. FAT): replace, but only if still absent.
            if not path.exists():
                os.replace(str(tmp), str(path))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass


def load_or_create_static_key(path: Path) -> Tuple[bytes, bytes]:
    """Return (private32, public32); create the key file on first use.

    Raises ValueError with a plain reason if the file exists but isn't a key.
    """
    path = Path(path)
    try:
        size: Optional[int] = path.stat().st_size
    except FileNotFoundError:
        size = None
    if size == 0:
        # Left by a power cut while an older version was creating it. An empty file was
        # never a key, so no device or hub can have been told its fingerprint.
        path.unlink()
        size = None
    if size is None:
        _create_key_file(path)
    try:
        priv = path.read_bytes()
    except OSError as exc:
        raise ValueError("cannot read the key file %s: %s" % (path, exc.strerror or exc))
    if len(priv) != 32:
        raise ValueError(
            "%s is damaged (%d bytes, a key has 32). Move it aside and start again; "
            "the new key will need approving again." % (path, len(priv)))
    return priv, public_from_private(priv)


def fingerprint(pub: bytes) -> str:
    """First 128 bits of SHA-256 of the public key, as 8 groups of 4 hex digits."""
    digest = hashlib.sha256(pub).hexdigest()[:32].upper()
    return "-".join(digest[i : i + 4] for i in range(0, 32, 4))


def normalize_fingerprint(text: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", text).upper()
