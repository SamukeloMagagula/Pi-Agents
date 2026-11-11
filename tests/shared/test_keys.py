from __future__ import annotations

import hashlib
import os
import re
import stat
import textwrap

import pytest

from devmon.shared.keys import (
    fingerprint,
    load_or_create_static_key,
    normalize_fingerprint,
)


def test_creates_then_reloads_same_key(tmp_path):
    p = tmp_path / "k.key"
    a = load_or_create_static_key(p)
    b = load_or_create_static_key(p)
    assert a == b and len(a[0]) == 32 and len(a[1]) == 32


def test_fingerprint_format():
    fp = fingerprint(bytes(32))
    assert re.fullmatch(r"([0-9A-F]{4}-){7}[0-9A-F]{4}", fp)
    assert fp == "-".join(textwrap.wrap(hashlib.sha256(bytes(32)).hexdigest()[:32].upper(), 4))


def test_normalize_accepts_lowercase_spaces_colons():
    fp = fingerprint(bytes(32))
    assert normalize_fingerprint(fp.lower().replace("-", ":")) == normalize_fingerprint(fp)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_key_file_is_owner_only(tmp_path):
    p = tmp_path / "k.key"
    load_or_create_static_key(p)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_empty_key_left_by_a_power_cut_is_replaced(tmp_path):
    p = tmp_path / "k.key"
    p.write_bytes(b"")
    priv, pub = load_or_create_static_key(p)
    assert len(priv) == 32 and p.read_bytes() == priv
    assert [f.name for f in tmp_path.iterdir()] == ["k.key"]  # no temp file left


def test_damaged_key_is_refused_not_replaced(tmp_path):
    p = tmp_path / "k.key"
    p.write_bytes(b"x" * 31)
    with pytest.raises(ValueError, match="damaged .31 bytes"):
        load_or_create_static_key(p)
    assert p.read_bytes() == b"x" * 31


def test_existing_key_is_never_overwritten(tmp_path, monkeypatch):
    # Another process creates the key between our check and our link.
    p = tmp_path / "k.key"
    import devmon.shared.keys as k
    real_link = os.link

    def racing_link(src, dst):
        with open(dst, "wb") as f:
            f.write(b"" * 32)
        return real_link(src, dst)

    monkeypatch.setattr(k.os, "link", racing_link)
    priv, _ = load_or_create_static_key(p)
    assert priv == b"" * 32
    assert [f.name for f in tmp_path.iterdir()] == ["k.key"]


def test_creates_parent_folders(tmp_path):
    p = tmp_path / "a" / "b" / "k.key"
    assert len(load_or_create_static_key(p)[0]) == 32


def test_leftover_temp_files_never_block_and_are_removed(tmp_path):
    p = tmp_path / "k.key"
    (tmp_path / ("k.key.%d.tmp" % os.getpid())).write_bytes(b"x" * 32)
    (tmp_path / "k.key.abc123.tmp").write_bytes(b"y" * 32)
    assert len(load_or_create_static_key(p)[0]) == 32
    assert [f.name for f in tmp_path.iterdir()] == ["k.key"]
