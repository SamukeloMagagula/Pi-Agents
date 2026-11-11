#!/usr/bin/env python3
"""WindPulse secure vault — authenticated encryption for data at rest.

The key is generated and kept on the HUB, never on the Pi. A Pi holds only ciphertext,
so an attacker who gains a shell on a Pi (Scenario 1/3) cannot read the sensitive data:
decryption fails without the key, which lives off the device.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` library, which is already
installed on the hub and the agents. Standard library otherwise, Python 3.9+.

    vault.py gen-key   vault.key                      # on the hub only
    vault.py encrypt --key vault.key  secret.csv  secret.enc
    vault.py decrypt --key vault.key  secret.enc  [secret.out]   # omit out -> stdout
"""
from __future__ import annotations

import argparse
import os
import sys

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    sys.exit("vault: needs the 'cryptography' package (pip install cryptography)")


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vault.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="create a new vault key (keep this on the hub)")
    g.add_argument("out", help="path to write the key to")

    e = sub.add_parser("encrypt", help="encrypt a file")
    e.add_argument("--key", required=True)
    e.add_argument("infile")
    e.add_argument("outfile")

    d = sub.add_parser("decrypt", help="decrypt a file (fails without the right key)")
    d.add_argument("--key", required=True)
    d.add_argument("infile")
    d.add_argument("outfile", nargs="?", help="omit to write plaintext to stdout")

    args = ap.parse_args(argv)

    if args.cmd == "gen-key":
        if os.path.exists(args.out):
            sys.exit("vault: refusing to overwrite existing key %s" % args.out)
        with open(args.out, "wb") as f:
            f.write(Fernet.generate_key())
        try:
            os.chmod(args.out, 0o600)
        except OSError:
            pass
        print("vault: key written to %s  (keep it on the hub, never on a Pi)" % args.out)
        return 0

    try:
        fernet = Fernet(_read(args.key).strip())
    except (ValueError, OSError) as exc:
        sys.exit("vault: bad or missing key (%s)" % exc)

    if args.cmd == "encrypt":
        token = fernet.encrypt(_read(args.infile))
        with open(args.outfile, "wb") as f:
            f.write(token)
        print("vault: encrypted %s -> %s (%d bytes ciphertext)" % (
            args.infile, args.outfile, len(token)))
        return 0

    # decrypt
    try:
        plain = fernet.decrypt(_read(args.infile))
    except InvalidToken:
        sys.exit("vault: DECRYPT FAILED — wrong key or tampered data. The data stays protected.")
    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(plain)
        print("vault: decrypted %s -> %s" % (args.infile, args.outfile))
    else:
        sys.stdout.buffer.write(plain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
