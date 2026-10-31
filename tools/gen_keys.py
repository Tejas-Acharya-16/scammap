#!/usr/bin/env python3
"""Generate an Ed25519 keypair for licence signing.

Writes the PRIVATE key to a file OUTSIDE the repo (default ~/smashers_keys/license.key).
Prints the PUBLIC key (base64) to paste into app/license.py.

Usage: python tools/gen_keys.py [--out PATH]
"""
import argparse
import base64
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 licence keypair")
    default_dir = Path.home() / "smashers_keys"
    parser.add_argument("--out", type=Path, default=default_dir / "license.key",
                        help=f"Path for the private key (default: {default_dir / 'license.key'})")
    args = parser.parse_args()

    key_path: Path = args.out
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        print(f"Key already exists at {key_path}", file=sys.stderr)
        print("Reading existing key to show the public key.", file=sys.stderr)
        raw = key_path.read_bytes()
        sk = SigningKey(raw)
    else:
        sk = SigningKey.generate()
        key_path.write_bytes(bytes(sk))
        # Restrictive permissions (best effort on Windows)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        print(f"Private key written to: {key_path}", file=sys.stderr)

    vk = sk.verify_key
    pub_b64 = base64.b64encode(bytes(vk)).decode()
    print(f"\nPublic key (base64, paste into app/license.py):\n{pub_b64}")
    print(f"\nPython constant:\nLICENSE_PUBLIC_KEY_B64 = \"{pub_b64}\"")


if __name__ == "__main__":
    main()
