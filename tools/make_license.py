#!/usr/bin/env python3
"""Create a signed licence file for Community Scam Map.

Usage:
  python tools/make_license.py --licensee "Demo Bank" --minutes 5
  python tools/make_license.py --licensee "Demo Bank" --until 2027-01-31T23:59:59+05:30
  python tools/make_license.py --licensee "Demo Bank" --minutes 5 --key ~/smashers_keys/license.key

Prints the signed JSON to stdout. Redirect to a file:
  python tools/make_license.py --licensee "Demo Bank" --minutes 5 > lic5.json
"""
import argparse
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl.signing import SigningKey

IST = timezone(timedelta(hours=5, minutes=30))


def main():
    parser = argparse.ArgumentParser(description="Mint a signed licence file")
    parser.add_argument("--licensee", required=True, help="Licensee name")
    parser.add_argument("--minutes", type=int, help="Minutes from now until expiry")
    parser.add_argument("--until", type=str, help="Expiry as ISO 8601 datetime")
    default_key = Path.home() / "smashers_keys" / "license.key"
    parser.add_argument("--key", type=Path, default=default_key,
                        help=f"Path to private key (default: {default_key})")
    args = parser.parse_args()

    if not args.minutes and not args.until:
        parser.error("Specify --minutes or --until")
    if args.minutes and args.until:
        parser.error("Specify only one of --minutes or --until")

    # Load private key
    if not args.key.exists():
        print(f"Private key not found at {args.key}", file=sys.stderr)
        print("Run tools/gen_keys.py first.", file=sys.stderr)
        sys.exit(1)

    sk = SigningKey(args.key.read_bytes())

    # Compute expiry
    if args.minutes:
        expires_at = datetime.now(IST) + timedelta(minutes=args.minutes)
    else:
        expires_at = datetime.fromisoformat(args.until)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=IST)

    expires_at_str = expires_at.isoformat()

    # Sign: message = licensee + \n + expires_at (exact strings)
    message = (args.licensee + "\n" + expires_at_str).encode("utf-8")
    signed = sk.sign(message)
    signature_b64 = base64.b64encode(signed.signature).decode()

    licence = {
        "licensee": args.licensee,
        "expires_at": expires_at_str,
        "signature": signature_b64,
    }

    print(json.dumps(licence, indent=2))


if __name__ == "__main__":
    main()
