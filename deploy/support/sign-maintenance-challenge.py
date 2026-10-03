#!/usr/bin/env python3
"""Sign one MoonShield maintenance challenge using an externally-held RSA key."""

import argparse
import base64
from pathlib import Path
import re
import subprocess
import sys


REPOSITORY = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", required=True, type=Path,
                        help="RSA private key stored outside the repository")
    parser.add_argument("--challenge", required=True,
                        help="exact challenge string displayed by the appliance")
    args = parser.parse_args()

    try:
        key_path = args.private_key.expanduser().resolve(strict=True)
        if REPOSITORY == key_path or REPOSITORY in key_path.parents:
            parser.error("private key must be stored outside the repository")
        if not key_path.is_file():
            parser.error("private key path is not a regular file")
        if not re.fullmatch(r"MOONSHIELD-MAINT-V1\|[0-9a-f]{16}\|[0-9a-f]{64}", args.challenge):
            parser.error("challenge format is invalid or unsupported")
        modulus = subprocess.run(
            ["openssl", "rsa", "-in", str(key_path), "-noout", "-modulus"],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        match = re.fullmatch(r"Modulus=([0-9A-Fa-f]+)", modulus)
        if not match or int(match.group(1), 16).bit_length() < 3072:
            parser.error("maintenance signer requires RSA private key of at least 3072 bits")
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=args.challenge.encode("utf-8"), check=True,
            capture_output=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        print(f"signing failed: {error.__class__.__name__}", file=sys.stderr)
        return 1
    print(base64.b64encode(signed).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
