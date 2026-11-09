"""Read-only production snapshot-input validation shared by CLI and Ansible."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_CONFIG_BYTES = 1024 * 1024
# kubectl's bufio scanner needs space for the line terminator as well.
MAX_ENV_LINE_BYTES = 64 * 1024 - 1


class SnapshotConfigurationError(ValueError):
    """A fixed diagnostic that never includes credential contents."""


def transport_issues(content: str) -> list[str]:
    """Validate literal kubectl env-file input and TLS-verifying transport."""
    issues = []
    seen = set()
    for number, raw in enumerate(content.split("\n"), 1):
        if len(raw.encode("utf-8")) > MAX_ENV_LINE_BYTES:
            issues.append(
                f"RKE2 S3 configuration line exceeds the kubectl env-file limit (line {number})"
            )
            continue
        line = raw.removesuffix("\r")
        if number == 1:
            line = line.removeprefix("\ufeff")
        line = line.lstrip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[-._a-zA-Z][-._a-zA-Z0-9]*", key):
            issues.append(
                f"Production RKE2 S3 configuration requires explicit key=value entries "
                f"with valid names (line {number})"
            )
            continue
        if key in seen:
            issues.append(f"RKE2 S3 configuration contains duplicate keys (line {number})")
            continue
        seen.add(key)
        if key in {"etcd-s3-insecure", "etcd-s3-skip-ssl-verify"} and value not in {
            "false",
            "False",
            "FALSE",
            "0",
            "f",
            "F",
        }:
            issues.append(f"Production RKE2 S3 configuration requires {key}=false")
    if not seen:
        issues.append("Production RKE2 S3 configuration must contain explicit key=value entries")
    return issues


def validate_file(path: str | Path) -> dict[str, str | int]:
    """Return only digests and size for the exact bounded, validated bytes."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise SnapshotConfigurationError("RKE2 S3 configuration must be a regular file")
        content = source.read(MAX_CONFIG_BYTES + 1)
    if not content:
        raise SnapshotConfigurationError(
            "RKE2 S3 snapshot configuration secret file must not be empty"
        )
    if len(content) > MAX_CONFIG_BYTES:
        raise SnapshotConfigurationError("RKE2 S3 configuration exceeds the 1 MiB limit")
    issues = transport_issues(content.decode("utf-8"))
    if issues:
        raise SnapshotConfigurationError("\n".join(issues))
    return {
        "schemaVersion": 1,
        "status": "PRODUCTION_SNAPSHOT_INPUT_VALIDATED",
        "sha256": hashlib.sha256(content).hexdigest(),
        # Ansible copy accepts a SHA-1 transfer checksum; publication additionally
        # requires the stronger SHA-256 and byte-count postcondition.
        "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        "bytes": len(content),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate production RKE2 S3 input privately")
    parser.add_argument("file")
    args = parser.parse_args(argv)
    try:
        receipt = validate_file(args.file)
    except (OSError, UnicodeError, SnapshotConfigurationError):
        print("Production RKE2 S3 input validation failed", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
