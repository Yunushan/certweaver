#!/usr/bin/env python3
"""Verify that a release tag and built artifacts agree with project metadata."""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--dist", default="dist")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    expected_tag = f"v{version}"
    if args.tag != expected_tag:
        print(
            f"Release tag {args.tag!r} does not match project version {expected_tag!r}",
            file=sys.stderr,
        )
        return 1

    dist = root / args.dist
    expected = {
        f"certweaver-{version}-py3-none-any.whl",
        f"certweaver-{version}.tar.gz",
    }
    actual = {path.name for path in dist.iterdir() if path.is_file()}
    missing = sorted(expected - actual)
    if missing:
        print(f"Missing release artifacts: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(f"Release metadata and artifacts verified for {expected_tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
