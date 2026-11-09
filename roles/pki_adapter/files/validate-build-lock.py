"""Validate a static, hash-locked application build profile without evaluating it."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REQUIREMENT = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?"
    r"==[A-Za-z0-9][A-Za-z0-9_.+!-]*"
    r"(?:\s+--hash=sha256:[a-f0-9]{64})+"
)


def validate(path: Path) -> None:
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Build dependency lock exceeds size limit")
    lines = raw.decode("utf-8").replace("\\\r\n", " ").replace("\\\n", " ").splitlines()
    names = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT.fullmatch(line)
        if not match:
            raise ValueError(
                "Build lock requires exact versions and sha256 hashes; "
                "options/URLs/includes are forbidden"
            )
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in names:
            raise ValueError("Duplicate build dependency")
        names.add(name)
    if not {"pip", "setuptools", "wheel"} <= names:
        raise ValueError("Build lock must include pip, setuptools and wheel")


if __name__ == "__main__":
    try:
        validate(Path(sys.argv[1]))
    except (IndexError, OSError, UnicodeError, ValueError) as error:
        print(type(error).__name__ + ": invalid application dependency lock", file=sys.stderr)
        raise SystemExit(1) from None
