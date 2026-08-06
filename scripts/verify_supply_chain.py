#!/usr/bin/env python3
"""Verify repository-level supply-chain invariants before CI or release."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION_RE = re.compile(r"\buses:\s*([^\s#]+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def _workflow_errors() -> list[str]:
    errors: list[str] = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = ACTION_RE.search(line)
            if not match or match.group(1).startswith("./"):
                continue
            action = match.group(1)
            if not SHA_RE.search(action):
                errors.append(
                    f"{path.relative_to(ROOT)}:{line_number}: action is not SHA pinned: {action}"
                )
    return errors


def _dependency_errors() -> list[str]:
    errors: list[str] = []
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    dependencies = [
        *project.get("dependencies", []),
        *project.get("optional-dependencies", {}).get("dev", []),
    ]
    for dependency in dependencies:
        if "<" not in dependency:
            errors.append(f"pyproject.toml: unbounded dependency: {dependency}")

    for line_number, line in enumerate(
        (ROOT / "collections" / "requirements.yml").read_text(encoding="utf-8").splitlines(), 1
    ):
        if "version:" in line and "<" not in line:
            errors.append(
                f"collections/requirements.yml:{line_number}: collection range has no upper bound"
            )
    return errors


def _compose_errors() -> list[str]:
    errors: list[str] = []
    path = ROOT / "docker" / "compose.pki.yml"
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if re.match(r"\s+image:\s+", line) and ":?pin " not in line:
            errors.append(
                f"{path.relative_to(ROOT)}:{line_number}: image must require an explicit "
                "pinned reference"
            )
    return errors


def _gitlab_errors() -> list[str]:
    path = ROOT / ".gitlab-ci.yml"
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if ":latest" in text:
        errors.append(".gitlab-ci.yml: floating :latest image reference")
    if "zricethezav/gitleaks@sha256:" not in text:
        errors.append(".gitlab-ci.yml: Gitleaks image must use a SHA-256 digest")
    return errors


def main() -> int:
    errors = [*_workflow_errors(), *_dependency_errors(), *_compose_errors(), *_gitlab_errors()]
    if errors:
        print("Supply-chain verification failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Supply-chain verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
