"""Regenerate reviewed universal pip hash locks with an independently trusted uv.

Generating pins does not approve dependency licenses, advisories or support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import tempfile
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def generate(root: Path, executable: Path, *, cutoff: datetime) -> dict:
    root, executable = root.resolve(), executable.absolute()
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("Lock generator must be one independently trusted regular executable")
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith(("UV_", "PIP_"))
    }
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    version = subprocess.run(
        [str(executable), "--version"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    ).stdout.strip()
    if not re.fullmatch(r"uv \d+\.\d+\.\d+(?: .*)?", version):
        raise ValueError("Unexpected lock generator identity")
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    validate = runpy.run_path(str(root / "scripts/install-python-deps.py"))["validate_lock"]
    work_root = root / ".certweaver/lock-generation"
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_root) as temporary:
        work = Path(temporary)
        build = work / "build.in"
        build.write_text(
            (root / "ci/python-build.in").read_text(encoding="utf-8")
            + "\n"
            + "\n".join(config["build-system"]["requires"])
            + "\n",
            encoding="utf-8",
        )
        outputs = {}
        for profile in ("runtime", "build", "dev"):
            output = work / f"python-{profile}.lock"
            command = [
                str(executable),
                "--no-config",
                "--no-cache",
                "pip",
                "compile",
                "pyproject.toml",
                "--universal",
                "--python-version",
                "3.11",
                "--generate-hashes",
                "--no-annotate",
                "--no-header",
                "--no-build",
                "--format",
                "requirements.txt",
                "--default-index",
                "https://pypi.org/simple",
                "--exclude-newer",
                cutoff.isoformat(),
                "--output-file",
                str(output),
            ]
            if profile != "runtime":
                command.append(str(build))
            if profile == "dev":
                command.extend(["--extra", "dev"])
            result = subprocess.run(
                command, cwd=root, env=environment, capture_output=True, timeout=300, check=False
            )
            log = work_root / f"{profile}.log"
            log.write_bytes(result.stdout + b"\n" + result.stderr)
            log.chmod(0o600)
            if result.returncode:
                raise ValueError(f"{profile} dependency resolution failed; no locks replaced")
            text = output.read_text(encoding="utf-8")
            validate(text)
            outputs[profile] = text
        for profile, text in outputs.items():
            (root / f"ci/python-{profile}.lock").write_text(text, encoding="utf-8", newline="\n")
    manifest = {
        "schemaVersion": 1,
        "status": "GENERATED_PINS_REQUIRE_MAINTAINER_REVIEW",
        "generatedAt": datetime.now(UTC).isoformat(),
        "excludeNewerThan": cutoff.isoformat(),
        "generator": {"version": version, "executableSha256": digest(executable)},
        "resolution": {
            "universal": True,
            "minimumPython": "3.11",
            "index": "https://pypi.org/simple",
        },
        "inputs": {name: digest(root / name) for name in ("pyproject.toml", "ci/python-build.in")},
        "locks": {
            profile: {
                "path": f"ci/python-{profile}.lock",
                "sha256": digest(root / f"ci/python-{profile}.lock"),
            }
            for profile in ("runtime", "build", "dev")
        },
    }
    (root / "ci/python-locks.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uv", type=Path, required=True)
    parser.add_argument(
        "--exclude-newer",
        type=datetime.fromisoformat,
        default=datetime.now(UTC) - timedelta(days=7),
    )
    args = parser.parse_args()
    if args.exclude_newer.tzinfo is None or args.exclude_newer > datetime.now(UTC):
        parser.error("--exclude-newer must be an aware timestamp in the past")
    try:
        print(
            json.dumps(
                generate(Path(__file__).resolve().parents[1], args.uv, cutoff=args.exclude_newer),
                indent=2,
            )
        )
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"ERROR: Python lock generation failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
