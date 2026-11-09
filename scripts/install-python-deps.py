"""Install the source-bound Python hash locks; never resolve new build inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PROFILES = ("runtime", "build", "dev")


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError("Python lock inputs must be bounded regular files")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate Python lock manifest key")
        result[key] = value
    return result


def validate_lock(text: str) -> None:
    lines = text.replace("\\\n", " ").splitlines()
    entries = [line.strip() for line in lines if line.strip()]
    if not entries or any(
        not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.!+_-]*"
            r"(?:\s*;\s*[A-Za-z0-9_.'\"<>=! ()-]+)?\s+"
            r"(?:--hash=sha256:[a-f0-9]{64}\s*)+",
            line,
        )
        for line in entries
    ):
        raise ValueError("Python locks require exact versions and SHA-256 hashes only")


def lock_file(root: Path, profile: str) -> Path:
    if profile not in PROFILES:
        raise ValueError("Unknown Python lock profile")
    manifest_path = root / "ci/python-locks.json"
    digest(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if (
        type(manifest.get("schemaVersion")) is not int
        or manifest["schemaVersion"] != 1
        or manifest.get("resolution")
        != {"universal": True, "minimumPython": "3.11", "index": "https://pypi.org/simple"}
        or set(manifest["inputs"]) != {"pyproject.toml", "ci/python-build.in"}
        or set(manifest["locks"]) != set(PROFILES)
    ):
        raise ValueError("Unsupported Python lock manifest")
    for name, expected in manifest["inputs"].items():
        if digest(root / name) != expected:
            raise ValueError("Python dependency inputs changed; regenerate and review the locks")
    for name, record in manifest["locks"].items():
        path = root / f"ci/python-{name}.lock"
        if record["path"] != f"ci/python-{name}.lock" or digest(path) != record["sha256"]:
            raise ValueError("Python dependency lock hash/path mismatch")
        # No nested requirements, index overrides, editable installs, direct URLs
        # or unpinned entries can enter an otherwise hash-locked installation.
        validate_lock(path.read_text(encoding="utf-8"))
    return root / f"ci/python-{profile}.lock"


def pip_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PIP_")}
    # pip documents os.devnull as disabling every configuration file. Do not use
    # --isolated here: PIP_CONFIG_FILE must remain visible to its config loader.
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


def pip_command() -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "pip",
        "install",
        "--no-input",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--index-url",
        "https://pypi.org/simple",
    ]


def candidate_requirements(root: Path, wheel: Path, destination: Path) -> Path:
    lock = lock_file(root, "runtime")
    wheel_hash = digest(wheel)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(lock.read_text(encoding="utf-8").rstrip() + "\n")
        stream.write(f"certweaver @ {wheel.resolve().as_uri()} --hash=sha256:{wheel_hash}\n")
    return destination


def install_profile(
    root: Path, profile: str, *, project: bool = False, editable: bool = False
) -> None:
    lock = lock_file(root, profile)
    # The interpreter's provisioned pip is the bootstrap trust boundary. It
    # installs only the pinned pip wheel; that installer handles the full set.
    build_lock = lock_file(root, "build").read_text(encoding="utf-8").replace("\\\n", " ")
    pip_entries = [line for line in build_lock.splitlines() if line.startswith("pip==")]
    if len(pip_entries) != 1:
        raise ValueError("Build lock must pin exactly one bootstrap pip")
    with tempfile.TemporaryDirectory(prefix="certweaver-pip-") as temporary:
        bootstrap = Path(temporary) / "pip.lock"
        bootstrap.write_text(pip_entries[0] + "\n", encoding="utf-8")
        subprocess.run(
            [*pip_command(), "--require-hashes", "--only-binary=:all:", "-r", str(bootstrap)],
            cwd=root,
            env=pip_environment(),
            check=True,
            timeout=300,
        )
    subprocess.run(
        [*pip_command(), "--require-hashes", "--only-binary=:all:", "-r", str(lock)],
        cwd=root,
        env=pip_environment(),
        check=True,
        timeout=600,
    )
    if project or editable:
        command = [*pip_command(), "--no-deps", "--no-build-isolation"]
        if editable:
            command.append("--editable")
        command.append(str(root))
        subprocess.run(command, cwd=root, env=pip_environment(), check=True, timeout=300)
    subprocess.run(
        [sys.executable, "-I", "-m", "pip", "check"],
        cwd=root,
        env=pip_environment(),
        check=True,
        timeout=60,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES)
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--project", action="store_true")
    options.add_argument("--editable", action="store_true")
    args = parser.parse_args()
    try:
        install_profile(
            Path(__file__).resolve().parents[1],
            args.profile,
            project=args.project,
            editable=args.editable,
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: Locked Python dependency installation failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
