"""Build exact-source packages with locked tools and canonical sdist metadata."""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import runpy
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
import zlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_MEMBERS = 10000
STATUS = "EXACT_SOURCE_PACKAGE_BUILD_NOT_PRODUCTION_APPROVAL"
POLICY_FILES = (
    "scripts/build-package.py",
    "scripts/install-python-deps.py",
    "ci/python-locks.json",
    "ci/python-build.lock",
    "ci/python-build.in",
    "pyproject.toml",
)


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARCHIVE:
        raise ValueError("Package build inputs must be bounded nonempty regular files")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def environment() -> dict[str, str]:
    result = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "PIP_", "GIT_", "SETUPTOOLS_", "DISTUTILS_"))
    }
    result.update(
        PIP_CONFIG_FILE=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_OPTIONAL_LOCKS="0",
    )
    return result


def source_epoch(root: Path, commit: str) -> int:
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise ValueError("A full immutable build source commit is required")
    for arguments, expected in [
        (["rev-parse", "HEAD"], commit),
        (["status", "--porcelain", "--untracked-files=normal"], ""),
    ]:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            env=environment(),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        if result.stdout.strip() != expected:
            raise ValueError("Package build requires a clean checkout at the expected commit")
    result = subprocess.run(
        ["git", "show", "-s", "--format=%ct", commit],
        cwd=root,
        env=environment(),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    value = result.stdout.strip()
    if not value.isascii() or not value.isdecimal() or not 315532800 <= int(value) <= 4294967295:
        raise ValueError("Source commit timestamp is outside the gzip/ZIP build policy range")
    return int(value)


def build_tools(root: Path) -> dict[str, str]:
    installer = runpy.run_path(str(root / "scripts/install-python-deps.py"))
    lock = installer["lock_file"](root, "build")
    from packaging.requirements import Requirement

    result = {}
    for line in lock.read_text(encoding="utf-8").replace("\\\n", " ").splitlines():
        if not line.strip():
            continue
        requirement = Requirement(line.split(" --hash=", 1)[0].strip())
        if requirement.marker and not requirement.marker.evaluate():
            continue
        version = importlib.metadata.version(requirement.name)
        if version not in requirement.specifier:
            raise ValueError("Installed build tools differ from the source-bound build lock")
        result[requirement.name] = version
    return result


def inspected_members(bundle: tarfile.TarFile, prefix: str) -> list[tarfile.TarInfo]:
    members, seen, expanded = [], set(), 0
    for member in bundle:
        path = PurePosixPath(member.name)
        if (
            not member.name
            or "\\" in member.name
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in member.name.split("/"))
            or path.parts[0] != prefix
            or member.name in seen
            or not (member.isfile() or member.isdir())
            or (member.isfile() and member.name == prefix)
        ):
            raise ValueError("Source archive contains unsafe, duplicate or unsupported members")
        seen.add(member.name)
        expanded += member.size
        if member.size < 0 or expanded > MAX_EXPANDED or len(members) >= MAX_MEMBERS:
            raise ValueError("Source archive exceeds normalization bounds")
        members.append(member)
    if not members or not any(member.isfile() for member in members):
        raise ValueError("Source archive has no regular package payload")
    return sorted(members, key=lambda member: member.name)


def payload(bundle: tarfile.TarFile, members: list[tarfile.TarInfo]) -> dict:
    result = {}
    for member in members:
        if member.isfile():
            with bundle.extractfile(member) as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            result[member.name] = {"sha256": checksum, "executable": bool(member.mode & 0o111)}
    return result


def normalize_sdist(path: Path, *, version: str, epoch: int) -> dict:
    if type(epoch) is not int or not 315532800 <= epoch <= 4294967295:
        raise ValueError("Normalization epoch must be an integer in the build policy range")
    original_hash = digest(path)
    prefix = f"certweaver-{version}"
    temporary = path.with_name(path.name + ".normalized")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("Refusing to replace an existing normalization output")
    try:
        with tarfile.open(path, "r:gz") as original:
            members = inspected_members(original, prefix)
            before = payload(original, members)
            with (
                temporary.open("xb") as output,
                gzip.GzipFile(
                    filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9
                ) as compressed,
                tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target,
            ):
                for item in members:
                    canonical = copy.copy(item)
                    canonical.uid = canonical.gid = 0
                    canonical.uname = canonical.gname = ""
                    canonical.mtime = epoch
                    canonical.pax_headers = {}
                    canonical.mode = 0o755 if item.isdir() or item.mode & 0o111 else 0o644
                    canonical.size = item.size if item.isfile() else 0
                    content = original.extractfile(item) if item.isfile() else None
                    try:
                        target.addfile(canonical, content)
                    finally:
                        if content is not None:
                            content.close()
        digest(temporary)
        with tarfile.open(temporary, "r:gz") as normalized:
            after = payload(normalized, inspected_members(normalized, prefix))
        if before != after:
            raise ValueError("Source normalization changed file bytes or executable semantics")
        os.replace(temporary, path)
    finally:
        if temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()
    return {
        "policyVersion": 1,
        "originalSha256": original_hash,
        "normalizedSha256": digest(path),
        "payloadSha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        "regularFiles": len(before),
        "payloadPreserved": True,
        "epoch": epoch,
        "ownership": "0:0",
        "memberOrder": "lexical",
        "modes": "directories/executable files 0755; other regular files 0644",
    }


def normalize_wheel(path: Path, *, epoch: int) -> dict:
    if type(epoch) is not int or not 315532800 <= epoch <= 4294967295:
        raise ValueError("Normalization epoch must be an integer in the build policy range")
    original_hash = digest(path)
    temporary = path.with_name(path.name + ".normalized")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("Refusing to replace an existing wheel normalization output")
    stamp = datetime.fromtimestamp(epoch, UTC).timetuple()[:6]
    stamp = (*stamp[:5], stamp[5] // 2 * 2)
    before, after = {}, {}
    try:
        with zipfile.ZipFile(path) as original:
            members, expanded = {}, 0
            for item in original.infolist():
                name = item.filename
                mode = item.external_attr >> 16
                if (
                    not name
                    or "\\" in name
                    or name.startswith("/")
                    or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                    or ":" in name
                    or name in members
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or item.file_size > 64 * 1024 * 1024
                ):
                    raise ValueError("Wheel contains unsafe or unsupported normalization members")
                expanded += item.file_size
                if expanded > MAX_EXPANDED or len(members) >= MAX_MEMBERS:
                    raise ValueError("Wheel exceeds normalization bounds")
                members[name] = item
            if not members or not any(not item.is_dir() for item in members.values()):
                raise ValueError("Wheel has no regular package payload")
            with zipfile.ZipFile(temporary, "x") as target:
                for name, item in sorted(members.items()):
                    data = original.read(item)
                    executable = bool(item.external_attr >> 16 & 0o111) and not item.is_dir()
                    before[name] = {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "executable": executable,
                    }
                    canonical = zipfile.ZipInfo(name, stamp)
                    canonical.create_system = 3
                    permissions = 0o755 if item.is_dir() or executable else 0o644
                    kind = stat.S_IFDIR if item.is_dir() else stat.S_IFREG
                    canonical.external_attr = (kind | permissions) << 16 | (
                        0x10 if item.is_dir() else 0
                    )
                    target.writestr(
                        canonical, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
                    )
        digest(temporary)
        with zipfile.ZipFile(temporary) as normalized:
            for item in normalized.infolist():
                after[item.filename] = {
                    "sha256": hashlib.sha256(normalized.read(item)).hexdigest(),
                    "executable": bool(item.external_attr >> 16 & 0o111) and not item.is_dir(),
                }
        if before != after:
            raise ValueError("Wheel normalization changed payload or executable semantics")
        os.replace(temporary, path)
    finally:
        if temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()
    return {
        "policyVersion": 1,
        "originalSha256": original_hash,
        "normalizedSha256": digest(path),
        "payloadPreserved": True,
        "payloadSha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        "epoch": epoch,
        "memberOrder": "lexical",
        "zipCreatorSystem": 3,
        "compression": "deflate level 9",
        "timestampResolutionSeconds": 2,
    }


def runtime_inputs() -> dict:
    return {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "machine": platform.machine(),
        "system": platform.system(),
        "zlibCompileVersion": zlib.ZLIB_VERSION,
        "zlibRuntimeVersion": zlib.ZLIB_RUNTIME_VERSION,
    }


def build_package(root: Path, *, commit: str) -> dict:
    root = root.resolve()
    epoch = source_epoch(root, commit)
    tools = build_tools(root)
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    release = runpy.run_path(str(root / "scripts/check-release.py"))
    version = release["release_version"]("v" + metadata["project"]["version"], root)
    directory, work = root / "dist", root / ".certweaver/package-build"
    for path in (directory, work):
        if path.exists() or path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(
                "Package build requires fresh output/work directories inside the checkout"
            )
    work.mkdir(parents=True, mode=0o700)
    variables = environment()
    variables.update(SOURCE_DATE_EPOCH=str(epoch), PYTHONHASHSEED="0", TZ="UTC")
    result = subprocess.run(
        [sys.executable, "-s", "-m", "build", "--no-isolation"],
        cwd=root,
        env=variables,
        capture_output=True,
        timeout=300,
        check=False,
    )
    log = work / "backend.log"
    log.write_bytes(result.stdout + b"\n" + result.stderr)
    log.chmod(0o600)
    if result.returncode:
        raise ValueError("Locked package backend failed; inspect restricted local build log")
    if source_epoch(root, commit) != epoch:
        raise ValueError("Build source identity or timestamp changed during packaging")
    expected = {f"certweaver-{version}-py3-none-any.whl", f"certweaver-{version}.tar.gz"}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("Package backend produced missing or unexpected outputs")
    for path in directory.iterdir():
        digest(path)
    normalization = normalize_sdist(
        directory / f"certweaver-{version}.tar.gz", version=version, epoch=epoch
    )
    wheel_normalization = normalize_wheel(
        directory / f"certweaver-{version}-py3-none-any.whl", epoch=epoch
    )
    record = {
        "schemaVersion": 1,
        "status": STATUS,
        "sourceCommit": commit,
        "sourceDateEpoch": epoch,
        "packageVersion": version,
        "environment": {"PYTHONHASHSEED": "0", "TZ": "UTC", "buildIsolation": False},
        "interpreter": runtime_inputs(),
        "buildTools": tools,
        "normalization": normalization,
        "wheelNormalization": wheel_normalization,
        "artifacts": {path.name: digest(path) for path in sorted(directory.iterdir())},
        "policySha256": {name: digest(root / name) for name in POLICY_FILES},
    }
    (work / "receipt.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                build_package(Path(__file__).resolve().parents[1], commit=args.commit), indent=2
            )
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        importlib.metadata.PackageNotFoundError,
        tarfile.TarError,
    ) as exc:
        print(f"ERROR: Exact-source package build failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
