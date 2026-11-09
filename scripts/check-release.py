"""Validate release identity and exact artifact handoff before publication.

Checksums establish byte integrity, not authenticity. The release workflow must
also verify authenticated provenance against the expected repository/workflow/
source commit. This script never executes or extracts archive contents.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


def release_version(tag: str, root: Path) -> str:
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    module = ast.parse((root / "src/certweaver/__init__.py").read_text(encoding="utf-8"))
    versions = [
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
    ]
    if versions != [version] or tag != f"v{version}":
        raise ValueError("Release tag, module version and package version must agree")
    if not re.fullmatch(r"[A-Za-z0-9.+]+", version):
        raise ValueError("Unsupported release version filename")
    return version


def _metadata(raw: bytes, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    if metadata.get_all("Name") != ["certweaver"] or metadata.get_all("Version") != [version]:
        raise ValueError("Artifact package metadata does not match release identity")


def _checkout(root: Path, commit: str) -> None:
    environment = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if (
        head.returncode
        or status.returncode
        or head.stdout.strip() != commit
        or status.stdout.strip()
    ):
        raise ValueError(
            "Release verification requires a clean checkout at the expected source commit"
        )


def check_release(directory: Path, *, tag: str, commit: str, root: Path) -> list[str]:
    try:
        version = release_version(tag, root)
        if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
            raise ValueError("A full immutable source commit is required")
        _checkout(root, commit)
        wheel = f"certweaver-{version}-py3-none-any.whl"
        sdist = f"certweaver-{version}.tar.gz"
        repo_tar = f"certweaver-{tag}.tar.gz"
        repo_zip = f"certweaver-{tag}.zip"
        sbom = f"certweaver-{tag}.sbom.cdx.json"
        names = {wheel, sdist, repo_tar, repo_zip, sbom}
        members = list(directory.iterdir())
        if {p.name for p in members} != names | {"SHA256SUMS"}:
            raise ValueError("Release directory has missing or unexpected artifacts")
        if any(p.is_symlink() or not p.is_file() or p.stat().st_size == 0 for p in members):
            raise ValueError("Release artifacts must be nonempty regular files, without links")
        checksums = {}
        for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9.+_-]+)", line)
            if not match or match[2] not in names or match[2] in checksums:
                raise ValueError("Checksum manifest contains an invalid/duplicate/unknown entry")
            checksums[match[2]] = match[1]
        if set(checksums) != names:
            raise ValueError("Checksum manifest must cover every release artifact exactly once")
        for name, digest in checksums.items():
            with (directory / name).open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != digest:
                raise ValueError(f"Release artifact checksum mismatch: {name}")
        with zipfile.ZipFile(directory / wheel) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                raise ValueError("Duplicate wheel members")
            _metadata(archive.read(f"certweaver-{version}.dist-info/METADATA"), version)
        with tarfile.open(directory / sdist) as archive:
            _metadata(archive.extractfile(f"certweaver-{version}/PKG-INFO").read(), version)
        with zipfile.ZipFile(directory / repo_zip) as archive:
            if archive.comment.decode("ascii") != commit:
                raise ValueError("Repository ZIP source commit does not match candidate")
            if not archive.namelist() or any(
                not n.startswith(f"certweaver-{tag}/") for n in archive.namelist()
            ):
                raise ValueError("Repository ZIP prefix differs from release identity")
        with tarfile.open(directory / repo_tar) as archive:
            if archive.pax_headers.get("comment") != commit:
                raise ValueError("Repository tar source commit does not match candidate")
            if not archive.getmembers() or any(
                m.name != f"certweaver-{tag}" and not m.name.startswith(f"certweaver-{tag}/")
                for m in archive.getmembers()
            ):
                raise ValueError("Repository tar prefix differs from release identity")
        bill = json.loads((directory / sbom).read_text(encoding="utf-8"))
        if (
            not isinstance(bill, dict)
            or bill.get("bomFormat") != "CycloneDX"
            or not bill.get("specVersion")
            or not isinstance(bill.get("components"), list)
            or not bill["components"]
            or any(
                not isinstance(c, dict) or not c.get("name") or not c.get("type")
                for c in bill["components"]
            )
        ):
            raise ValueError("Release SBOM is missing a usable CycloneDX component inventory")
        return []
    except (
        OSError,
        ValueError,
        KeyError,
        AttributeError,
        TypeError,
        tarfile.TarError,
        zipfile.BadZipFile,
        SyntaxError,
    ) as exc:
        return [str(exc)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("dist"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit")
    parser.add_argument(
        "--identity-only",
        action="store_true",
        help="Check source/tag version only; does not qualify artifacts",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.identity_only:
        try:
            print(f"Release identity valid: {release_version(args.tag, root)}")
            return 0
        except (OSError, ValueError, KeyError, SyntaxError) as exc:
            print(f"ERROR: {exc}")
            return 1
    errors = check_release(args.directory, tag=args.tag, commit=args.commit or "", root=root)
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("Release identity, complete checksums, package metadata and archive commits verified")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
