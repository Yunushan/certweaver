"""Expand release archives for scanning without executing their contents."""

from __future__ import annotations

import argparse
import json
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def expand_release(
    source: Path,
    destination: Path,
    *,
    max_bytes: int = 256 * 1024 * 1024,
    max_members: int = 20000,
    max_depth: int = 3,
) -> dict:
    """Fail closed on unsafe/unbounded archives; never overwrite a prior run."""
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    count = total = 0

    def name_path(base: Path, name: str) -> Path:
        relative = PurePosixPath(name)
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in name
            or ":" in name
        ):
            raise ValueError("Unsafe release archive member path")
        return base.joinpath(*relative.parts)

    def write(stream, target: Path, size: int, depth: int) -> None:
        nonlocal count, total
        count += 1
        if count > max_members or size < 0 or size > max_bytes - total:
            raise ValueError("Release inspection member/size limit exceeded")
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with target.open("xb") as out:
            target.chmod(0o600)
            copied = 0
            while block := stream.read(min(1024 * 1024, max_bytes - total + 1)):
                copied += len(block)
                total += len(block)
                if total > max_bytes or copied > size:
                    raise ValueError("Release archive expanded beyond its declared/bounded size")
                out.write(block)
        if copied != size:
            raise ValueError("Release archive member was truncated")
        archive(target, depth)

    def archive(path: Path, depth: int) -> None:
        nonlocal count
        is_zip = path.name.endswith((".whl", ".zip"))
        is_tar = path.name.endswith((".tar.gz", ".tgz", ".tar"))
        if not is_zip and not is_tar:
            return
        if depth >= max_depth:
            raise ValueError("Release inspection archive nesting limit exceeded")
        base = path.with_name(path.name + ".contents")
        base.mkdir(mode=0o700, exist_ok=False)
        seen = set()

        def member(name: str, directory: bool) -> Path:
            nonlocal count
            result = name_path(base, name)
            if result in seen:
                raise ValueError("Duplicate release archive member")
            seen.add(result)
            if directory:
                count += 1
                if count > max_members:
                    raise ValueError("Release inspection member limit exceeded")
                result.mkdir(parents=True, mode=0o700, exist_ok=True)
            return result

        if is_zip:
            with zipfile.ZipFile(path) as bundle:
                for item in bundle.infolist():
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (
                        0,
                        stat.S_IFREG,
                        stat.S_IFDIR,
                    ):
                        raise ValueError("Release archive links/special files are forbidden")
                    target = member(item.filename, item.is_dir())
                    if not item.is_dir():
                        with bundle.open(item) as content:
                            write(content, target, item.file_size, depth + 1)
        else:
            with tarfile.open(path) as bundle:
                for item in bundle:
                    if not item.isfile() and not item.isdir():
                        raise ValueError("Release archive links/special files are forbidden")
                    target = member(item.name, item.isdir())
                    if item.isfile():
                        with bundle.extractfile(item) as content:
                            write(content, target, item.size, depth + 1)

    if not source.is_dir():
        raise ValueError("Release inspection source must be a directory")
    for path in sorted(source.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Release inspection inputs must be regular files without links")
        with path.open("rb") as stream:
            write(stream, name_path(destination, path.name), path.stat().st_size, 0)
    if count == 0:
        raise ValueError("Release inspection inputs are empty")
    return {
        "filesAndDirectories": count,
        "expandedBytes": total,
        "destination": str(destination),
        "status": "EXPANDED_FOR_SCANNING_NOT_APPROVED",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(expand_release(args.source, args.destination), indent=2))
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"ERROR: Release archive inspection failed: {exc}")
        raise SystemExit(1) from exc
