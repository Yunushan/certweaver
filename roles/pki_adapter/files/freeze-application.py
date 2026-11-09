"""Freeze an unprivileged application build without following its links."""

from __future__ import annotations

import grp
import os
import posixpath
import stat
import sys
from pathlib import Path


def freeze(root: Path, gid: int, *, uid: int = 0) -> int:
    count = 0
    interpreter = Path(sys.executable).resolve()
    flags = os.O_RDONLY | os.O_NOFOLLOW

    def walk(directory: int, relative: str):
        nonlocal count
        # Lock the directory before inspecting children. Every open is relative
        # to a held directory descriptor; rename and symlink races cannot send
        # chown/chmod operations outside this tree.
        os.fchown(directory, uid, gid)
        os.fchmod(directory, 0o750)
        for name in os.listdir(directory):
            count += 1
            if count > 200_000:
                raise ValueError("Application build exceeds entry limit")
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(name, dir_fd=directory)
                if target.startswith("/"):
                    if Path(target).resolve() != interpreter:
                        raise ValueError("External application symlink")
                else:
                    normalized = posixpath.normpath(posixpath.join(relative, target))
                    if normalized == ".." or normalized.startswith("../"):
                        raise ValueError("Escaping application symlink")
                os.chown(name, uid, gid, dir_fd=directory, follow_symlinks=False)
                continue
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError("Special file in application build")
            selected_flags = flags | (os.O_DIRECTORY if stat.S_ISDIR(metadata.st_mode) else 0)
            child = os.open(name, selected_flags, dir_fd=directory)
            try:
                actual = os.fstat(child)
                if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError("Application entry changed during freezing")
                if stat.S_ISDIR(actual.st_mode):
                    walk(child, posixpath.join(relative, name))
                elif stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1:
                    os.fchown(child, uid, gid)
                    os.fchmod(child, 0o750 if actual.st_mode & 0o111 else 0o640)
                else:
                    raise ValueError("Linked or substituted application file")
            finally:
                os.close(child)

    directory = os.open(root, flags | os.O_DIRECTORY)
    try:
        walk(directory, "")
    finally:
        os.close(directory)
    return count


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            raise ValueError("Root is required to freeze the application")
        count = freeze(Path(sys.argv[1]), grp.getgrnam(sys.argv[2]).gr_gid)
        print(f"Protected {count} application entries")
    except (IndexError, KeyError, OSError, ValueError):
        print(
            "Application ownership verification failed; preserve the build for inspection",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
