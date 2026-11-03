from __future__ import annotations

import io
import runpy
import stat
import tarfile
import zipfile

import pytest

from certweaver.registry import project_root

expand_release = runpy.run_path(str(project_root() / "scripts/expand-release-assets.py"))[
    "expand_release"
]


def test_nested_release_contents_are_expanded_without_execution(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "inspection"
    source.mkdir()
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("fixture.pem", b"scanner fixture only")
    with tarfile.open(source / "fixture.tar.gz", "w:gz") as archive:
        payload = nested.getvalue()
        member = tarfile.TarInfo("nested.whl")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    report = expand_release(source, destination)
    expected = destination / "fixture.tar.gz.contents/nested.whl.contents/fixture.pem"
    assert expected.read_bytes() == b"scanner fixture only"
    assert report["filesAndDirectories"] == 3
    assert report["status"] == "EXPANDED_FOR_SCANNING_NOT_APPROVED"
    with pytest.raises(FileExistsError):
        expand_release(source, destination)


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/drive", "..\\outside"])
@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_archive_members_cannot_escape_inspection(tmp_path, name, kind):
    source = tmp_path / "source"
    source.mkdir()
    if kind == "zip":
        with zipfile.ZipFile(source / "fixture.zip", "w") as archive:
            archive.writestr(name, b"fixture")
    else:
        with tarfile.open(source / "fixture.tar", "w") as archive:
            member = tarfile.TarInfo(name)
            member.size = 7
            archive.addfile(member, io.BytesIO(b"fixture"))
    with pytest.raises(ValueError, match="Unsafe"):
        expand_release(source, tmp_path / "inspection")
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("kind", ["zip", "symlink", "hardlink", "fifo"])
def test_archive_links_and_special_files_are_rejected(tmp_path, kind):
    source = tmp_path / "source"
    source.mkdir()
    if kind == "zip":
        with zipfile.ZipFile(source / "fixture.zip", "w") as archive:
            member = zipfile.ZipInfo("link")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "outside")
    else:
        with tarfile.open(source / "fixture.tar", "w") as archive:
            member = tarfile.TarInfo("link")
            member.type = {
                "symlink": tarfile.SYMTYPE,
                "hardlink": tarfile.LNKTYPE,
                "fifo": tarfile.FIFOTYPE,
            }[kind]
            member.linkname = "outside"
            archive.addfile(member)
    with pytest.raises(ValueError, match="links/special"):
        expand_release(source, tmp_path / "inspection")


@pytest.mark.parametrize("limit", ["bytes", "members", "nesting"])
def test_expansion_limits_fail_closed(tmp_path, limit):
    source = tmp_path / "source"
    source.mkdir()
    with zipfile.ZipFile(source / "fixture.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"a" * 10000)
        archive.writestr("second.txt", b"x")
    kwargs = {
        "bytes": {"max_bytes": 500},
        "members": {"max_members": 1},
        "nesting": {"max_depth": 0},
    }[limit]
    with pytest.raises(ValueError, match="limit"):
        expand_release(source, tmp_path / "inspection", **kwargs)


def test_duplicate_members_and_empty_input_are_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="empty"):
        expand_release(source, tmp_path / "empty-inspection")
    with tarfile.open(source / "duplicate.tar", "w") as archive:
        archive.addfile(tarfile.TarInfo("same"), io.BytesIO(b""))
        archive.addfile(tarfile.TarInfo("same"), io.BytesIO(b""))
    with pytest.raises(ValueError, match="Duplicate"):
        expand_release(source, tmp_path / "duplicate-inspection")
