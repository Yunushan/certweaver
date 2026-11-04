from __future__ import annotations

import hashlib
import io
import json
import runpy
import shutil
import stat
import subprocess
import tarfile
import zipfile

import pytest

from certweaver.registry import project_root

builder = runpy.run_path(str(project_root() / "scripts/build-package.py"))
reproducer = runpy.run_path(str(project_root() / "scripts/check-package-reproducibility.py"))
EPOCH = 1767225600
COMMIT = "a" * 40


def source_archive(path, *, stamp, reverse=False, bad=None):
    names = ["certweaver-0.1.0", "certweaver-0.1.0/data", "certweaver-0.1.0/run"]
    if bad in {"escape", "absolute", "prefix"}:
        names[-1] = {
            "escape": "certweaver-0.1.0/../outside",
            "absolute": "/outside",
            "prefix": "wrong/run",
        }[bad]
    if bad == "duplicate":
        names.append(names[-1])
    with tarfile.open(path, "w:gz") as bundle:
        for name in reversed(names) if reverse else names:
            item = tarfile.TarInfo(name)
            item.mtime = stamp
            item.uid, item.gid, item.uname, item.gname = stamp, stamp, "fixture", "fixture"
            item.pax_headers = {"mtime": str(stamp + 0.25), "atime": str(stamp)}
            if name == names[0]:
                item.type = tarfile.DIRTYPE
            else:
                item.mode = 0o755 if name.endswith("run") else 0o664
                item.size = 7
                if bad in {"symlink", "hardlink", "fifo"}:
                    item.type = {
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "fifo": tarfile.FIFOTYPE,
                    }[bad]
                bundle.addfile(item, io.BytesIO(b"fixture"))
                continue
            bundle.addfile(item)


def test_source_normalization_is_byte_identical_payload_preserving_and_idempotent(tmp_path):
    paths = [tmp_path / (str(i) + ".tar.gz") for i in range(2)]
    for index, path in enumerate(paths):
        source_archive(path, stamp=100 + index, reverse=bool(index))
        receipt = builder["normalize_sdist"](path, version="0.1.0", epoch=EPOCH)
        assert receipt["payloadPreserved"] and receipt["regularFiles"] == 2
        with tarfile.open(path) as bundle:
            for item in bundle:
                assert item.mtime == EPOCH and item.uid == item.gid == 0
                if item.isfile():
                    assert bundle.extractfile(item).read() == b"fixture"
                    assert item.mode == (0o755 if item.name.endswith("run") else 0o644)
    assert paths[0].read_bytes() == paths[1].read_bytes()
    before = paths[0].read_bytes()
    builder["normalize_sdist"](paths[0], version="0.1.0", epoch=EPOCH)
    assert paths[0].read_bytes() == before


@pytest.mark.parametrize(
    "bad",
    [
        "escape",
        "absolute",
        "prefix",
        "duplicate",
        "symlink",
        "hardlink",
        "fifo",
        "bounds",
        "members",
        "corrupt",
        "existing-output",
    ],
)
def test_invalid_source_archive_never_replaces_original(tmp_path, monkeypatch, bad):
    path = tmp_path / "input.tar.gz"
    source_archive(path, stamp=123, bad=bad)
    if bad == "corrupt":
        path.write_bytes(b"not a gzip archive")
    if bad == "bounds":
        monkeypatch.setitem(builder["inspected_members"].__globals__, "MAX_EXPANDED", 1)
    if bad == "members":
        monkeypatch.setitem(builder["inspected_members"].__globals__, "MAX_MEMBERS", 1)
    if bad == "existing-output":
        path.with_name(path.name + ".normalized").write_bytes(b"preserve")
    before = path.read_bytes()
    with pytest.raises((ValueError, tarfile.TarError)):
        builder["normalize_sdist"](path, version="0.1.0", epoch=EPOCH)
    assert path.read_bytes() == before


def wheel(path, *, stamp, mode, reverse=False, bad=None):
    names = ["package/data", "package/run", "package.dist-info/RECORD"]
    if bad == "escape":
        names[0] = "../outside"
    if bad == "duplicate":
        names.append(names[0])
    with zipfile.ZipFile(path, "w") as bundle:
        for name in reversed(names) if reverse else names:
            item = zipfile.ZipInfo(name, (2020 + stamp, 1, 1, 0, 0, 0))
            item.create_system = stamp
            item.external_attr = (stat.S_IFREG | (0o755 if name.endswith("run") else mode)) << 16
            if bad == "symlink":
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
            item.comment = b"varying metadata"
            bundle.writestr(item, b"unchanged fixture contents")


def test_wheel_normalization_preserves_record_contents_and_executable_bits(tmp_path):
    paths = [tmp_path / (str(i) + ".whl") for i in range(2)]
    for index, path in enumerate(paths):
        wheel(path, stamp=index, mode=0o666 if index else 0o644, reverse=bool(index))
        record = builder["normalize_wheel"](path, epoch=EPOCH)
        assert record["payloadPreserved"]
        with zipfile.ZipFile(path) as bundle:
            assert bundle.read("package.dist-info/RECORD") == b"unchanged fixture contents"
            assert bundle.getinfo("package/run").external_attr >> 16 & 0o111
    assert paths[0].read_bytes() == paths[1].read_bytes()


@pytest.mark.parametrize("bad", ["escape", "duplicate", "symlink", "bounds", "members"])
def test_unsafe_wheel_cannot_be_normalized(tmp_path, monkeypatch, bad):
    path = tmp_path / "input.whl"
    wheel(path, stamp=1, mode=0o644, bad=bad)
    if bad in {"bounds", "members"}:
        monkeypatch.setitem(
            builder["normalize_wheel"].__globals__,
            "MAX_EXPANDED" if bad == "bounds" else "MAX_MEMBERS",
            1,
        )
    before = path.read_bytes()
    with pytest.raises(ValueError):
        builder["normalize_wheel"](path, epoch=EPOCH)
    assert path.read_bytes() == before


@pytest.mark.parametrize("failure", ["dirty", "wrong-commit", "invalid-time", "invalid-commit"])
def test_source_identity_and_epoch_fail_closed(tmp_path, monkeypatch, failure):
    def run(command, **kwargs):
        assert "GIT_DIR" not in kwargs["env"]
        if "rev-parse" in command:
            output = "b" * 40 if failure == "wrong-commit" else COMMIT
        elif "status" in command:
            output = " M pyproject.toml" if failure == "dirty" else ""
        else:
            output = "123.25" if failure == "invalid-time" else str(EPOCH)
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setenv("GIT_DIR", "untrusted")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError):
        builder["source_epoch"](tmp_path, "main" if failure == "invalid-commit" else COMMIT)


def repro_fixture(tmp_path):
    original, clone = tmp_path / "first", tmp_path / "second"
    policies = [
        "scripts/build-package.py",
        "scripts/install-python-deps.py",
        "ci/python-locks.json",
        "ci/python-build.lock",
        "ci/python-build.in",
        "pyproject.toml",
    ]
    for root in (original, clone):
        for name in [*policies, "scripts/check-package-reproducibility.py"]:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(project_root() / name, target)
        (root / "dist").mkdir()
        for name in ("fixture.whl", "fixture.tar.gz"):
            (root / "dist" / name).write_bytes(b"synthetic package, not installable")
        record = {
            "status": builder["STATUS"],
            "sourceCommit": COMMIT,
            "sourceDateEpoch": EPOCH,
            "buildTools": {"fixture": "1"},
            "normalization": {"payloadPreserved": True},
            "wheelNormalization": {"payloadPreserved": True},
            "interpreter": {"fixture": "test-only"},
            "policySha256": {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in policies
            },
            "artifacts": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (root / "dist").iterdir()
            },
        }
        output = root / ".certweaver/package-build/receipt.json"
        output.parent.mkdir(parents=True)
        output.write_text(json.dumps(record), encoding="utf-8")
    return original, clone


@pytest.mark.parametrize(
    "change",
    [
        None,
        "substitution",
        "wrong-source",
        "missing-policy",
        "missing-normalization",
        "interpreter",
        "missing-artifact",
        "changed-policy",
    ],
)
def test_reproduction_rejects_inconsistent_receipts_or_different_bytes(tmp_path, change):
    original, clone = repro_fixture(tmp_path)
    path = clone / ".certweaver/package-build/receipt.json"
    record = json.loads(path.read_text())
    if change == "substitution":
        (clone / "dist/fixture.whl").write_bytes(b"different payload")
        record["artifacts"]["fixture.whl"] = hashlib.sha256(b"different payload").hexdigest()
    elif change == "wrong-source":
        record["sourceCommit"] = "b" * 40
    elif change == "missing-policy":
        record["policySha256"].pop("pyproject.toml")
    elif change == "missing-normalization":
        record["normalization"] = {}
    elif change == "interpreter":
        record["interpreter"] = {"fixture": "different"}
    elif change == "missing-artifact":
        (clone / "dist/fixture.whl").unlink()
    elif change == "changed-policy":
        (clone / "scripts/build-package.py").write_bytes(b"changed verifier")
    path.write_text(json.dumps(record), encoding="utf-8")
    if change:
        with pytest.raises(ValueError):
            reproducer["verify_reproduction"](
                original, clone, commit=COMMIT, epoch=EPOCH, tools={"fixture": "1"}
            )
    else:
        result = reproducer["verify_reproduction"](
            original, clone, commit=COMMIT, epoch=EPOCH, tools={"fixture": "1"}
        )
        assert (
            result["status"] == reproducer["STATUS"]
            and result["independentReviewerApproval"] is False
        )
