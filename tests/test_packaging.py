from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import uuid
import zipfile
from pathlib import Path

from certweaver.registry import project_root


def test_operator_secrets_are_excluded_from_both_distribution_formats(tmp_path: Path) -> None:
    """Build adjacent to realistic ignored secrets and inspect every archive member."""
    root = project_root()
    source = tmp_path / "source"
    source.mkdir()
    resources = [
        line.strip()
        for line in (root / "certweaver-resources.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    build_files = ["pyproject.toml", "setup.py", "MANIFEST.in", "certweaver-resources.txt"]
    build_files.extend(["README.md", "LICENSE", "ci/tools.lock.json", "ci/secret-scan.yaml"])
    build_files.append("ci/cluster-health-client.lock.json")
    build_files.extend(
        [
            "ci/python-build.in",
            "ci/python-runtime.lock",
            "ci/python-build.lock",
            "ci/python-dev.lock",
            "ci/python-locks.json",
        ]
    )
    for relative in [*build_files, *resources]:
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    shutil.copytree(root / "src" / "certweaver", source / "src" / "certweaver")
    marker = uuid.uuid4().hex.encode("ascii")
    private_names = ["docker/.env", "config/secrets/rke2-token", "examples/configs/secrets/token"]
    for relative in private_names:
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(marker)
    cached_manifest = source / "src" / "certweaver.egg-info" / "SOURCES.txt"
    cached_manifest.parent.mkdir()
    cached_manifest.write_text("\n".join(private_names) + "\n", encoding="utf-8")

    temporary = tmp_path / "temporary"
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update(TMPDIR=str(temporary), TEMP=str(temporary), TMP=str(temporary))
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--sdist", "--wheel"],
        cwd=source,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    with tarfile.open(next((source / "dist").glob("*.tar.gz"))) as archive:
        for member in archive.getmembers():
            relative = member.name.partition("/")[2]
            assert relative not in private_names
            if member.isfile():
                content = archive.extractfile(member)
                assert content is not None
                if marker in content.read():
                    raise AssertionError("Source distribution contains private fixture data")
        included = {member.name.partition("/")[2] for member in archive.getmembers()}
        assert set(resources) <= included

    # pip compiles .py files even when they are deployment resources rather than
    # importable modules. Verify the installed asset set remains exactly allowlisted.
    installed = tmp_path / "installed"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            "--target",
            str(installed),
            str(next((source / "dist").glob("*.whl"))),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assets = installed / "certweaver" / "_assets"
    actual = {path.relative_to(assets).as_posix() for path in assets.rglob("*") if path.is_file()}
    assert actual == set(resources)
    assert all((assets / name).read_bytes() == (source / name).read_bytes() for name in resources)

    with zipfile.ZipFile(next((source / "dist").glob("*.whl"))) as archive:
        asset_prefix = "certweaver/_assets/"
        included = {
            name.removeprefix(asset_prefix)
            for name in archive.namelist()
            if name.startswith(asset_prefix)
        }
        assert included == set(resources)
        for name in archive.namelist():
            if marker in archive.read(name):
                raise AssertionError("Wheel contains private fixture data")
