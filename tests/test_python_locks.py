from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import subprocess
from pathlib import Path

import pytest

from certweaver.registry import project_root

installer = runpy.run_path(str(project_root() / "scripts/install-python-deps.py"))


def lock_fixture(tmp_path):
    shutil.copytree(project_root() / "ci", tmp_path / "ci")
    shutil.copyfile(project_root() / "pyproject.toml", tmp_path / "pyproject.toml")
    return tmp_path / "ci/python-locks.json"


def replace_lock(tmp_path, text):
    path = tmp_path / "ci/python-runtime.lock"
    path.write_text(text, encoding="utf-8")
    manifest_path = tmp_path / "ci/python-locks.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["locks"]["runtime"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_committed_locks_are_bound_to_current_inputs_and_include_complete_profiles():
    for profile in ("runtime", "build", "dev"):
        assert installer["lock_file"](project_root(), profile).is_file()


@pytest.mark.parametrize(
    "change",
    [
        "input",
        "lock",
        "manifest-duplicate",
        "path",
        "profile",
        "schema",
        "missing-input",
    ],
)
def test_invalid_locks_are_rejected_before_any_installer_runs(tmp_path, monkeypatch, change):
    manifest_path = lock_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    profile = "runtime"
    if change == "input":
        (tmp_path / "pyproject.toml").write_text("changed inputs", encoding="utf-8")
    elif change == "lock":
        (tmp_path / "ci/python-runtime.lock").write_text("changed lock", encoding="utf-8")
    elif change == "manifest-duplicate":
        manifest_path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
    elif change == "path":
        manifest["locks"]["runtime"]["path"] = "../untrusted.lock"
    elif change == "profile":
        profile = "unapproved"
    elif change == "schema":
        manifest["schemaVersion"] = True
    elif change == "missing-input":
        manifest["inputs"].pop("pyproject.toml")
    if change in {"path", "schema", "missing-input"}:
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        installer["install_profile"](tmp_path, profile)
    assert calls == []


@pytest.mark.parametrize(
    "text",
    [
        "package>=1.0 --hash=sha256:" + "a" * 64,
        "package==1.0",
        "",
        "-r other.lock",
        "--extra-index-url https://invalid",
        "package @ https://invalid/archive.whl --hash=sha256:" + "a" * 64,
        "package==1.0 --hash=md5:" + "a" * 32,
        "package==1.0 --hash=sha256:" + "a" * 63,
        "package==1.0 --hash=sha256:" + "a" * 64 + " --trusted-host invalid",
    ],
)
def test_unsafe_requirement_syntax_is_rejected_even_with_a_matching_manifest(tmp_path, text):
    lock_fixture(tmp_path)
    replace_lock(tmp_path, text)
    with pytest.raises(ValueError, match="exact versions|bounded regular"):
        installer["lock_file"](tmp_path, "runtime")


@pytest.mark.parametrize("editable", [False, True])
def test_installer_bootstraps_pinned_pip_and_disables_resolution_and_config_overrides(
    tmp_path, monkeypatch, editable
):
    lock_fixture(tmp_path)
    monkeypatch.setenv("PIP_INDEX_URL", "https://unapproved.invalid")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://extra.invalid")
    monkeypatch.setenv("PIP_CONFIG_FILE", str(tmp_path / "unapproved.ini"))
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        environment = kwargs["env"]
        assert environment["PIP_CONFIG_FILE"] == os.devnull
        assert not any(key.startswith("PIP_") and key != "PIP_CONFIG_FILE" for key in environment)
        assert "-I" in command and kwargs["check"] is True
        if len(calls) == 1:
            assert Path(command[-1]).read_text().startswith("pip==")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    installer["install_profile"](tmp_path, "build", project=not editable, editable=editable)
    assert len(calls) == 4
    assert all(
        "--require-hashes" in command and "--only-binary=:all:" in command for command in calls[:2]
    )
    assert "--no-deps" in calls[2] and "--no-build-isolation" in calls[2]
    assert ("--editable" in calls[2]) is editable
    assert calls[3][-1] == "check"


def test_candidate_requirement_binds_local_wheel_bytes_and_refuses_to_overwrite(tmp_path):
    lock_fixture(tmp_path)
    wheel = tmp_path / "candidate with spaces.whl"
    wheel.write_bytes(b"synthetic wheel identity, not installable")
    output = tmp_path / "candidate.lock"
    installer["candidate_requirements"](tmp_path, wheel, output)
    text = output.read_text()
    assert wheel.as_uri() in text
    assert "--hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() in text
    assert (tmp_path / "ci/python-runtime.lock").read_text().strip() in text
    with pytest.raises(FileExistsError):
        installer["candidate_requirements"](tmp_path, wheel, output)
