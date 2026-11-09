from __future__ import annotations

import os
import runpy
import shutil
import subprocess
import zlib

import pytest
import yaml

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root

GIT_ADAPTERS = [
    ("acme-sh", "acme_sh_ref"),
    ("dehydrated", "dehydrated_ref"),
    ("boulder", "boulder_ref"),
    ("lemur", "lemur_ref"),
]
VERIFIER = project_root() / "roles/pki_adapter/files/verify-git-checkout"


@pytest.mark.parametrize("slug,key", GIT_ADAPTERS)
@pytest.mark.parametrize("reference", ["main", "v1.2.3", "latest", "a" * 12, "A" * 40, "a" * 64])
def test_mutable_or_noncanonical_git_refs_cannot_enter_deployment(slug, key, reference):
    data = load_config(project_root() / "examples/configs/standalone.yml")
    data["spec"]["adapters"]["enabled"] = [slug]
    data["spec"]["adapters"]["acknowledge"] = [slug]
    data["spec"]["adapters"]["versions"][key] = reference
    assert validate_config(data).ok  # Nonproduction templates remain inspectable.
    assert any("full lowercase Git commit" in w for w in validate_config(data).warnings)
    assert any(
        "full lowercase Git commit" in e for e in validate_config(data, for_deployment=True).errors
    )
    data["spec"]["environment"] = "production"
    assert any("full lowercase Git commit" in e for e in validate_config(data).errors)


@pytest.mark.parametrize("slug,key", GIT_ADAPTERS)
def test_full_git_commit_passes_format_preflight_without_claiming_resolution(slug, key):
    data = load_config(project_root() / "examples/configs/standalone.yml")
    data["spec"]["adapters"]["enabled"] = [slug]
    data["spec"]["adapters"]["acknowledge"] = [slug]
    data["spec"]["adapters"]["versions"][key] = "a" * 40
    if slug == "lemur":
        data["spec"]["adapters"]["options"] = {
            "lemur": {
                "requirementsFile": "/reviewed/requirements.lock",
                "configFile": "/reviewed/lemur.py",
            }
        }
    assert validate_config(data, for_deployment=True).ok


@pytest.mark.parametrize(
    "change", ["no-update", "force", "recursive", "moving-submodule", "no-pin", "no-launcher"]
)
def test_source_guard_rejects_git_acquisition_regressions(tmp_path, change):
    shutil.copytree(project_root() / "roles", tmp_path / "roles")
    path = tmp_path / "roles/pki_adapter/tasks/_checkout_verified_git.yml"
    document = yaml.safe_load(path.read_text())
    scanner = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))
    git = next(
        t["ansible.builtin.git"] for t in scanner["tasks"](document) if "ansible.builtin.git" in t
    )
    if change == "no-update":
        git["update"] = False
    elif change == "force":
        git["force"] = True
    elif change == "recursive":
        git["recursive"] = True
    elif change == "moving-submodule":
        git["track_submodules"] = True
    elif change == "no-launcher":
        git.pop("executable")
    else:
        git["version"] = "main"
    path.write_text(yaml.safe_dump(document))
    assert scanner["inspect"](tmp_path)["guardErrors"]


@pytest.mark.skipif(os.name == "nt", reason="Exact POSIX ownership, modes and symlinks")
def test_checkout_verifier_checks_actual_bytes_and_object_graph_without_index_trust(tmp_path):
    verify = runpy.run_path(str(VERIFIER))["verify"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_AUTHOR_NAME="Synthetic verifier fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Synthetic verifier fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )

    def git(*arguments):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false", *arguments],
            cwd=tmp_path,
            env=env,
        )

    git("init", "-b", "fixture")
    script = tmp_path / "script.sh"
    script.write_bytes(b"#!/bin/sh\nexit 0\n")
    script.chmod(0o700)
    data = tmp_path / "data"
    data.write_bytes(b"approved-content\n")
    (tmp_path / ".gitignore").write_text("*.ignored\n")
    (tmp_path / "link").symlink_to("data")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/child").write_text("child\n")
    git("add", "--all")
    git("commit", "-m", "Synthetic exact checkout fixture")
    commit = git("rev-parse", "HEAD").decode().strip()
    repository = "https://example.invalid/fixture.git"
    git("remote", "add", "origin", repository)
    assert verify(tmp_path, commit, repository)["files"] == 5
    before = data.stat()
    git("update-index", "--assume-unchanged", "data")
    data.write_bytes(b"tampered-content\n")
    os.utime(data, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert git("status", "--porcelain") == b""
    with pytest.raises(ValueError, match="file bytes differ"):
        verify(tmp_path, commit, repository)
    data.write_bytes(b"approved-content\n")
    ignored = tmp_path / "extra.ignored"
    ignored.write_text("unreviewed synthetic file")
    with pytest.raises(ValueError, match="untracked or ignored"):
        verify(tmp_path, commit, repository)
    ignored.unlink()
    script.chmod(0o600)
    with pytest.raises(ValueError, match="executable mode"):
        verify(tmp_path, commit, repository)
    script.chmod(0o700)
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    object_path = tmp_path / ".git/objects" / tree[:2] / tree[2:]
    original = object_path.read_bytes()
    decoded = zlib.decompress(original)
    # Git loose objects are read-only. The fixture owns this temporary object;
    # explicitly permit the corruption probe instead of depending on root.
    object_path.chmod(0o600)
    object_path.write_bytes(zlib.compress(decoded[:-1] + bytes([decoded[-1] ^ 1])))
    with pytest.raises(ValueError, match="identity mismatch|inspection failed"):
        verify(tmp_path, commit, repository)
    object_path.write_bytes(original)
    assert verify(tmp_path, commit, repository)["files"] == 5
