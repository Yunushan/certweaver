from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys

import pytest
import yaml

from certweaver import snapshot
from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-snapshot-config.py"))


def test_validated_receipt_binds_exact_bytes_without_returning_credentials(tmp_path, capsys):
    source = tmp_path / "private.env"
    content = b"etcd-s3-secret-key=private-canary==\r\netcd-s3-insecure=false\r\n"
    source.write_bytes(content)
    assert snapshot.main([str(source)]) == 0
    captured = capsys.readouterr()
    receipt = json.loads(captured.out)
    assert receipt == {
        "schemaVersion": 1,
        "status": "PRODUCTION_SNAPSHOT_INPUT_VALIDATED",
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        "bytes": len(content),
    }
    assert not captured.err and "private-canary" not in captured.out


@pytest.mark.parametrize("size", [65535, 65536, 65537])
def test_env_line_boundary_prevents_silent_client_truncation(tmp_path, size):
    source = tmp_path / "boundary.env"
    prefix = "etcd-s3-secret-key="
    source.write_bytes((prefix + "x" * (size - len(prefix)) + "\n").encode())
    if size == 65535:
        assert snapshot.validate_file(source)["bytes"] == size + 1
    else:
        with pytest.raises(snapshot.SnapshotConfigurationError, match="env-file limit"):
            snapshot.validate_file(source)


def test_env_line_limit_counts_encoded_bytes_including_bom_and_cr(tmp_path):
    for content in [
        "etcd-s3-secret-key=" + "é" * 32768,
        "\ufeff" + "a=" + "x" * 65531,
        "a=" + "x" * 65533 + "\r",
    ]:
        source = tmp_path / "boundary.env"
        source.write_bytes(content.encode())
        assert len(content) <= 65536
        with pytest.raises(snapshot.SnapshotConfigurationError, match="env-file limit"):
            snapshot.validate_file(source)


@pytest.mark.parametrize("kind", ["missing", "directory", "empty", "oversize", "utf8", "unsafe"])
def test_module_errors_never_disclose_source_or_credential_data(tmp_path, capsys, kind):
    source = tmp_path / "private-canary"
    if kind == "directory":
        source.mkdir()
    elif kind != "missing":
        source.write_bytes(
            {
                "empty": b"",
                "oversize": b"#" * (snapshot.MAX_CONFIG_BYTES + 1),
                "utf8": b"\xffprivate-canary",
                "unsafe": b"etcd-s3-insecure=true\nprivate-canary\n",
            }[kind]
        )
    assert snapshot.main([str(source)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Production RKE2 S3 input validation failed\n"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named-pipe behavior")
def test_named_pipe_is_rejected_without_waiting_for_a_writer(tmp_path):
    source = tmp_path / "pipe"
    os.mkfifo(source)
    result = subprocess.run(
        [sys.executable, "-m", "certweaver.snapshot", str(source)],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == b"" and b"validation failed" in result.stderr


def test_snapshot_production_callers_and_transfer_are_mandatory():
    tools["guard"](project_root())


@pytest.mark.parametrize("change", ["github-missing", "github-conditional", "gitlab-missing"])
def test_snapshot_native_gate_is_required_in_both_ci_providers(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github", tmp_path / ".github")
    shutil.copytree(root / "ci", tmp_path / "ci")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    workflows = runpy.run_path(str(root / "scripts/check-release-workflows.py"))
    assert workflows["check_workflows"](tmp_path) == []
    if change.startswith("github"):
        path = tmp_path / ".github/workflows/ci.yml"
        document = workflows["load"](path)
        steps = document["jobs"]["test"]["steps"]
        step = next(s for s in steps if "check-snapshot-config.py" in s.get("run", ""))
        if change == "github-missing":
            steps.remove(step)
        else:
            step["if"] = "false"
    else:
        path = tmp_path / ".gitlab-ci.yml"
        document = workflows["load"](path)
        document["lint-test"]["script"] = [
            s for s in document["lint-test"]["script"] if "check-snapshot-config.py" not in s
        ]
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert any(
        "check-snapshot-config.py" in error for error in workflows["check_workflows"](tmp_path)
    )


@pytest.mark.parametrize(
    "change",
    [
        "disabled-policy",
        "debug",
        "schedule",
        "offhost",
        "delegate",
        "become",
        "connection",
        "check-skipped",
        "logging",
        "diff",
        "allowed-failure",
        "receipt",
        "deploy",
        "upgrade",
        "server",
        "addons",
        "recheck",
        "checksum",
        "digest",
        "size",
        "late-check",
        "publish-check",
        "public-transfer",
        "cleanup",
    ],
)
def test_snapshot_policy_and_exact_transfer_cannot_be_bypassed(tmp_path, change):
    root = project_root()
    for directory in [
        "roles/snapshot_config",
        "roles/rke2_server",
        "roles/cluster_addons",
        "roles/common",
        "playbooks",
    ]:
        shutil.copytree(root / directory, tmp_path / directory)
    tools["guard"](tmp_path)
    role_path = tmp_path / "roles/snapshot_config/tasks/main.yml"
    main_path = tmp_path / "roles/cluster_addons/tasks/main.yml"
    role = yaml.safe_load(role_path.read_text(encoding="utf-8"))
    main = yaml.safe_load(main_path.read_text(encoding="utf-8"))
    policy = role[0]
    assertion, command, receipt = policy["block"]
    block = next(t for t in main if t["name"] == "Reconcile RKE2 S3 snapshot secret")
    tasks = block["block"]
    transfer = next(t for t in tasks if t["name"].startswith("Stage RKE2"))
    binding = next(t for t in tasks if t["name"].startswith("Require exactly"))
    if change == "disabled-policy":
        policy["when"].append("certweaver_rke2_etcd_s3_enabled | bool")
    elif change in {"debug", "schedule", "offhost"}:
        assertion["ansible.builtin.assert"]["that"].pop(
            {"debug": 0, "schedule": 1, "offhost": 2}[change]
        )
    elif change in {"delegate", "become", "check-skipped", "logging", "diff", "allowed-failure"}:
        key, value = {
            "delegate": ("delegate_to", "remote"),
            "become": ("become", True),
            "check-skipped": ("check_mode", True),
            "logging": ("no_log", False),
            "diff": ("diff", True),
            "allowed-failure": ("failed_when", False),
        }[change]
        command[key] = value
    elif change == "connection":
        command["vars"]["ansible_connection"] = "ssh"
    elif change == "receipt":
        receipt["ansible.builtin.set_fact"]["certweaver_snapshot_policy"] = {"sha256": "fake"}
    elif change in {"deploy", "upgrade"}:
        path = tmp_path / (
            "playbooks/rke2-ha.yml" if change == "deploy" else "playbooks/upgrade.yml"
        )
        plays = yaml.safe_load(path.read_text(encoding="utf-8"))
        plays[0]["pre_tasks"] = []
        path.write_text(yaml.safe_dump(plays), encoding="utf-8")
    elif change == "server":
        path = tmp_path / "roles/rke2_server/tasks/main.yml"
        server = yaml.safe_load(path.read_text(encoding="utf-8"))
        server.pop(2)
        path.write_text(yaml.safe_dump(server), encoding="utf-8")
    elif change == "addons":
        main.pop(1)
    elif change == "recheck":
        tasks.pop(1)
    elif change == "checksum":
        transfer["ansible.builtin.copy"].pop("checksum")
    elif change in {"digest", "size"}:
        binding["ansible.builtin.assert"]["that"].pop(0 if change == "digest" else 1)
    elif change == "late-check":
        tasks.remove(binding)
        tasks.append(binding)
    elif change == "publish-check":
        block["when"].remove("not ansible_check_mode")
    elif change == "public-transfer":
        transfer["ansible.builtin.copy"]["mode"] = "0644"
    elif change == "cleanup":
        block["always"][0]["when"] = False
    role_path.write_text(yaml.safe_dump(role), encoding="utf-8")
    main_path.write_text(yaml.safe_dump(main), encoding="utf-8")
    with pytest.raises((ValueError, KeyError, IndexError, StopIteration)):
        tools["guard"](tmp_path)
