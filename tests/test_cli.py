from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from certweaver import cli
from certweaver.registry import project_root

CONFIG = project_root() / "config" / "certweaver.example.yml"


def invoke_cli(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["certweaver", *args])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def test_cli_reports_validation_matrix_plan_and_score(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert invoke_cli(monkeypatch, ["validate", "-c", str(CONFIG)]) == 0
    assert "Configuration is valid" in capsys.readouterr().out

    assert invoke_cli(monkeypatch, ["matrix"]) == 0
    assert "cert-manager" in capsys.readouterr().out

    assert invoke_cli(monkeypatch, ["plan", "-c", str(CONFIG)]) == 0
    assert "Bootstrap first RKE2 server" in capsys.readouterr().out

    assert invoke_cli(monkeypatch, ["score"]) == 0
    assert "Repo-local production maturity" in capsys.readouterr().out


def test_cli_renders_inventory_and_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    inventory = tmp_path / "inventory.yml"
    assert (
        invoke_cli(monkeypatch, ["render-inventory", "-c", str(CONFIG), "-o", str(inventory)]) == 0
    )
    assert inventory.exists()
    assert str(inventory) in capsys.readouterr().out

    evidence = tmp_path / "evidence"
    assert invoke_cli(monkeypatch, ["evidence", "-c", str(CONFIG), "-o", str(evidence)]) == 0
    assert (evidence / "manifest.json").exists()
    assert "Evidence bundle written" in capsys.readouterr().out


def test_cli_deploy_builds_expected_ansible_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    captured: list[list[str]] = []

    def fake_run(command: list[str], check: bool, env: dict[str, str]) -> SimpleNamespace:
        captured.append(command)
        assert check is False
        assert Path(command[2]).is_absolute()
        assert env["ANSIBLE_ROLES_PATH"].split(cli.os.pathsep)[0] == str(project_root() / "roles")
        assert env["ANSIBLE_CONFIG"] == str(project_root() / "ansible.cfg")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli.shutil, "which", lambda _: "ansible-playbook")
    monkeypatch.setattr(cli, "_required_secret_files", lambda _: {})
    monkeypatch.delenv("ANSIBLE_CONFIG", raising=False)
    inventory = tmp_path / "inventory.yml"
    assert (
        invoke_cli(
            monkeypatch,
            [
                "deploy",
                "-c",
                str(CONFIG),
                "-i",
                str(inventory),
                "--check",
                "--limit",
                "rke2-01",
                "--tags",
                "rke2",
            ],
        )
        == 0
    )
    assert captured[0][-5:] == ["--check", "--limit", "rke2-01", "--tags", "rke2"]
    assert "Executing: ansible-playbook" in capsys.readouterr().out


def test_cli_reports_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    broken = tmp_path / "broken.yml"
    broken.write_text("not: [valid", encoding="utf-8")
    assert invoke_cli(monkeypatch, ["validate", "-c", str(broken)]) == 2
    assert "certweaver: Invalid YAML" in capsys.readouterr().err


def test_cli_deploy_requires_ansible_before_writing_inventory(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    inventory = tmp_path / "inventory.yml"
    assert invoke_cli(monkeypatch, ["deploy", "-c", str(CONFIG), "-i", str(inventory)]) == 2
    assert not inventory.exists()
    assert "ansible-playbook is required" in capsys.readouterr().err


def test_cli_deploy_requires_secret_files_before_writing_inventory(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli.shutil, "which", lambda _: "ansible-playbook")
    monkeypatch.setattr(
        cli, "_required_secret_files", lambda _: {"etcd S3 configuration": tmp_path / "absent"}
    )
    inventory = tmp_path / "inventory.yml"
    assert invoke_cli(monkeypatch, ["deploy", "-c", str(CONFIG), "-i", str(inventory)]) == 2
    assert not inventory.exists()
    assert "Required etcd S3 configuration file is missing" in capsys.readouterr().err


def test_required_secret_files_resolve_relative_to_configuration():
    config = cli.load_config(CONFIG)
    files = cli._required_secret_files(config)
    assert files["RKE2/K3s token"] == CONFIG.parent / "secrets" / "rke2-token"
    assert files["etcd S3 configuration"] == CONFIG.parent / "secrets" / "etcd-s3.env"
    config["spec"]["platform"]["loadBalancer"]["enabled"] = False
    assert "Keepalived authentication" not in cli._required_secret_files(config)
    assert cli._required_secret_files({"spec": {"mode": "standalone"}}) == {}


@pytest.mark.parametrize("key", ["etcd-s3-insecure", "etcd-s3-skip-ssl-verify"])
def test_deploy_rejects_unsafe_backup_transport_before_inventory_or_ansible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], key: str
) -> None:
    data = cli.load_config(CONFIG)
    data.pop("__source_path__")
    secret = tmp_path / "s3.env"
    secret.write_text(f"etcd-s3-secret-key=private-canary\n{key}=true\n", encoding="utf-8")
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = "s3.env"
    config = tmp_path / "config.yml"
    config.write_text(yaml.safe_dump(data), encoding="utf-8")
    inventory = tmp_path / "inventory.yml"
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **kw: pytest.fail("Ansible invoked"))
    assert invoke_cli(monkeypatch, ["deploy", "-c", str(config), "-i", str(inventory)]) == 2
    assert not inventory.exists()
    output = capsys.readouterr()
    assert f"requires {key}=false" in output.err
    assert "private-canary" not in output.out + output.err


def test_cli_score_rejects_incomplete_evidence(monkeypatch, tmp_path, capsys):
    assert invoke_cli(monkeypatch, ["evidence", "-c", str(CONFIG), "-o", str(tmp_path)]) == 0
    capsys.readouterr()
    assert invoke_cli(monkeypatch, ["score", "-c", str(CONFIG), "--evidence", str(tmp_path)]) == 2
    assert "97/100" in capsys.readouterr().out


def test_cli_score_config_requires_evidence(monkeypatch, capsys):
    assert invoke_cli(monkeypatch, ["score", "-c", str(CONFIG)]) == 2
    assert "requires --evidence" in capsys.readouterr().err


def test_cli_reports_filesystem_errors_without_traceback(monkeypatch, tmp_path, capsys):
    destination = tmp_path / "file"
    destination.write_text("occupied", encoding="utf-8")
    assert (
        invoke_cli(
            monkeypatch,
            ["render-inventory", "-c", str(CONFIG), "-o", str(destination / "inventory.yml")],
        )
        == 2
    )
    error = capsys.readouterr().err
    assert "certweaver:" in error
    assert "Traceback" not in error


def test_doctor_reports_malformed_spec_without_crashing(monkeypatch, tmp_path, capsys):
    config = tmp_path / "invalid.yml"
    config.write_text("spec: null\n", encoding="utf-8")
    assert invoke_cli(monkeypatch, ["doctor", "-c", str(config)]) == 2
    assert "ERROR: Schema:" in capsys.readouterr().out
