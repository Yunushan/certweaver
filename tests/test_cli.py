from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

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
    assert invoke_cli(
        monkeypatch, ["render-inventory", "-c", str(CONFIG), "-o", str(inventory)]
    ) == 0
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

    def fake_run(command: list[str], check: bool) -> SimpleNamespace:
        captured.append(command)
        assert check is False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    inventory = tmp_path / "inventory.yml"
    assert invoke_cli(
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
    ) == 0
    assert captured[0][-5:] == ["--check", "--limit", "rke2-01", "--tags", "rke2"]
    assert "Executing: ansible-playbook" in capsys.readouterr().out


def test_cli_reports_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    broken = tmp_path / "broken.yml"
    broken.write_text("not: [valid", encoding="utf-8")
    assert invoke_cli(monkeypatch, ["validate", "-c", str(broken)]) == 2
    assert "certweaver: Invalid YAML" in capsys.readouterr().err
