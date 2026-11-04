from __future__ import annotations

import json
import runpy
import subprocess
from pathlib import Path

import pytest

from certweaver.registry import project_root

qualifier = runpy.run_path(str(project_root() / "scripts/qualify-release.py"))


def fixture_pipeline(tmp_path, monkeypatch, failure=None):
    directory = tmp_path / "dist"
    directory.mkdir()
    for name in [
        "certweaver-0.1.0-py3-none-any.whl",
        "certweaver-0.1.0.tar.gz",
        "certweaver-v0.1.0.tar.gz",
        "certweaver-v0.1.0.zip",
    ]:
        (directory / name).write_bytes(b"artifact fixture, not a release")
    stages = []

    def step(name):
        stages.append(name)
        if failure == name:
            raise ValueError(f"fixture {name} denied")

    def install(name, root):
        step("install-" + name)
        return root / name

    def expand(source, destination):
        step("expansion")
        destination.mkdir()
        return {"status": "fixture"}

    def scanner(binary):
        step("scanner-qualification")
        return {"status": "fixture scanner logic only"}

    def check(*args, **kwargs):
        step("handoff")
        return []

    def checkout(*args):
        step("checkout")

    def evidence(*args, **kwargs):
        step("evidence")

    def reproduction(*args, **kwargs):
        step("reproduction")
        return {"fixture": True}

    for part in ("package-build", "package-reproduction"):
        path = tmp_path / f".certweaver/{part}/receipt.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"fixture": true}', encoding="utf-8")

    helpers = {
        "check-release": {
            "release_version": lambda *_: "0.1.0",
            "_checkout": checkout,
            "check_release": check,
        },
        "install-ci-tool": {"install_tool": install, "tool_record": lambda *_: {"fixture": True}},
        "check-secret-scanner": {"qualify_scanner": scanner},
        "expand-release-assets": {"expand_release": expand},
        "release-evidence": {"export_evidence": evidence},
        "check-package-reproducibility": {"qualified_build": reproduction},
        "install-python-deps": {
            "candidate_requirements": lambda root, wheel, destination: destination
        },
    }
    monkeypatch.setitem(qualifier["qualify_release"].__globals__, "helpers", lambda _: helpers)

    def run(command, **kwargs):
        if "pip" in command:
            name = "runtime-install"
            assert "--require-hashes" in command and "--only-binary=:all:" in command
            assert "-I" in command and "--no-compile" in command
            runtime = Path(command[command.index("--target") + 1])
            runtime.mkdir()
            for package, version in [("certweaver", "0.1.0"), ("fixture-dep", "1.2.3")]:
                metadata = runtime / f"{package}-{version}.dist-info"
                metadata.mkdir()
                (metadata / "METADATA").write_text(
                    f"Name: {package}\nVersion: {version}\n", encoding="utf-8"
                )
        elif Path(command[0]).name == "syft":
            name = "runtime-sbom"
            Path(command[-1].split("=", 1)[1]).write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {
                                "name": package,
                                "version": version,
                                "type": "library",
                                "purl": f"pkg:pypi/{package}@{version}",
                            }
                            for package, version in [
                                ("certweaver", "0.1.0"),
                                ("fixture-dep", "1.2.3"),
                            ]
                        ],
                    }
                ),
                encoding="utf-8",
            )
        else:
            name = "runtime-vulnerabilities" if "vuln" in command else "artifact-secrets"
            if name == "runtime-vulnerabilities":
                assert command[1] == "rootfs"
                results = [
                    {
                        "Type": "python-pkg",
                        "Packages": [
                            {"Name": "certweaver", "Version": "0.1.0"},
                            {"Name": "fixture-dep", "Version": "1.2.3"},
                        ],
                    }
                ]
                if failure == "empty-scan":
                    results = []
                if failure == "partial-scan":
                    results[0]["Packages"].pop()
                if failure == "blocking-report":
                    results[0]["Vulnerabilities"] = [{"Severity": "HIGH"}]
            else:
                results = (
                    [] if failure != "secret-report" else [{"Secrets": [{"RuleID": "fixture"}]}]
                )
            if failure != "missing-report":
                Path(command[command.index("--output") + 1]).write_text(
                    json.dumps(
                        {
                            "SchemaVersion": 2,
                            "ArtifactName": command[-1],
                            "Results": results,
                        }
                    ),
                    encoding="utf-8",
                )
        stages.append(name)
        assert not any(key.startswith(("TRIVY_", "SYFT_")) for key in kwargs["env"])
        assert kwargs["env"]["PIP_CONFIG_FILE"] == __import__("os").devnull
        assert "PIP_INDEX_URL" not in kwargs["env"]
        return subprocess.CompletedProcess(
            command, 1 if failure == name else 0, b"fixture stdout", b"fixture stderr"
        )

    monkeypatch.setattr(subprocess, "run", run)
    return directory, stages


def test_shared_qualification_requires_all_stages_and_writes_exact_checksums(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "true")
    directory, stages = fixture_pipeline(tmp_path, monkeypatch)
    result = qualifier["qualify_release"](directory, tag="v0.1.0", commit="a" * 40, root=tmp_path)
    assert result["status"] == "ARTIFACT_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL"
    assert stages == [
        "checkout",
        "reproduction",
        "install-trivy",
        "install-syft",
        "runtime-install",
        "runtime-sbom",
        "scanner-qualification",
        "expansion",
        "runtime-vulnerabilities",
        "artifact-secrets",
        "handoff",
        "evidence",
    ]
    assert len((directory / "SHA256SUMS").read_text().splitlines()) == 5
    assert (
        json.loads((tmp_path / ".certweaver/release-qualification/summary.json").read_text())
        == result
    )


@pytest.mark.parametrize(
    "failure",
    [
        "checkout",
        "reproduction",
        "install-trivy",
        "install-syft",
        "runtime-install",
        "runtime-sbom",
        "scanner-qualification",
        "expansion",
        "runtime-vulnerabilities",
        "artifact-secrets",
        "handoff",
        "evidence",
    ],
)
def test_failed_stage_cannot_produce_a_qualified_summary(tmp_path, monkeypatch, failure):
    directory, stages = fixture_pipeline(tmp_path, monkeypatch, failure)
    with pytest.raises(ValueError):
        qualifier["qualify_release"](directory, tag="v0.1.0", commit="a" * 40, root=tmp_path)
    assert stages[-1] == failure
    assert not (tmp_path / ".certweaver/release-qualification/summary.json").exists()


def test_stale_or_extra_candidate_files_are_rejected_before_installation(tmp_path, monkeypatch):
    directory, stages = fixture_pipeline(tmp_path, monkeypatch)
    (directory / "old.sbom.json").write_text("stale fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="four fresh"):
        qualifier["qualify_release"](directory, tag="v0.1.0", commit="a" * 40, root=tmp_path)
    assert stages == ["checkout"]


@pytest.mark.parametrize(
    "failure", ["empty-scan", "partial-scan", "blocking-report", "secret-report", "missing-report"]
)
def test_exit_zero_without_complete_clean_reports_never_qualifies(tmp_path, monkeypatch, failure):
    directory, _ = fixture_pipeline(tmp_path, monkeypatch, failure)
    with pytest.raises((ValueError, OSError)):
        qualifier["qualify_release"](directory, tag="v0.1.0", commit="a" * 40, root=tmp_path)
    assert not (tmp_path / ".certweaver/release-qualification/summary.json").exists()
