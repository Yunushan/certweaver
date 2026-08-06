import json

from certweaver.config import load_config
from certweaver.readiness import (
    REQUIRED_EVIDENCE,
    SCORE_AREAS,
    repo_score,
    score_markdown,
    verify_live_evidence,
    write_evidence_bundle,
)
from certweaver.registry import project_root


def sample() -> dict:
    return load_config(project_root() / "config" / "certweaver.example.yml")


def test_repo_score_is_repo_local_target() -> None:
    assert repo_score() == (97, 100)
    assert "97/100" in score_markdown()
    assert sum(area.maximum for area in SCORE_AREAS) == 100
    assert len({area.area for area in SCORE_AREAS}) == len(SCORE_AREAS)


def test_evidence_bundle_writes_sanitized_artifacts(tmp_path) -> None:
    written = write_evidence_bundle(sample(), tmp_path)
    names = {path.name for path in written}
    assert {
        "README.md",
        "score.md",
        "required-live-evidence.md",
        "plan.txt",
        "config-summary.json",
        "manifest.json",
        "live-checks.sh",
    } <= names

    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["repoScore"] == 97
    assert manifest["repoScoreMaximum"] == 100
    assert manifest["configSha256"]
    assert manifest["validation"]["errors"] == []
    assert b"\r\n" not in (tmp_path / "live-checks.sh").read_bytes()

    summary = json.loads((tmp_path / "config-summary.json").read_text(encoding="utf-8"))
    assert summary["nodeCount"] == 3
    assert "cert-manager" in summary["adaptersEnabled"]
    assert "rke2TokenFile" in summary["secretFilesPresent"]
    assert summary["etcdSnapshotReplication"]["enabled"] is True


def _write_complete_live_evidence(destination) -> None:
    attestation = {
        "status": "pass",
        "observedAt": "2026-08-06T12:00:00Z",
        "operator": "test-operator",
        "source": "automated-test-fixture",
    }
    for requirement in REQUIRED_EVIDENCE:
        for relative in requirement.artifacts:
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.name.endswith("attestation.json"):
                path.write_text(json.dumps(attestation), encoding="utf-8")
            else:
                content = f"Observed pass evidence for {requirement.control}\n"
                path.write_text(content, encoding="utf-8")


def test_live_evidence_requires_complete_sanitized_attestations(tmp_path) -> None:
    evidence = tmp_path / "evidence"
    write_evidence_bundle(sample(), evidence)

    incomplete = verify_live_evidence(evidence, sample())
    assert not incomplete.ok
    assert any("required evidence artifact is missing" in error for error in incomplete.errors)

    _write_complete_live_evidence(evidence)
    complete = verify_live_evidence(evidence, sample())
    assert complete.ok
    assert len(complete.checked_artifacts) == sum(
        len(requirement.artifacts) for requirement in REQUIRED_EVIDENCE
    )


def test_live_evidence_rejects_secrets_and_placeholders(tmp_path) -> None:
    evidence = tmp_path / "evidence"
    write_evidence_bundle(sample(), evidence)
    _write_complete_live_evidence(evidence)

    (evidence / "secret-handling" / "attestation.json").write_text(
        '{"status":"pass","observedAt":"2026-08-06T12:00:00Z",'
        '"operator":"test","source":"token: leaked"}',
        encoding="utf-8",
    )
    (evidence / "incident-readiness.md").write_text("TODO\n", encoding="utf-8")

    result = verify_live_evidence(evidence, sample())
    assert not result.ok
    assert any("sensitive material" in error for error in result.errors)
    assert any("placeholder evidence" in error for error in result.errors)


def test_live_evidence_rejects_invalid_manifest_and_attestation(tmp_path) -> None:
    evidence = tmp_path / "evidence"
    write_evidence_bundle(sample(), evidence)
    _write_complete_live_evidence(evidence)

    manifest = evidence / "manifest.json"
    manifest.write_text("not-json\n", encoding="utf-8")
    result = verify_live_evidence(evidence, sample())
    assert any("manifest is not valid JSON" in error for error in result.errors)

    write_evidence_bundle(sample(), evidence)
    _write_complete_live_evidence(evidence)
    attestation = evidence / "rke2-ha" / "attestation.json"
    invalid_values = (
        "not-json\n",
        "[]\n",
        json.dumps({"status": "fail"}),
        json.dumps({"status": "pass", "observedAt": "not-a-date"}),
        json.dumps({"status": "pass", "observedAt": "2026-08-06T12:00:00"}),
        json.dumps(
            {
                "status": "pass",
                "observedAt": "2026-08-06T12:00:00Z",
                "operator": "",
                "source": "test",
            }
        ),
    )
    for value in invalid_values:
        attestation.write_text(value, encoding="utf-8")
        result = verify_live_evidence(evidence, sample())
        assert not result.ok
