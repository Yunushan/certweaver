import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from certweaver.config import load_config
from certweaver.errors import ConfigurationError
from certweaver.readiness import (
    REQUIRED_EVIDENCE,
    SCORE_AREAS,
    assess_evidence,
    assessment_markdown,
    config_sha256,
    implementation_sha256,
    live_checks_script,
    repo_score,
    score_markdown,
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
        "review.json",
    } <= names

    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["repoScore"] == 97
    assert manifest["repoScoreMaximum"] == 100
    assert manifest["configSha256"]
    assert manifest["validation"]["errors"] == []

    summary = json.loads((tmp_path / "config-summary.json").read_text(encoding="utf-8"))
    assert summary["nodeCount"] == 3
    assert "cert-manager" in summary["adaptersEnabled"]
    assert "rke2TokenFile" in summary["secretFilesPresent"]
    assert summary["etcdSnapshotReplication"]["enabled"] is True


NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)


def reviewed_bundle(tmp_path, config=None):
    config = config or sample()
    write_evidence_bundle(config, tmp_path)
    review_path = tmp_path / "review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["reviewedBy"] = "Staging operations reviewer"
    review["reviewedAt"] = NOW.isoformat()
    for idx, record in enumerate(review["controls"]):
        artifact = tmp_path / f"control-{idx}.txt"
        artifact.write_text(f"Test fixture for {record['control']}\n", encoding="utf-8")
        record.update({
            "status": "passed",
            "observedAt": (NOW - timedelta(hours=1)).isoformat(),
            "artifacts": [{
                "path": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }],
        })
    review_path.write_text(json.dumps(review), encoding="utf-8")
    return config, review


def save_review(tmp_path, review):
    (tmp_path / "review.json").write_text(json.dumps(review), encoding="utf-8")


def test_generated_skeleton_never_earns_live_credit(tmp_path) -> None:
    config = sample()
    write_evidence_bundle(config, tmp_path)
    assessment = assess_evidence(config, tmp_path, now=NOW)
    assert assessment.score == 97
    assert not assessment.complete
    assert len(assessment.pending_controls) == len(REQUIRED_EVIDENCE)
    assert "PENDING / FAIL" in assessment_markdown(assessment)


def test_reviewed_hashed_complete_bundle_passes(tmp_path) -> None:
    config, _ = reviewed_bundle(tmp_path)
    assessment = assess_evidence(config, tmp_path, now=NOW)
    assert assessment.complete
    assert assessment.score == 100
    assert assessment.errors == ()
    assert "human reviewer" in assessment_markdown(assessment)


@pytest.mark.parametrize("field", ["configSha256", "implementationSha256"])
def test_review_must_match_configuration_and_implementation(tmp_path, field) -> None:
    config, review = reviewed_bundle(tmp_path)
    review[field] = "0" * 64
    save_review(tmp_path, review)
    assessment = assess_evidence(config, tmp_path, now=NOW)
    assert not assessment.complete
    assert "does not match" in " ".join(assessment.errors)


@pytest.mark.parametrize("change", ["tampered", "empty", "missing", "digest"])
def test_artifact_integrity_is_required(tmp_path, change) -> None:
    config, review = reviewed_bundle(tmp_path)
    artifact = tmp_path / "control-0.txt"
    if change == "tampered":
        artifact.write_text("Changed after review", encoding="utf-8")
    elif change == "empty":
        artifact.write_text("", encoding="utf-8")
    elif change == "missing":
        artifact.unlink()
    else:
        review["controls"][0]["artifacts"][0]["sha256"] = "not a digest"
        save_review(tmp_path, review)
    assessment = assess_evidence(config, tmp_path, now=NOW)
    assert assessment.score == 97
    assert REQUIRED_EVIDENCE[0].control in assessment.pending_controls
    assert assessment.errors


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "C:/outside.txt", "..\\out"])
def test_artifacts_cannot_escape_evidence_directory(tmp_path, path) -> None:
    config, review = reviewed_bundle(tmp_path)
    review["controls"][0]["artifacts"][0]["path"] = path
    save_review(tmp_path, review)
    assert not assess_evidence(config, tmp_path, now=NOW).complete


@pytest.mark.parametrize("change", ["unknown", "duplicate", "missing", "failed", "no_artifacts"])
def test_every_required_control_needs_its_own_review(tmp_path, change) -> None:
    config, review = reviewed_bundle(tmp_path)
    if change == "unknown":
        review["controls"][0]["control"] = "A made-up control"
    elif change == "duplicate":
        review["controls"].append(review["controls"][0])
    elif change == "missing":
        review["controls"].pop(0)
    elif change == "failed":
        review["controls"][0]["status"] = "failed"
    else:
        review["controls"][0]["artifacts"] = []
    save_review(tmp_path, review)
    assert assess_evidence(config, tmp_path, now=NOW).score == 97


@pytest.mark.parametrize("change", ["stale", "future", "naive", "post_review"])
def test_evidence_must_be_recent_and_reviewed_after_observation(tmp_path, change) -> None:
    config, review = reviewed_bundle(tmp_path)
    if change == "stale":
        review["controls"][0]["observedAt"] = (NOW - timedelta(days=31)).isoformat()
    elif change == "future":
        review["reviewedAt"] = (NOW + timedelta(days=1)).isoformat()
    elif change == "naive":
        review["reviewedAt"] = "2026-10-26T12:00:00"
    else:
        review["controls"][0]["observedAt"] = (NOW + timedelta(minutes=1)).isoformat()
    save_review(tmp_path, review)
    assert not assess_evidence(config, tmp_path, now=NOW).complete


@pytest.mark.parametrize("reviewer", ["", "TODO", "operator", None, []])
def test_review_requires_a_named_accountable_person(tmp_path, reviewer) -> None:
    config, review = reviewed_bundle(tmp_path)
    review["reviewedBy"] = reviewer
    save_review(tmp_path, review)
    assert not assess_evidence(config, tmp_path, now=NOW).complete


@pytest.mark.parametrize("document", ["[]", "{}", '{"controls":[],"controls":[]}', "bad JSON"])
def test_malformed_review_is_a_reported_failure(tmp_path, document) -> None:
    (tmp_path / "review.json").write_text(document, encoding="utf-8")
    assessment = assess_evidence(sample(), tmp_path, now=NOW)
    assert assessment.errors
    assert not assessment.complete


def test_missing_review_is_reported(tmp_path) -> None:
    assert assess_evidence(sample(), tmp_path, now=NOW).errors


def test_invalid_config_cannot_earn_baseline_credit(tmp_path) -> None:
    config = sample()
    config["spec"]["rke2"]["secretsEncryption"] = False
    assessment = assess_evidence(config, tmp_path, now=NOW)
    assert assessment.score == 0
    with pytest.raises(ConfigurationError):
        write_evidence_bundle(config, tmp_path)
    assert not (tmp_path / "review.json").exists()


def test_evidence_bundle_generation_preserves_existing_evidence(tmp_path) -> None:
    reviewed_bundle(tmp_path)
    previous = (tmp_path / "review.json").read_bytes()
    with pytest.raises(ConfigurationError, match="preserve existing evidence"):
        write_evidence_bundle(sample(), tmp_path)
    assert (tmp_path / "review.json").read_bytes() == previous


def test_config_fingerprint_ignores_only_internal_source_metadata() -> None:
    config = sample()
    expected = config_sha256(config)
    config["__source_path__"] = "/somewhere/else/config.yml"
    assert config_sha256(config) == expected
    config["metadata"]["name"] = "a different deployment"
    assert config_sha256(config) != expected


def test_implementation_fingerprint_covers_code_and_assets(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("certweaver.readiness.project_root", lambda: tmp_path)
    (tmp_path / "roles").mkdir()
    asset = tmp_path / "roles" / "test.yml"
    asset.write_text("first version", encoding="utf-8")
    first = implementation_sha256()
    asset.write_text("second version", encoding="utf-8")
    assert implementation_sha256() != first


@pytest.mark.skipif(os.name == "nt" or not shutil.which("bash"), reason="Requires POSIX Bash")
def test_collector_stops_when_a_required_kubernetes_read_fails(tmp_path) -> None:
    script = tmp_path / "collect.sh"
    script.write_text(live_checks_script(), encoding="utf-8")
    executable = tmp_path / "kubectl"
    executable.write_text(
        '#!/usr/bin/env bash\n'
        'if [[ "$*" == *certificaterequests.cert-manager.io* ]]; then exit 7; fi\n'
        'printf "fixture\\n"\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    destination = tmp_path / "collected"
    env = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    result = subprocess.run(["bash", str(script), str(destination)], env=env, check=False)
    assert result.returncode == 7
    assert not (destination / "certificates.txt").exists()
    assert (destination / "observed-at.txt").exists()
