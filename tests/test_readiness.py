import json

from certweaver.config import load_config
from certweaver.readiness import (
    SCORE_AREAS,
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
