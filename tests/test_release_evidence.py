from __future__ import annotations

import copy
import hashlib
import json
import runpy
import shutil
from datetime import UTC, datetime, timedelta

import pytest

from certweaver.registry import project_root

evidence = runpy.run_path(str(project_root() / "scripts/release-evidence.py"))
NOW = datetime(2026, 11, 3, 7, 0, tzinfo=UTC)
START = NOW - timedelta(minutes=2)
COMMIT = "a" * 40


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def export_fixture(tmp_path):
    source = project_root()
    for name in ("ci", "scripts"):
        shutil.copytree(source / name, tmp_path / name)
    shutil.copyfile(source / "pyproject.toml", tmp_path / "pyproject.toml")
    work = tmp_path / ".certweaver/release-qualification"
    work.mkdir(parents=True)
    directory = tmp_path / "dist"
    directory.mkdir()
    (directory / "certweaver-0.1.0-py3-none-any.whl").write_text(
        "synthetic artifact bytes", encoding="utf-8"
    )
    (directory / "certweaver-0.1.0.tar.gz").write_text("synthetic sdist bytes", encoding="utf-8")
    dump(
        directory / "certweaver-v0.1.0.sbom.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": name,
                    "version": version,
                    "type": "library",
                    "purl": f"pkg:pypi/{name}@{version}",
                }
                for name, version in [("certweaver", "0.1.0"), ("fixture-dependency", "1.2.3")]
            ],
        },
    )
    scanner = {
        "status": "SCANNER_QUALIFIED_WITH_SYNTHETIC_FIXTURES",
        "observations": [
            {"case": "clean", "exitCode": 0, "secretFindings": 0},
            {"case": "expanded-archives", "exitCode": 1, "secretFindings": 6},
        ],
    }
    # Deliberately include sensitive-looking data in original reports and logs.
    # The exporter must never serialize these values into its derived record.
    dump(work / "runtime-install.json", {"url": "https://user:DO_NOT_EXPORT@invalid/?token=CANARY"})
    dump(work / "runtime-vulnerabilities.json", {"Target": "/private/RUNNER_PATH/runtime"})
    dump(work / "artifact-secrets.json", {"Results": [], "unrelated": "DO_NOT_EXPORT"})
    dump(work / "scanner-qualification.json", scanner)
    for name in ("package-build.json", "package-reproduction.json"):
        dump(work / name, {"fixture": "derived hashes only"})
    dump(
        work / "archive-inspection.json",
        {
            "filesAndDirectories": 25,
            "expandedBytes": 400,
            "destination": "/private/RUNNER_PATH/inspection",
        },
    )
    (work / "runtime-install.log").write_text("DO_NOT_EXPORT CANARY", encoding="utf-8")
    dump(
        work / "trivy-cache/db/metadata.json",
        {
            "Version": 2,
            "UpdatedAt": (NOW - timedelta(hours=1)).isoformat(),
            "DownloadedAt": START.isoformat(),
            "NextUpdate": (NOW + timedelta(hours=5)).isoformat(),
            "unknown": "DO_NOT_EXPORT",
        },
    )
    (work / "trivy-cache/db/trivy.db").write_bytes(b"synthetic database identity, not CVE data")
    lock_path = tmp_path / "ci/tools.lock.json"
    lock = json.loads(lock_path.read_text())
    scanner_tools = {name: lock["tools"][name] for name in ("trivy", "syft")}
    for name, record in scanner_tools.items():
        binary = tmp_path / f".certweaver/tools/{name}"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"synthetic tool; never executed")
        record["executableSha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        dump(
            binary.with_name(name + ".receipt.json"),
            {
                **record,
                "name": name,
                "status": "LOCKED_CI_TOOL_VERIFIED",
                "verificationMode": "CACHED_EXECUTABLE",
                "archiveVerifiedThisRun": False,
                "unrelated": "DO_NOT_EXPORT",
            },
        )
    dump(lock_path, lock)
    summary = {
        "status": "ARTIFACT_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL",
        "tag": "v0.1.0",
        "sourceCommit": COMMIT,
        "packageReproducibility": {
            "status": "BYTE_IDENTICAL_PACKAGE_REBUILD_NOT_PRODUCTION_APPROVAL",
            "sourceCommit": COMMIT,
            "sourceDateEpoch": 1767225600,
            "freshSourceClone": True,
            "freshLockedEnvironment": True,
            "independentReviewerApproval": False,
            "artifacts": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in directory.iterdir()
                if p.name.endswith((".whl", ".tar.gz"))
            },
        },
        "scannerQualification": scanner,
        "verifiedRuntimeInventory": {"certweaver": "0.1.0", "fixture-dependency": "1.2.3"},
        "tools": scanner_tools,
    }
    return work, directory, summary


def export(tmp_path, work, directory, summary):
    return evidence["export_evidence"](
        tmp_path, work, directory, summary, started=START, finished=NOW
    )


def verify(record, tmp_path, directory, *, now=NOW):
    evidence["verify_record"](
        record, root=tmp_path, directory=directory, tag="v0.1.0", commit=COMMIT, now=now
    )


def test_export_binds_identity_and_omits_logs_urls_paths_and_unselected_fields(tmp_path):
    work, directory, summary = export_fixture(tmp_path)
    output = export(tmp_path, work, directory, summary)
    text = output.read_text()
    assert all(canary not in text for canary in ("DO_NOT_EXPORT", "CANARY", "RUNNER_PATH"))
    record = json.loads(text)
    verify(record, tmp_path, directory)
    assert record["tools"]["trivy"]["archiveVerifiedThisRun"] is False
    assert (
        record["database"]["databaseSha256"]
        == hashlib.sha256((work / "trivy-cache/db/trivy.db").read_bytes()).hexdigest()
    )
    assert set(output.parent.iterdir()) == {output}


@pytest.mark.parametrize(
    "change",
    [
        "missing-db",
        "empty-db",
        "missing-metadata",
        "schema",
        "stale",
        "expired",
        "future-update",
        "future-download",
        "old-download",
        "naive-time",
        "reversed-update",
        "duplicate-key",
        "scanner-missing",
        "scanner-count",
        "archive-count",
        "receipt",
        "receipt-mode",
        "tool-tamper",
        "inventory-url",
        "existing-output",
    ],
)
def test_invalid_qualification_cannot_export_a_passing_record(tmp_path, change):
    work, directory, summary = export_fixture(tmp_path)
    metadata_path = work / "trivy-cache/db/metadata.json"
    metadata = json.loads(metadata_path.read_text())
    if change == "missing-db":
        (work / "trivy-cache/db/trivy.db").unlink()
    elif change == "empty-db":
        (work / "trivy-cache/db/trivy.db").write_bytes(b"")
    elif change == "missing-metadata":
        metadata_path.unlink()
    elif change == "schema":
        metadata["Version"] = 1
    elif change == "stale":
        metadata["UpdatedAt"] = (NOW - timedelta(hours=25)).isoformat()
    elif change == "expired":
        metadata["NextUpdate"] = NOW.isoformat()
    elif change == "future-update":
        metadata["UpdatedAt"] = (NOW + timedelta(minutes=6)).isoformat()
    elif change == "future-download":
        metadata["DownloadedAt"] = (NOW + timedelta(minutes=6)).isoformat()
    elif change == "old-download":
        metadata["DownloadedAt"] = (START - timedelta(minutes=6)).isoformat()
    elif change == "naive-time":
        metadata["UpdatedAt"] = "2026-11-03T06:00:00"
    elif change == "reversed-update":
        metadata["NextUpdate"] = metadata["UpdatedAt"]
    elif change == "duplicate-key":
        metadata_path.write_text('{"Version":2,"Version":2}', encoding="utf-8")
    elif change == "scanner-missing":
        (work / "scanner-qualification.json").unlink()
    elif change == "scanner-count":
        summary["scannerQualification"]["observations"][1]["secretFindings"] = 3
        dump(work / "scanner-qualification.json", summary["scannerQualification"])
    elif change == "archive-count":
        dump(work / "archive-inspection.json", {"filesAndDirectories": 0, "expandedBytes": 1})
    elif change in {"receipt", "receipt-mode"}:
        receipt_path = tmp_path / ".certweaver/tools/trivy.receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["status" if change == "receipt" else "archiveVerifiedThisRun"] = True
        dump(receipt_path, receipt)
    elif change == "tool-tamper":
        (tmp_path / ".certweaver/tools/trivy").write_bytes(b"changed after verification")
    elif change == "inventory-url":
        summary["verifiedRuntimeInventory"]["fixture-dependency"] = "https://private/token"
    elif change == "existing-output":
        dump(tmp_path / "release-evidence/operator.json", {"preserve": True})
    if change in {
        "schema",
        "stale",
        "expired",
        "future-update",
        "future-download",
        "old-download",
        "naive-time",
        "reversed-update",
    }:
        dump(metadata_path, metadata)
    with pytest.raises((OSError, ValueError)):
        export(tmp_path, work, directory, summary)
    assert not (tmp_path / "release-evidence/qualification.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "artifact",
        "extra-artifact",
        "source",
        "policy",
        "expired-at-publication",
        "future-record",
        "wrong-commit",
        "missing-original-hash",
        "bad-original-hash",
        "wrong-database-policy",
        "unscanned",
        "extra-field",
        "wrong-tool",
        "inventory-substitution",
    ],
)
def test_publication_rejects_changed_incomplete_or_expired_evidence(tmp_path, change):
    work, directory, summary = export_fixture(tmp_path)
    output = export(tmp_path, work, directory, summary)
    record = copy.deepcopy(json.loads(output.read_text()))
    now = NOW
    if change == "artifact":
        (directory / "certweaver-0.1.0-py3-none-any.whl").write_bytes(b"substitution")
    elif change == "extra-artifact":
        (directory / "unreviewed.txt").write_bytes(b"unreviewed")
    elif change == "source":
        record["sourceCommit"] = "b" * 40
    elif change == "policy":
        (tmp_path / "ci/secret-scan.yaml").write_text("changed", encoding="utf-8")
    elif change == "expired-at-publication":
        now += timedelta(hours=5)
    elif change == "future-record":
        now -= timedelta(minutes=6)
    elif change == "wrong-commit":
        record["sourceCommit"] = "main"
    elif change == "missing-original-hash":
        record["originalReportSha256"].pop("runtime-vulnerabilities.json")
    elif change == "bad-original-hash":
        record["originalReportSha256"]["runtime-vulnerabilities.json"] = "not-a-hash"
    elif change == "wrong-database-policy":
        record["database"]["policy"]["maximumAgeHours"] = 900
    elif change == "unscanned":
        record["vulnerabilityScan"]["inventoryReconciled"] = False
    elif change == "extra-field":
        record["logs"] = "unexpected raw output"
    elif change == "wrong-tool":
        record["tools"]["trivy"]["executableSha256"] = "f" * 64
    elif change == "inventory-substitution":
        record["runtimeInventory"]["fixture-dependency"] = "9.9.9"
    with pytest.raises(ValueError):
        verify(record, tmp_path, directory, now=now)


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX symlink permission semantics")
def test_linked_database_cannot_be_used_as_original_evidence(tmp_path):
    work, directory, summary = export_fixture(tmp_path)
    database = work / "trivy-cache/db/trivy.db"
    outside = tmp_path / "unrelated.db"
    outside.write_bytes(database.read_bytes())
    database.unlink()
    database.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        export(tmp_path, work, directory, summary)
