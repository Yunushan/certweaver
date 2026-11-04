"""Export and verify a bounded qualification record, without logs or secret matches.

This record is derived local evidence. It does not replace retained original
reports, upstream signature verification or independent production approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_DB_BYTES = 2 * 1024 * 1024 * 1024
MAX_DB_AGE = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
STATUS = "DERIVED_QUALIFICATION_EVIDENCE_NOT_PRODUCTION_APPROVAL"
REPORTS = {
    "package-build.json",
    "package-reproduction.json",
    "runtime-install.json",
    "runtime-vulnerabilities.json",
    "artifact-secrets.json",
    "scanner-qualification.json",
    "archive-inspection.json",
}
DATABASE_POLICY = {
    "maximumAgeHours": 24,
    "clockSkewMinutes": 5,
    "unexpiredNextUpdateRequired": True,
    "freshDownloadRequired": True,
}


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate evidence JSON key")
        result[key] = value
    return result


def regular(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Evidence input must be one bounded nonempty regular file")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Evidence input exceeds its size limit")
    return value


def document(path: Path) -> dict:
    value = json.loads(regular(path, MAX_JSON_BYTES), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("Evidence input must be a JSON object")
    return value


def sha256(path: Path, limit: int = MAX_JSON_BYTES) -> str:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Evidence hash input must be one bounded nonempty regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Evidence timestamp must be an aware ISO timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Evidence timestamp must include its timezone")
    return parsed.astimezone(UTC)


def validate_database(metadata: dict, *, started: datetime, finished: datetime) -> None:
    if type(metadata.get("Version")) is not int or metadata["Version"] != 2:
        raise ValueError("Unsupported vulnerability database schema")
    updated, downloaded, next_update = (
        timestamp(metadata.get(key)) for key in ("UpdatedAt", "DownloadedAt", "NextUpdate")
    )
    if not (
        started <= finished
        and updated <= downloaded + CLOCK_SKEW
        and updated <= finished + CLOCK_SKEW
        and started - CLOCK_SKEW <= downloaded <= finished + CLOCK_SKEW
        and timedelta(0) <= finished - updated + CLOCK_SKEW <= MAX_DB_AGE + CLOCK_SKEW
        and updated < next_update
        and finished < next_update
    ):
        raise ValueError("Vulnerability database chronology or freshness policy failed")


def database_record(work: Path, *, started: datetime, finished: datetime) -> dict:
    cache = work / "trivy-cache/db"
    if cache.is_symlink() or not cache.resolve().is_relative_to(work.resolve()):
        raise ValueError("Vulnerability database cache escapes qualification storage")
    metadata = document(cache / "metadata.json")
    validate_database(metadata, started=started, finished=finished)
    return {
        "metadata": {
            key: metadata[key] for key in ("Version", "UpdatedAt", "DownloadedAt", "NextUpdate")
        },
        "metadataSha256": sha256(cache / "metadata.json"),
        "databaseSha256": sha256(cache / "trivy.db", MAX_DB_BYTES),
        "policy": DATABASE_POLICY.copy(),
    }


def export_evidence(
    root: Path, work: Path, directory: Path, summary: dict, *, started: datetime, finished: datetime
) -> Path:
    destination = root / "release-evidence"
    if destination.exists() or destination.is_symlink():
        raise ValueError("Refusing to replace existing qualification evidence")
    if not destination.resolve().is_relative_to(root.resolve()):
        raise ValueError("Qualification evidence storage escapes checkout")
    scanner = document(work / "scanner-qualification.json")
    if (
        summary.get("status") != "ARTIFACT_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL"
        or scanner != summary.get("scannerQualification")
        or scanner.get("status") != "SCANNER_QUALIFIED_WITH_SYNTHETIC_FIXTURES"
        or scanner.get("observations")
        != [
            {"case": "clean", "exitCode": 0, "secretFindings": 0},
            {"case": "expanded-archives", "exitCode": 1, "secretFindings": 6},
        ]
    ):
        raise ValueError("Successful scanner controls and qualification are required")
    # Whitelisting keeps pip URLs, environment values, source snippets, secret
    # matches, runner paths and process output out of the transferable record.
    original_reports = {name: sha256(work / name) for name in sorted(REPORTS)}
    inspection = document(work / "archive-inspection.json")
    counts = {key: inspection.get(key) for key in ("filesAndDirectories", "expandedBytes")}
    if any(type(value) is not int or value <= 0 for value in counts.values()):
        raise ValueError("Archive inspection evidence must contain positive counts")
    tools = {}
    for name in ("trivy", "syft"):
        receipt_path = root / f".certweaver/tools/{name}.receipt.json"
        receipt = document(receipt_path)
        lock = summary["tools"][name]
        if (
            set(lock)
            != {"repository", "version", "url", "archiveSha256", "executableSha256", "member"}
            or any(receipt.get(key) != value for key, value in lock.items())
            or receipt.get("status") != "LOCKED_CI_TOOL_VERIFIED"
            or receipt.get("name") != name
            or receipt.get("verificationMode")
            not in {"CACHED_EXECUTABLE", "OFFLINE_ARCHIVE", "DOWNLOADED_ARCHIVE"}
            or receipt.get("archiveVerifiedThisRun")
            is not (receipt["verificationMode"] != "CACHED_EXECUTABLE")
            or sha256(root / f".certweaver/tools/{name}", MAX_DB_BYTES) != lock["executableSha256"]
        ):
            raise ValueError("CI tool receipt does not match the qualified executable")
        tools[name] = {
            **lock,
            "verificationMode": receipt["verificationMode"],
            "archiveVerifiedThisRun": receipt["archiveVerifiedThisRun"],
            "receiptSha256": sha256(receipt_path),
        }
    record = {
        "schemaVersion": 1,
        "status": STATUS,
        "sourceCommit": summary["sourceCommit"],
        "tag": summary["tag"],
        "startedAt": started.isoformat(),
        "finishedAt": finished.isoformat(),
        "artifacts": {p.name: sha256(p, MAX_DB_BYTES) for p in sorted(directory.iterdir())},
        "runtimeInventory": summary["verifiedRuntimeInventory"],
        "packageReproducibility": summary["packageReproducibility"],
        "vulnerabilityScan": {
            "target": "installed Python runtime",
            "severities": ["HIGH", "CRITICAL"],
            "blockingFindings": 0,
            "inventoryReconciled": True,
        },
        "secretScan": {
            "target": "expanded candidate archives",
            "allSeverities": True,
            "findings": 0,
            "cleanControlFindings": 0,
            "seededControlFindings": 6,
        },
        "archiveInspection": counts,
        "database": database_record(work, started=started, finished=finished),
        "tools": tools,
        "originalReportSha256": original_reports,
        "policySourceSha256": {
            path: sha256(root / path)
            for path in (
                "ci/tools.lock.json",
                "ci/secret-scan.yaml",
                "scripts/qualify-release.py",
                "scripts/release-evidence.py",
                "scripts/check-secret-scanner.py",
                "scripts/expand-release-assets.py",
                "scripts/check-release.py",
                "scripts/install-ci-tool.py",
                "scripts/install-python-deps.py",
                "scripts/build-package.py",
                "scripts/check-package-reproducibility.py",
                "ci/python-locks.json",
                "ci/python-runtime.lock",
                "ci/python-build.lock",
                "ci/python-dev.lock",
                "ci/python-build.in",
                "pyproject.toml",
            )
        },
        "limitations": [
            "Derived facts and original-report hashes; "
            "original reports require separate protected retention",
            "Database hash is an identity record, not an upstream signature or archived database",
            "No independent control review, hosted CI proof or production approval is inferred",
        ],
    }
    # Verify before creating a transferable output. A failed export cannot leave
    # an apparently successful qualification evidence file behind.
    verify_record(
        record,
        directory=directory,
        root=root,
        tag=summary["tag"],
        commit=summary["sourceCommit"],
        now=finished,
    )
    destination.mkdir(mode=0o700)
    output = destination / "qualification.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    output.chmod(0o600)
    return output


def verify_record(
    record: dict, *, directory: Path, root: Path, tag: str, commit: str, now: datetime
) -> None:
    if (
        set(record)
        != {
            "schemaVersion",
            "status",
            "sourceCommit",
            "tag",
            "startedAt",
            "finishedAt",
            "artifacts",
            "runtimeInventory",
            "packageReproducibility",
            "vulnerabilityScan",
            "secretScan",
            "archiveInspection",
            "database",
            "tools",
            "originalReportSha256",
            "policySourceSha256",
            "limitations",
        }
        or type(record.get("schemaVersion")) is not int
        or record["schemaVersion"] != 1
        or record.get("status") != STATUS
        or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit)
        or record.get("sourceCommit") != commit
        or record.get("tag") != tag
    ):
        raise ValueError("Qualification evidence identity/schema mismatch")
    started, finished = timestamp(record.get("startedAt")), timestamp(record.get("finishedAt"))
    if not started <= finished <= now + CLOCK_SKEW or now - finished > MAX_DB_AGE:
        raise ValueError("Qualification evidence chronology/freshness failed")
    validate_database(record["database"]["metadata"], started=started, finished=finished)
    validate_database(record["database"]["metadata"], started=started, finished=now)
    database = record["database"]
    if (
        database.get("policy") != DATABASE_POLICY
        or set(database) != {"metadata", "metadataSha256", "databaseSha256", "policy"}
        or set(database["metadata"]) != {"Version", "UpdatedAt", "DownloadedAt", "NextUpdate"}
        or set(record["originalReportSha256"]) != REPORTS
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
            for value in [
                database["metadataSha256"],
                database["databaseSha256"],
                *record["originalReportSha256"].values(),
            ]
        )
    ):
        raise ValueError("Qualification database policy or original-report hashes are invalid")
    if record["artifacts"] != {
        path.name: sha256(path, MAX_DB_BYTES) for path in sorted(directory.iterdir())
    }:
        raise ValueError("Qualification evidence artifact identity/hash mismatch")
    required = {
        "ci/tools.lock.json",
        "ci/secret-scan.yaml",
        "scripts/qualify-release.py",
        "scripts/release-evidence.py",
        "scripts/check-secret-scanner.py",
        "scripts/expand-release-assets.py",
        "scripts/check-release.py",
        "scripts/install-ci-tool.py",
        "scripts/install-python-deps.py",
        "scripts/build-package.py",
        "scripts/check-package-reproducibility.py",
        "ci/python-locks.json",
        "ci/python-runtime.lock",
        "ci/python-build.lock",
        "ci/python-dev.lock",
        "ci/python-build.in",
        "pyproject.toml",
    }
    if set(record["policySourceSha256"]) != required or any(
        sha256(root / path) != digest for path, digest in record["policySourceSha256"].items()
    ):
        raise ValueError("Qualification policy source identity/hash mismatch")
    lock = document(root / "ci/tools.lock.json")["tools"]
    if set(record["tools"]) != {"trivy", "syft"}:
        raise ValueError("Qualification tool inventory is incomplete")
    for name in ("trivy", "syft"):
        tool = record["tools"][name]
        if (
            set(tool)
            != set(lock[name]) | {"verificationMode", "archiveVerifiedThisRun", "receiptSha256"}
            or any(tool.get(key) != value for key, value in lock[name].items())
            or tool.get("verificationMode")
            not in {"CACHED_EXECUTABLE", "OFFLINE_ARCHIVE", "DOWNLOADED_ARCHIVE"}
            or tool.get("archiveVerifiedThisRun")
            is not (tool["verificationMode"] != "CACHED_EXECUTABLE")
            or not isinstance(tool.get("receiptSha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", tool["receiptSha256"])
        ):
            raise ValueError("Qualification tool identity mismatch")
    inventory = record["runtimeInventory"]
    reproduction = record["packageReproducibility"]
    if (
        set(reproduction)
        != {
            "status",
            "sourceCommit",
            "sourceDateEpoch",
            "artifacts",
            "freshSourceClone",
            "freshLockedEnvironment",
            "independentReviewerApproval",
        }
        or reproduction.get("status") != "BYTE_IDENTICAL_PACKAGE_REBUILD_NOT_PRODUCTION_APPROVAL"
        or reproduction.get("sourceCommit") != commit
        or type(reproduction.get("sourceDateEpoch")) is not int
        or reproduction.get("freshSourceClone") is not True
        or reproduction.get("freshLockedEnvironment") is not True
        or reproduction.get("independentReviewerApproval") is not False
        or reproduction.get("artifacts")
        != {
            name: sha256(directory / name, MAX_DB_BYTES)
            for name in (f"certweaver-{tag[1:]}-py3-none-any.whl", f"certweaver-{tag[1:]}.tar.gz")
        }
    ):
        raise ValueError("Retained package reproduction does not match the candidate")
    if (
        not isinstance(inventory, dict)
        or not inventory
        or any(
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
            or not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}", version)
            for name, version in inventory.items()
        )
    ):
        raise ValueError("Qualification inventory contains invalid package identities")
    bill = document(directory / f"certweaver-{tag}.sbom.cdx.json")
    components = bill.get("components")
    if (
        bill.get("bomFormat") != "CycloneDX"
        or not isinstance(components, list)
        or any(not isinstance(component, dict) for component in components)
    ):
        raise ValueError("Qualification inventory requires the candidate CycloneDX SBOM")
    sbom_inventory = {}
    for component in components:
        if component.get("type") == "library" and str(component.get("purl", "")).startswith(
            "pkg:pypi/"
        ):
            name = component.get("name")
            if not isinstance(name, str):
                raise ValueError("SBOM package identity is missing")
            name = re.sub(r"[-_.]+", "-", name).lower()
            version = component.get("version")
            if name in sbom_inventory and sbom_inventory[name] != version:
                raise ValueError("Contradictory SBOM package versions")
            sbom_inventory[name] = version
    if sbom_inventory != inventory:
        raise ValueError("Retained qualification inventory does not match the candidate SBOM")
    if (
        record["vulnerabilityScan"]
        != {
            "target": "installed Python runtime",
            "severities": ["HIGH", "CRITICAL"],
            "blockingFindings": 0,
            "inventoryReconciled": True,
        }
        or record["secretScan"]
        != {
            "target": "expanded candidate archives",
            "allSeverities": True,
            "findings": 0,
            "cleanControlFindings": 0,
            "seededControlFindings": 6,
        }
        or not record["runtimeInventory"]
    ):
        raise ValueError("Qualification evidence must record all successful checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        evidence = Path("release-evidence/qualification.json")
        if evidence.parent.is_symlink() or set(evidence.parent.iterdir()) != {evidence}:
            raise ValueError("Evidence handoff contains unexpected files")
        verify_record(
            document(evidence),
            directory=args.directory,
            root=root,
            tag=args.tag,
            commit=args.commit,
            now=datetime.now(UTC),
        )
        print(
            "Qualification evidence identity, hashes and freshness verified; "
            "production approval not inferred"
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: Qualification evidence verification failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
