from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from .config import _get, validate_config
from .errors import ConfigurationError
from .registry import project_root
from .render import execution_plan


@dataclass(frozen=True)
class ScoreArea:
    area: str
    score: int
    maximum: int
    evidence: str


@dataclass(frozen=True)
class EvidenceRequirement:
    control: str
    evidence: str


@dataclass(frozen=True)
class EvidenceAssessment:
    score: int
    maximum: int
    errors: tuple[str, ...]
    pending_controls: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.errors and not self.pending_controls and self.score == self.maximum


EVIDENCE_MAX_AGE = timedelta(days=30)
EVIDENCE_MAX_BYTES = 10 * 1024 * 1024


SCORE_AREAS: tuple[ScoreArea, ...] = (
    ScoreArea(
        "HA topology",
        14,
        15,
        "Three RKE2 server/etcd nodes, odd quorum, VIP, HAProxy, Keepalived, "
        "and co-located port-collision validation.",
    ),
    ScoreArea(
        "Host hardening",
        14,
        15,
        "SELinux, firewalld, swap disablement, minimum host capacity checks, "
        "kernel modules, Kubernetes sysctls, audit policy, and secrets encryption.",
    ),
    ScoreArea(
        "Network exposure",
        14,
        15,
        "Management CIDRs are required for production and cannot be any-network; "
        "ingress CIDRs are separate.",
    ),
    ScoreArea(
        "Certificate control plane",
        14,
        14,
        "cert-manager, approver-policy, trust-manager, HA values, NetworkPolicies, "
        "disabled auto-approval, and ACME ownership conflict validation.",
    ),
    ScoreArea(
        "Version and supply chain",
        12,
        12,
        "Pinned versions, verified Helm and privileged installer downloads, immutable "
        "GitHub Actions, SBOMs, attestations, Renovate, and security scanning.",
    ),
    ScoreArea(
        "Backup and recovery",
        10,
        10,
        "Scheduled etcd snapshots and S3-compatible off-host replication are required; "
        "restore evidence is tracked in the evidence bundle.",
    ),
    ScoreArea(
        "CI and static validation",
        10,
        10,
        "Ruff, pytest, yamllint, ansible-lint, schema validation, Trivy, Gitleaks, "
        "and CodeQL.",
    ),
    ScoreArea(
        "Evidence automation",
        5,
        5,
        "Sanitized evidence bundles and configuration-bound, implementation-bound "
        "review checks for artifact integrity, freshness, and completeness.",
    ),
    ScoreArea(
        "Documentation and limits",
        4,
        4,
        "Architecture, firewall, security model, operations, publishing, air-gap "
        "notes, scorecard, and tested boundaries.",
    ),
)


REQUIRED_EVIDENCE: tuple[EvidenceRequirement, ...] = (
    EvidenceRequirement(
        "RKE2 HA install",
        "kubectl node inventory, RKE2 service status from all three nodes, and etcd "
        "member health.",
    ),
    EvidenceRequirement(
        "VIP failover",
        "Active VIP owner before and after stopping HAProxy or Keepalived on the "
        "current owner, plus API success through the VIP.",
    ),
    EvidenceRequirement(
        "Backup and restore",
        "A staging restore from an etcd snapshot using the matching RKE2 token.",
    ),
    EvidenceRequirement(
        "Certificate issuance",
        "A successful CertificateRequest through the approved issuer path, with "
        "approver-policy enforcing policy.",
    ),
    EvidenceRequirement(
        "Trust distribution",
        "trust-manager Bundle reconciliation and expected target ConfigMaps or Secrets.",
    ),
    EvidenceRequirement(
        "Network controls",
        "Firewalld rich rules and an external port scan from management and "
        "non-management networks.",
    ),
    EvidenceRequirement(
        "Host hardening",
        "SELinux enforcing, swap disabled, chrony synchronized, audit logs written, "
        "and CIS/sysctl decision recorded.",
    ),
    EvidenceRequirement(
        "Secret handling",
        "RKE2 token, Keepalived auth, DNS credentials, CA keys, unseal material, "
        "and backup keys stored in approved systems.",
    ),
    EvidenceRequirement(
        "Upgrade rehearsal",
        "Staging upgrade of RKE2, Helm charts, and adapters using pinned versions.",
    ),
    EvidenceRequirement(
        "Incident readiness",
        "Documented CA key compromise, certificate revocation, cluster restore, and "
        "credential rotation procedure.",
    ),
)


def repo_score() -> tuple[int, int]:
    return (
        sum(area.score for area in SCORE_AREAS),
        sum(area.maximum for area in SCORE_AREAS),
    )


def clean_config(config: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in config.items() if not key.startswith("__")}


def config_sha256(config: dict[str, Any]) -> str:
    rendered = yaml.safe_dump(clean_config(config), sort_keys=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def implementation_sha256() -> str:
    """Identify the installed implementation and all deployment resources."""
    root = project_root()
    digest = hashlib.sha256()
    paths: list[tuple[str, Path]] = [
        (f"src/certweaver/{path.name}", path)
        for path in Path(__file__).parent.glob("*.py")
    ]
    for relative in (
        "config", "roles", "playbooks", "kubernetes", "docker", "collections", "ansible.cfg",
    ):
        path = root / relative
        if path.is_dir():
            paths.extend(
                (item.relative_to(root).as_posix(), item)
                for item in path.rglob("*") if item.is_file()
            )
        elif path.is_file():
            paths.append((relative, path))
    for name, path in sorted(paths):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def evidence_review_template(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "configSha256": config_sha256(config),
        "implementationSha256": implementation_sha256(),
        "reviewedBy": "",
        "reviewedAt": "",
        "controls": [
            {"control": item.control, "status": "pending", "observedAt": "", "artifacts": []}
            for item in REQUIRED_EVIDENCE
        ],
    }


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON field: {key}")
        value[key] = item
    return value


def _evidence_timestamp(
    value: Any, label: str, now: datetime, errors: list[str]
) -> datetime | None:
    try:
        if not isinstance(value, str):
            raise ValueError("timestamp must be a string")
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timezone is required")
        timestamp = timestamp.astimezone(UTC)
    except (ValueError, OverflowError):
        errors.append(f"{label} must be an ISO-8601 timestamp with a timezone")
        return None
    if timestamp > now + timedelta(minutes=5):
        errors.append(f"{label} is in the future")
    if now - timestamp > EVIDENCE_MAX_AGE:
        errors.append(f"{label} is older than 30 days; repeat the staging checks")
    return timestamp


def _verify_artifact(artifact: Any, root: Path, label: str, errors: list[str]) -> None:
    if not isinstance(artifact, dict):
        errors.append(f"{label}: artifact must contain path and sha256")
        return
    relative, expected = artifact.get("path"), artifact.get("sha256")
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or ":" in relative
        or "\0" in relative
    ):
        errors.append(f"{label}: artifact path must be a relative POSIX path")
        return
    posix, windows = PurePosixPath(relative), PureWindowsPath(relative)
    if posix.is_absolute() or windows.drive or ".." in posix.parts:
        errors.append(f"{label}: artifact path must stay inside the evidence directory")
        return
    if not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        errors.append(f"{label}: artifact sha256 must contain 64 hexadecimal characters")
        return
    try:
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            errors.append(f"{label}: artifact must be a file inside the evidence directory")
            return
        if path.name == "review.json" or not 0 < path.stat().st_size <= EVIDENCE_MAX_BYTES:
            errors.append(
                f"{label}: artifact must be nonempty, at most 10 MiB, and not review.json"
            )
            return
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(f"{label}: unable to read artifact: {exc}")
        return
    if actual != expected.lower():
        errors.append(f"{label}: artifact SHA-256 does not match its reviewed digest")


def assess_evidence(
    config: dict[str, Any], destination: str | Path, *, now: datetime | None = None
) -> EvidenceAssessment:
    """Verify review completeness and integrity, not the truth of a human attestation."""
    score, maximum = repo_score()
    errors = list(validate_config(config).errors)
    controls = tuple(item.control for item in REQUIRED_EVIDENCE)
    if errors:
        return EvidenceAssessment(0, maximum, tuple(errors), controls)
    if _get(config, "spec.mode") != "rke2-ha" or _get(config, "spec.environment") != "production":
        errors.append("The 100-point deployment score requires the production rke2-ha profile")
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must include a timezone")
    root = Path(destination).resolve()
    review_path = root / "review.json"
    try:
        if (
            review_path.is_symlink()
            or not review_path.is_file()
            or not review_path.resolve().is_relative_to(root)
        ):
            raise ValueError("review.json must be a regular file inside the evidence directory")
        if review_path.stat().st_size > EVIDENCE_MAX_BYTES:
            raise ValueError("review.json exceeds 10 MiB")
        review = json.loads(
            review_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, ValueError, RuntimeError, RecursionError) as exc:
        errors.append(f"Unable to read evidence review: {exc}")
        return EvidenceAssessment(score, maximum, tuple(errors), controls)
    if not isinstance(review, dict):
        errors.append("Evidence review must be a JSON object")
        return EvidenceAssessment(score, maximum, tuple(errors), controls)
    if type(review.get("schemaVersion")) is not int or review.get("schemaVersion") != 1:
        errors.append("Evidence review schemaVersion must be 1")
    if review.get("configSha256") != config_sha256(config):
        errors.append("Evidence configuration SHA-256 does not match this configuration")
    if review.get("implementationSha256") != implementation_sha256():
        errors.append("Evidence implementation SHA-256 does not match this implementation")
    reviewer = review.get("reviewedBy")
    if not isinstance(reviewer, str) or len(reviewer.strip()) < 3 or reviewer.strip().lower() in {
        "todo", "pending", "replace", "operator", "example",
    }:
        errors.append("reviewedBy must identify the person responsible for the evidence review")
    reviewed_at = _evidence_timestamp(review.get("reviewedAt"), "reviewedAt", current, errors)
    records = review.get("controls")
    if not isinstance(records, list):
        errors.append("Evidence controls must be an array")
        return EvidenceAssessment(score, maximum, tuple(errors), controls)
    pending = set(controls)
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("control"), str):
            errors.append("Each evidence control must be an object with a control name")
            continue
        name = record["control"]
        if name not in controls or name in seen:
            errors.append(f"Unknown or duplicate evidence control: {name}")
            continue
        seen.add(name)
        status = record.get("status")
        if status != "passed":
            if status not in ("pending", "failed"):
                errors.append(f"{name}: status must be pending, failed, or passed")
            continue
        before = len(errors)
        observed_at = _evidence_timestamp(
            record.get("observedAt"), f"{name}: observedAt", current, errors
        )
        if observed_at and reviewed_at and observed_at > reviewed_at:
            errors.append(f"{name}: evidence was observed after its review")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(f"{name}: passed controls require at least one reviewed artifact")
        else:
            for artifact in artifacts:
                _verify_artifact(artifact, root, name, errors)
        if len(errors) == before:
            pending.remove(name)
    ordered_pending = tuple(name for name in controls if name in pending)
    return EvidenceAssessment(
        maximum if not errors and not ordered_pending else score,
        maximum, tuple(errors), ordered_pending,
    )


def assessment_markdown(assessment: EvidenceAssessment) -> str:
    lines = [
        "# CertWeaver deployment evidence assessment", "",
        f"Production readiness: **{assessment.score}/{assessment.maximum}**.", "",
        "Evidence integrity and review completeness: "
        + ("PASS" if assessment.complete else "PENDING / FAIL"), "",
        "This validates artifact hashes, freshness, configuration and implementation binding. "
        "The named human reviewer remains responsible for the truth and sufficiency "
        "of live evidence.",
    ]
    if assessment.errors:
        lines.extend(["", *[f"- ERROR: {error}" for error in assessment.errors]])
    if assessment.pending_controls:
        lines.extend(["", "Outstanding live controls:", ""])
        lines.extend(f"- {name}" for name in assessment.pending_controls)
    return "\n".join(lines) + "\n"


def config_summary(config: dict[str, Any]) -> dict[str, Any]:
    spec = config.get("spec", {})
    platform = spec.get("platform", {})
    nodes = platform.get("nodes", []) or []
    versions = spec.get("versions", {}) or {}
    secrets = dict(spec.get("secrets", {}) or {})
    snapshot_s3 = ((spec.get("rke2", {}) or {}).get("etcdSnapshots", {}) or {}).get("s3", {})
    if isinstance(snapshot_s3, dict) and snapshot_s3.get("configSecretFile"):
        secrets["etcdS3ConfigFile"] = snapshot_s3["configSecretFile"]
    source = Path(config.get("__source_path__", ".")).parent

    return {
        "name": _get(config, "metadata.name", "certweaver"),
        "mode": spec.get("mode"),
        "environment": spec.get("environment"),
        "nodeCount": len(nodes),
        "loadBalancer": platform.get("loadBalancer", {}),
        "vipPorts": platform.get("vip", {}).get("ports", {}),
        "addonsEnabled": sorted(
            key
            for key, value in (spec.get("addons", {}) or {}).items()
            if isinstance(value, dict) and value.get("enabled") is True
        ),
        "adaptersEnabled": sorted((spec.get("adapters", {}) or {}).get("enabled", [])),
        "versions": versions,
        "secretFilesPresent": {
            key: bool(value and (source / value).exists())
            for key, value in secrets.items()
            if isinstance(value, str)
        },
        "helmChecksumPresent": bool(
            versions.get("helmChecksum") or versions.get("helmChecksums")
        ),
        "etcdSnapshotReplication": {
            "enabled": bool(snapshot_s3.get("enabled", False))
            if isinstance(snapshot_s3, dict)
            else False,
            "secretName": snapshot_s3.get("secretName") if isinstance(snapshot_s3, dict) else None,
        },
    }


def score_markdown() -> str:
    score, maximum = repo_score()
    lines = [
        "# CertWeaver production maturity score",
        "",
        f"Repo-local production maturity: **{score}/{maximum}**.",
        "",
        "| Area | Score | Evidence |",
        "|---|---:|---|",
    ]
    for area in SCORE_AREAS:
        lines.append(f"| {area.area} | {area.score}/{area.maximum} | {area.evidence} |")
    lines.extend(
        [
            "",
            "The remaining points require live staging or production-like evidence.",
            "Run `certweaver evidence` to create the local evidence bundle skeleton.",
            "After human review, run `certweaver score -c CONFIG --evidence DIRECTORY` "
            "to assess deployment readiness.",
        ]
    )
    return "\n".join(lines) + "\n"


def requirements_markdown() -> str:
    lines = [
        "# Required live evidence for 100/100",
        "",
        "Keep secrets, tokens, kubeconfigs, and private hostnames out of committed reports.",
        "",
        "| Control | Required evidence | Status |",
        "|---|---|---|",
    ]
    for requirement in REQUIRED_EVIDENCE:
        lines.append(f"| {requirement.control} | {requirement.evidence} | TODO |")
    return "\n".join(lines) + "\n"


def live_checks_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail
umask 077

KUBECONFIG="${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}"
OUT="${1:-certweaver-live-evidence}"
mkdir "$OUT"
K=(kubectl --kubeconfig "$KUBECONFIG")

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/observed-at.txt"
"${K[@]}" wait --for=condition=Ready nodes --all --timeout=120s
"${K[@]}" -n cert-manager wait --for=condition=Available deployments --all --timeout=120s
"${K[@]}" get nodes -o wide > "$OUT/nodes.txt"
"${K[@]}" get pods --all-namespaces -o wide > "$OUT/pods.txt"
"${K[@]}" -n cert-manager get deploy,pod > "$OUT/cert-manager.txt"
"${K[@]}" get certificaterequests.cert-manager.io \
  --all-namespaces > "$OUT/certificate-requests.txt"
"${K[@]}" get certificaterequestpolicies.policy.cert-manager.io \
  --all-namespaces > "$OUT/approver-policy.txt"
"${K[@]}" get bundles.trust.cert-manager.io \
  --all-namespaces -o yaml > "$OUT/trust-bundles.yaml"
"${K[@]}" get certificates.cert-manager.io \
  --all-namespaces > "$OUT/certificates.txt"

cat > "$OUT/manual-node-evidence.txt" <<'NOTE'
Collect node-local service, SELinux, firewalld, and snapshot evidence separately
from each RKE2 node.
These read-only snapshots do not demonstrate failover, restore, or upgrade success.
Review all required controls and complete review.json separately.
NOTE
printf '%s\\n' 'Read-only collection completed; human review and manual staging checks remain.'
"""


def write_evidence_bundle(config: dict[str, Any], destination: str | Path) -> list[Path]:
    target = Path(destination)
    validation = validate_config(config)
    validation.require_ok()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ConfigurationError(
            f"Evidence destination must be an empty directory: {target}. "
            "Choose a new output directory to preserve existing evidence."
        )
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    score, maximum = repo_score()
    sha = config_sha256(config)
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()

    manifest = {
        "generatedAt": generated_at,
        "repoScore": score,
        "repoScoreMaximum": maximum,
        "configSha256": sha,
        "implementationSha256": implementation_sha256(),
        "validation": {
            "errors": validation.errors,
            "warnings": validation.warnings,
        },
        "scoreAreas": [asdict(area) for area in SCORE_AREAS],
        "requiredEvidence": [asdict(requirement) for requirement in REQUIRED_EVIDENCE],
    }

    files: dict[str, str] = {
        "README.md": (
            "# CertWeaver evidence bundle\n\n"
            f"Generated for config SHA-256 `{sha}`.\n\n"
            "This directory is safe to commit only after reviewing and removing "
            "environment-sensitive details from live evidence files.\n\n"
            "Collect staging artifacts for every control listed in required-live-evidence.md. "
            "Review their content, then complete review.json with your identity, timezone-aware "
            "reviewedAt and observedAt timestamps, passed statuses, and relative artifact paths "
            "with SHA-256 digests. Checks expire after 30 days. Regenerate the bundle if the "
            "configuration or implementation changes.\n\n"
            "Run `certweaver score -c CONFIG --evidence THIS_DIRECTORY` to check the review. "
            "The verifier checks integrity and completeness; the named reviewer is responsible "
            "for verifying that artifacts demonstrate each live control. A generated skeleton "
            "never earns live-evidence points.\n"
        ),
        "score.md": score_markdown(),
        "required-live-evidence.md": requirements_markdown(),
        "plan.txt": "\n".join(
            f"{idx:02d}. {item}" for idx, item in enumerate(execution_plan(config), start=1)
        )
        + "\n",
        "config-summary.json": json.dumps(config_summary(config), indent=2, sort_keys=True)
        + "\n",
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "review.json": json.dumps(evidence_review_template(config), indent=2, sort_keys=True)
        + "\n",
        "live-checks.sh": live_checks_script(),
    }

    written: list[Path] = []
    for relative, content in files.items():
        path = target / relative
        path.write_text(content, encoding="utf-8", newline="\n")
        if path.name.endswith(".sh"):
            path.chmod(0o755)
        written.append(path)
    return written
