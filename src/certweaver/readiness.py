from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .config import _get, validate_config
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
        11,
        12,
        "Pinned versions, Helm checksums, release-aged Renovate, GitHub Actions "
        "pinning policy, and security scanning.",
    ),
    ScoreArea(
        "Backup and recovery",
        9,
        10,
        "Scheduled etcd snapshots are required and restore evidence is tracked in "
        "the evidence bundle.",
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
        "Local score reporting plus sanitized evidence-bundle generation.",
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


def config_summary(config: dict[str, Any]) -> dict[str, Any]:
    spec = config.get("spec", {})
    platform = spec.get("platform", {})
    nodes = platform.get("nodes", []) or []
    versions = spec.get("versions", {}) or {}
    secrets = spec.get("secrets", {}) or {}
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

KUBECONFIG="${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}"
OUT="${1:-certweaver-live-evidence}"
mkdir -p "$OUT"
K=(kubectl --kubeconfig "$KUBECONFIG")

"${K[@]}" get nodes -o wide > "$OUT/nodes.txt"
"${K[@]}" get pods --all-namespaces -o wide > "$OUT/pods.txt"
"${K[@]}" -n cert-manager get deploy,pod > "$OUT/cert-manager.txt"
"${K[@]}" get certificaterequests.cert-manager.io \
  --all-namespaces > "$OUT/certificate-requests.txt" || true
"${K[@]}" get certificaterequestpolicies.policy.cert-manager.io \
  --all-namespaces > "$OUT/approver-policy.txt" || true
"${K[@]}" get bundles.trust.cert-manager.io \
  --all-namespaces -o yaml > "$OUT/trust-bundles.yaml" || true
"${K[@]}" get certificates.cert-manager.io \
  --all-namespaces > "$OUT/certificates.txt" || true

cat > "$OUT/manual-node-evidence.txt" <<'NOTE'
Collect node-local service, SELinux, firewalld, and snapshot evidence separately
from each RKE2 node.
NOTE
"""


def write_evidence_bundle(config: dict[str, Any], destination: str | Path) -> list[Path]:
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    validation = validate_config(config)
    score, maximum = repo_score()
    sha = config_sha256(config)
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()

    manifest = {
        "generatedAt": generated_at,
        "repoScore": score,
        "repoScoreMaximum": maximum,
        "configSha256": sha,
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
            "environment-sensitive details from live evidence files.\n"
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
        "live-checks.sh": live_checks_script(),
    }

    written: list[Path] = []
    for relative, content in files.items():
        path = target / relative
        path.write_text(content, encoding="utf-8")
        if path.name.endswith(".sh"):
            path.chmod(0o755)
        written.append(path)
    return written
