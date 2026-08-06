from __future__ import annotations

import hashlib
import json
import re
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
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class LiveEvidenceResult:
    errors: tuple[str, ...]
    checked_artifacts: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


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
        (
            "rke2-ha/nodes.txt",
            "rke2-ha/rke2-services.txt",
            "rke2-ha/etcd-members.txt",
            "rke2-ha/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "VIP failover",
        "Active VIP owner before and after stopping HAProxy or Keepalived on the "
        "current owner, plus API success through the VIP.",
        (
            "vip-failover/before.txt",
            "vip-failover/after.txt",
            "vip-failover/api-check.txt",
            "vip-failover/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "Backup and restore",
        "A staging restore from an etcd snapshot using the matching RKE2 token.",
        ("backup-restore/restore.txt", "backup-restore/attestation.json"),
    ),
    EvidenceRequirement(
        "Certificate issuance",
        "A successful CertificateRequest through the approved issuer path, with "
        "approver-policy enforcing policy.",
        (
            "certificate-issuance/certificate-requests.txt",
            "certificate-issuance/approver-policy.txt",
            "certificate-issuance/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "Trust distribution",
        "trust-manager Bundle reconciliation and expected target ConfigMaps or Secrets.",
        (
            "trust-distribution/bundles.yaml",
            "trust-distribution/targets.txt",
            "trust-distribution/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "Network controls",
        "Firewalld rich rules and an external port scan from management and "
        "non-management networks.",
        (
            "network-controls/firewalld.txt",
            "network-controls/scan-management.txt",
            "network-controls/scan-non-management.txt",
            "network-controls/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "Host hardening",
        "SELinux enforcing, swap disabled, chrony synchronized, audit logs written, "
        "and CIS/sysctl decision recorded.",
        (
            "host-hardening/selinux.txt",
            "host-hardening/swap.txt",
            "host-hardening/chrony.txt",
            "host-hardening/audit.txt",
            "host-hardening/cis-decision.txt",
            "host-hardening/attestation.json",
        ),
    ),
    EvidenceRequirement(
        "Secret handling",
        "RKE2 token, Keepalived auth, DNS credentials, CA keys, unseal material, "
        "and backup keys stored in approved systems.",
        ("secret-handling/attestation.json",),
    ),
    EvidenceRequirement(
        "Upgrade rehearsal",
        "Staging upgrade of RKE2, Helm charts, and adapters using pinned versions.",
        ("upgrade-rehearsal/upgrade.txt", "upgrade-rehearsal/attestation.json"),
    ),
    EvidenceRequirement(
        "Incident readiness",
        "Documented CA key compromise, certificate revocation, cluster restore, and "
        "credential rotation procedure.",
        ("incident-readiness.md", "incident-readiness-attestation.json"),
    ),
)


_SENSITIVE_EVIDENCE_PATTERNS = (
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(
        r'(?im)(?:^|\")(?:token|client-key-data|password|passphrase|rke2_token|'
        r'keepalived_auth|aws_secret_access_key|secret_access_key|private_key|'
        r'unseal_key|bearer|authorization)\"?\s*[:=]'
    ),
    re.compile(r"(?im)^\s*(?:clusters|contexts|users):\s*$"),
    re.compile(r"(?im)^\s*apiVersion:\s*v1\s*$\n\s*kind:\s*Config\s*$"),
)
_PLACEHOLDER_PATTERN = re.compile(
    r"(?i)\b(?:TODO|TBD|REPLACE_ME|CHANGE_ME|NOT_COLLECTED|INSERT_.*?_HERE)\b"
)
_SENSITIVE_FILENAME_PATTERN = re.compile(r"(?i)(?:kubeconfig|\.pem$|\.key$|id_rsa)")


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
        ]
    )
    return "\n".join(lines) + "\n"


def requirements_markdown() -> str:
    lines = [
        "# Required live evidence for 100/100",
        "",
        "Keep secrets, tokens, kubeconfigs, and private hostnames out of committed reports.",
        "",
        (
            "Each artifact must be non-empty and each `attestation.json` must record a "
            + "timezone-aware observation, an operator, environment, source, and `status: pass`."
        ),
        "",
        "| Control | Required evidence | Artifacts | Status |",
        "|---|---|---|---|",
    ]
    for requirement in REQUIRED_EVIDENCE:
        artifacts = "<br>".join(f"`{artifact}`" for artifact in requirement.artifacts)
        lines.append(
            f"| {requirement.control} | {requirement.evidence} | {artifacts} | TODO |"
        )
    return "\n".join(lines) + "\n"


def _artifact_path(root: Path, relative: str) -> Path | None:
    candidate = root / relative
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _read_evidence_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _write_text_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _validate_attestation(path: Path, text: str, errors: list[str]) -> None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        errors.append(f"{path.name}: attestation is not valid JSON")
        return
    if not isinstance(value, dict):
        errors.append(f"{path.name}: attestation must be a JSON object")
        return
    if value.get("status") != "pass":
        errors.append(f"{path.name}: attestation status must be pass")
    observed_at = value.get("observedAt")
    if not isinstance(observed_at, str):
        errors.append(f"{path.name}: attestation observedAt is required")
    else:
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is None or parsed.tzinfo is None:
            errors.append(f"{path.name}: observedAt must be timezone-aware ISO-8601")
    for key in ("operator", "source", "environment"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            errors.append(f"{path.name}: attestation {key} is required")


def verify_live_evidence(
    destination: str | Path, config: dict[str, Any] | None = None
) -> LiveEvidenceResult:
    root = Path(destination).resolve()
    errors: list[str] = []
    checked: list[str] = []
    if not root.is_dir():
        return LiveEvidenceResult(("evidence directory does not exist",), ())
    if config is None:
        errors.append("a configuration is required to validate deployment evidence")
    else:
        strict_validation = validate_config(config, strict=True)
        if strict_validation.errors:
            errors.append("configuration fails strict production validation")

    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        errors.append("manifest.json: evidence bundle manifest is required")
    else:
        try:
            manifest = json.loads(_read_evidence_text(manifest_path))
        except json.JSONDecodeError:
            manifest = None
            errors.append("manifest.json: evidence bundle manifest is not valid JSON")
        if isinstance(manifest, dict):
            score, maximum = repo_score()
            if manifest.get("repoScore") != score or manifest.get("repoScoreMaximum") != maximum:
                errors.append("manifest.json: repository score does not match this checkout")
            if config is not None and manifest.get("configSha256") != config_sha256(config):
                errors.append("manifest.json: config hash does not match the supplied config")
            validation = manifest.get("validation", {})
            if isinstance(validation, dict) and validation.get("errors"):
                errors.append("manifest.json: configuration validation contains errors")
            elif not isinstance(validation, dict):
                errors.append("manifest.json: validation must be a JSON object")

    checked_paths: set[Path] = set()
    for requirement in REQUIRED_EVIDENCE:
        for relative in requirement.artifacts:
            path = _artifact_path(root, relative)
            if path is None:
                errors.append(f"{relative}: artifact path escapes evidence directory")
                continue
            if path.is_symlink():
                errors.append(f"{relative}: symlinked evidence artifacts are not accepted")
                continue
            if not path.is_file():
                errors.append(f"{relative}: required evidence artifact is missing")
                continue
            checked_paths.add(path)
            text = _read_evidence_text(path)
            checked.append(relative)
            if not text.strip():
                errors.append(f"{relative}: evidence artifact is empty")
                continue
            if any(pattern.search(text) for pattern in _SENSITIVE_EVIDENCE_PATTERNS):
                errors.append(f"{relative}: sensitive material must be redacted")
            if _PLACEHOLDER_PATTERN.search(text):
                errors.append(f"{relative}: placeholder evidence is not accepted")
            if path.name.endswith("attestation.json"):
                _validate_attestation(path, text, errors)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path in checked_paths:
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            errors.append(f"{relative}: symlinked evidence artifacts are not accepted")
            continue
        if _SENSITIVE_FILENAME_PATTERN.search(path.name):
            errors.append(f"{relative}: sensitive-looking filenames are not accepted")
            continue
        text = _read_evidence_text(path)
        if any(pattern.search(text) for pattern in _SENSITIVE_EVIDENCE_PATTERNS):
            errors.append(f"{relative}: sensitive material must be redacted")

    return LiveEvidenceResult(tuple(errors), tuple(checked))


def live_checks_script() -> str:
    return r"""#!/usr/bin/env bash
set -euo pipefail

umask 077
KUBECONFIG="${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}"
OUT="${1:-certweaver-live-evidence}"
mkdir -p "$OUT"
K=(kubectl --kubeconfig "$KUBECONFIG")

mkdir -p "$OUT/rke2-ha" "$OUT/certificate-issuance" "$OUT/trust-distribution"

"${K[@]}" get nodes -o wide > "$OUT/rke2-ha/nodes.txt"
"${K[@]}" get --raw=/readyz?verbose > "$OUT/rke2-ha/api-readyz.txt"
"${K[@]}" get pods --all-namespaces -o wide > "$OUT/rke2-ha/pods.txt"
"${K[@]}" -n cert-manager get deploy,pod > "$OUT/certificate-issuance/cert-manager.txt"
"${K[@]}" get certificaterequests.cert-manager.io \
  --all-namespaces > "$OUT/certificate-issuance/certificate-requests.txt"
"${K[@]}" get certificaterequestpolicies.policy.cert-manager.io \
  --all-namespaces > "$OUT/certificate-issuance/approver-policy.txt"
"${K[@]}" get bundles.trust.cert-manager.io \
  --all-namespaces -o yaml > "$OUT/trust-distribution/bundles.yaml"
"${K[@]}" get certificates.cert-manager.io \
  --all-namespaces > "$OUT/certificate-issuance/certificates.txt"

: "${CERTWEAVER_NODES:?Set CERTWEAVER_NODES to three comma-separated SSH targets}"
IFS=',' read -r -a NODES <<< "$CERTWEAVER_NODES"
if [[ "${#NODES[@]}" -ne 3 ]]; then
  echo "CERTWEAVER_NODES must contain exactly three SSH targets" >&2
  exit 2
fi
mkdir -p "$OUT/host-hardening" "$OUT/network-controls"
: > "$OUT/rke2-ha/rke2-services.txt"
: > "$OUT/rke2-ha/etcd-members.txt"
: > "$OUT/host-hardening/selinux.txt"
: > "$OUT/host-hardening/swap.txt"
: > "$OUT/host-hardening/chrony.txt"
: > "$OUT/host-hardening/audit.txt"
: > "$OUT/network-controls/firewalld.txt"
for index in "${!NODES[@]}"; do
  node="${NODES[$index]}"
  label="node-$((index + 1))"
  printf '%s\n' "$label" >> "$OUT/rke2-ha/rke2-services.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n systemctl is-active rke2-server; sudo -n systemctl is-enabled rke2-server" \
    >> "$OUT/rke2-ha/rke2-services.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n getenforce" >> "$OUT/host-hardening/selinux.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n swapon --show" >> "$OUT/host-hardening/swap.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n chronyc tracking" >> "$OUT/host-hardening/chrony.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n auditctl -s" >> "$OUT/host-hardening/audit.txt"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$node" \
    "sudo -n firewall-cmd --list-all" >> "$OUT/network-controls/firewalld.txt"
done

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "${NODES[0]}" \
  "sudo -n env ETCDCTL_API=3 /var/lib/rancher/rke2/bin/etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt \
    --cert=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt \
    --key=/var/lib/rancher/rke2/server/tls/etcd/server-client.key \
    endpoint health --cluster" > "$OUT/rke2-ha/etcd-members.txt"

cat > "$OUT/manual-evidence.txt" <<'NOTE'
Collect and redact the remaining disruptive or externally sourced evidence:
VIP owner before/after failover and API checks, snapshot restore, external scans
from management and non-management networks, trust-manager target objects,
approved secret-storage attestation, upgrade rehearsal, and incident readiness.
Create the exact artifacts listed by required-live-evidence.md, with a
timezone-aware attestation.json containing status=pass, operator, environment,
and source.
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
        _write_text_lf(path, content)
        if path.name.endswith(".sh"):
            path.chmod(0o755)
        written.append(path)
    return written
