"""Offline staging input preparation. Completeness never grants execution authority."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .config import _get, validate_config
from .enterprise import (
    CATALOGUE_SHA256,
    MAX_DOCUMENT_BYTES,
    _framework,
    _reject_constant,
    _time,
    _unique_object,
    canonical_digest,
    review_digest,
    scope_digest,
)
from .errors import ConfigurationError
from .registry import project_root
from .render import inventory_from_config

FORMAT_VERSION = "1.0.0"
REFERENCE_GROUPS = {
    "deployment": ["mode", "configurationRef", "inventoryRef", "renderedInventorySha256"],
    "access": [
        "controllerRef",
        "transportAccessRef",
        "privilegePolicyRef",
        "kubeconfigRef",
        "secretSystemRef",
        "independentRecoveryAccessRef",
    ],
    "topology": [
        "architectureRef",
        "hostBaselineRef",
        "networkDnsTimePolicyRef",
        "loadBalancerPolicyRef",
        "selinuxPolicyRef",
        "issuerPolicyRef",
        "backupTargetRef",
        "notificationTestDestinationRef",
    ],
    "execution": [
        "runbookRef",
        "faultLoadPlanRef",
        "recoveryPlanRef",
        "stopConditionsRef",
        "cleanupPlanRef",
        "windowStart",
        "windowEnd",
        "authorizationRef",
    ],
    "assurance": [
        "backendIntegrationRef",
        "approvalAuthorityPolicyRef",
        "evidenceStoreRef",
        "retentionPolicyRef",
        "originalEvidenceAccessRef",
        "redactionPolicyRef",
    ],
}
PLACEHOLDER = re.compile(r"^(todo|tbd|pending|unknown|none|null|changeme|replace[-_ ]?me)$", re.I)


def _template() -> dict:
    _, validator = _framework()
    document = _read(project_root() / "docs/readiness/enterprise-assessment.template.json")
    if not validator.is_valid(document):
        raise ConfigurationError("Packaged assessment template is invalid")
    return document


def _read(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("oversized")
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (OSError, ValueError, RecursionError) as error:
        # Never echo intake values, credential references, JSON payloads or parser diagnostics.
        raise ConfigurationError("Cannot read staging package JSON document") from error


def staging_inputs_template() -> dict:
    assessment = _template()
    return {
        "schemaVersion": FORMAT_VERSION,
        "catalogueSha256": CATALOGUE_SHA256,
        **{group: dict.fromkeys(fields) for group, fields in REFERENCE_GROUPS.items()},
        "authorities": {
            role: {"actorRef": None, "deputyRef": None} for role in assessment["approvals"]
        },
        "controlPlans": {
            identifier: {"independentReviewerRef": None, "procedureRef": None}
            for identifier in assessment["controls"]
        },
    }


def staging_inputs_schema() -> dict:
    """Emit the inspection schema; validation always uses this installed implementation."""
    reference = {"type": ["string", "null"], "minLength": 1, "maxLength": 2048}

    def shape(value: Any) -> dict:
        if isinstance(value, dict):
            return {
                "type": "object",
                "additionalProperties": False,
                "required": list(value),
                "properties": {name: shape(child) for name, child in value.items()},
            }
        return reference if value is None else {"const": value}

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **shape(staging_inputs_template()),
    }


def approval_checklist(assessment: dict) -> dict:
    """Planning purposes mirror the evaluator; these entries are never approvals."""
    catalogue, _ = _framework()
    scope = ["scope"]
    scope.extend("objective:" + name for name in assessment["approvedObjectives"])
    scope.extend("applicability:" + name for name in assessment["conditionalGateDecisions"])
    review = [
        f"control:{item['id']}:level:{level}"
        for item in catalogue["controls"]
        for level in range(1, 5)
    ]
    review.extend("gate:" + item["id"] for item in catalogue["releaseGates"])
    review.extend("release:" + role for role in assessment["approvals"])
    return {
        "status": "UNAPPROVED_PLANNING_REFERENCE",
        "catalogueSha256": CATALOGUE_SHA256,
        "scopePurposesBeforeObservation": scope,
        "reviewPurposesAfterObservation": review,
        "finalAssurancePurposes": [
            purpose
            for purpose in review
            if not purpose.startswith("control:") or purpose.endswith(":4")
        ],
        "perRecordPurposes": [
            "run:RUN_ID",
            "evidence:EVIDENCE_ID",
            "closure:findings:ID",
            "closure:exceptions:ID",
            "change:ID",
            "audit:ID",
        ],
        "authorityRequirements": [
            "Authenticate canonical actor, domain role, exact purpose/payload and validity",
            "Inspect payload, cumulative criteria, original evidence and operating ownership",
            "Deny revoked, expired, mismatched, unauthorized or self-reviewed claims",
            "Authorize before execution; review evidence and controls after observation",
        ],
    }


def initialize_staging(destination: str | Path) -> Path:
    """Create an exclusive private package. Inputs are intentionally unset."""
    catalogue, _ = _framework()
    control_plan = {
        "schemaVersion": FORMAT_VERSION,
        "catalogueSha256": CATALOGUE_SHA256,
        "status": "UNAPPROVED_PLANNING_REFERENCE",
        "controls": catalogue["controls"],
        "releaseGates": catalogue["releaseGates"],
        "freshnessPolicies": catalogue["freshnessPolicies"],
    }
    documents = {
        "assessment.json": _template(),
        "enterprise-assessment.schema.json": _read(
            project_root() / "docs/readiness/enterprise-assessment.schema.json"
        ),
        "staging-inputs.json": staging_inputs_template(),
        "staging-inputs.schema.json": staging_inputs_schema(),
        "control-plan.json": control_plan,
        "approval-checklist.json": approval_checklist(_template()),
    }
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir(mode=0o700)  # Existing directories/symlinks fail; never overwrite operator input.
    for name, value in documents.items():
        descriptor = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    return target.resolve()


def _present(value: Any) -> bool:
    return (
        isinstance(value, str) and bool(value.strip()) and not PLACEHOLDER.fullmatch(value.strip())
    )


def _without_locators(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_locators(child)
            for key, child in value.items()
            if not key.lower().endswith("approvalref") and key != "authorizationRef"
        }
    if isinstance(value, list):
        return [_without_locators(child) for child in value]
    return value


def check_staging(
    directory: str | Path,
    *,
    config_path: str | Path | None = None,
    inventory_path: str | Path | None = None,
) -> dict:
    """Inspect local data only; no transport, secret fetch, subprocess or deployment."""
    root = Path(directory)
    assessment = _read(root / "assessment.json")
    inputs = _read(root / "staging-inputs.json")
    catalogue, assessment_validator = _framework()
    issues: list[dict[str, str]] = []

    def block(path: str, reason: str) -> None:
        issues.append({"path": path, "reason": reason})

    valid = True
    for name, document, validator in [
        ("assessment", assessment, assessment_validator),
        ("inputs", inputs, Draft202012Validator(staging_inputs_schema())),
    ]:
        for error in validator.iter_errors(document):
            # Report a field pointer and fixed reason, never jsonschema's value-bearing message.
            parts = [str(part).replace("~", "~0").replace("/", "~1") for part in error.path]
            block("/" + name + "/" + "/".join(parts), "Invalid document structure")
            valid = False
    result = {
        "schemaVersion": FORMAT_VERSION,
        "status": "INPUTS_INCOMPLETE",
        "inputsComplete": False,
        "executionAuthorized": False,
        "productionDecision": "NOT_APPROVED",
        "enterprisePointsAwarded": 0,
        "authorizationStatus": "UNVERIFIED_REQUIRES_CONTROLLED_BACKEND",
        "issues": issues,
    }
    if not valid:
        return result

    subject = assessment["subject"]
    baseline = _template()
    if assessment["catalogueSha256"] != CATALOGUE_SHA256:
        block("/assessment/catalogueSha256", "Frozen catalogue binding required")
    for field in baseline["subject"]:
        value = subject[field]
        if field == "workingTreePatchSha256":
            if value is not None:
                block("/assessment/subject/" + field, "Freeze a committed candidate")
        elif field != "declaredExclusions" and not value:
            block("/assessment/subject/" + field, "Required subject input is missing")
    for index, artifact in enumerate(subject["releaseArtifacts"]):
        if not _present(artifact["provenanceRef"]):
            block(
                f"/assessment/subject/releaseArtifacts/{index}/provenanceRef",
                "Candidate provenance locator required",
            )
    for name, objective in assessment["approvedObjectives"].items():
        for field, value in objective.items():
            if not _present(value):
                block(
                    f"/assessment/approvedObjectives/{name}/{field}",
                    "Required objective input is missing",
                )
        if _present(objective["target"]) and not re.search(r"\d", objective["target"]):
            block(
                f"/assessment/approvedObjectives/{name}/target",
                "Record quantitative targets; units, populations and windows need authority review",
            )
    for name, decision in assessment["conditionalGateDecisions"].items():
        if type(decision["active"]) is not bool:
            block(
                f"/assessment/conditionalGateDecisions/{name}/active",
                "Applicability decision required",
            )
        for field in ["rationale", "reviewApprovalRef"]:
            if not _present(decision[field]):
                block(
                    f"/assessment/conditionalGateDecisions/{name}/{field}",
                    "Applicability rationale and review locator required",
                )
    for group, fields in REFERENCE_GROUPS.items():
        for field in fields:
            if not _present(inputs[group][field]):
                block(f"/inputs/{group}/{field}", "Required staging input is missing")
    for role, record in inputs["authorities"].items():
        for field, value in record.items():
            if not _present(value):
                block(
                    f"/inputs/authorities/{role}/{field}", "Authority and deputy locators required"
                )
        if _present(record["actorRef"]) and record["actorRef"] == record["deputyRef"]:
            block(f"/inputs/authorities/{role}", "Primary and deputy must be distinct")
    for identifier in baseline["controls"]:
        control = assessment["controls"][identifier]
        plan = inputs["controlPlans"][identifier]
        for field in ["accountableOwnerRef", "implementationAuthorRef", "verifierRef"]:
            if not _present(control[field]):
                block(f"/assessment/controls/{identifier}/{field}", "Control assignment required")
        for field, value in plan.items():
            if not _present(value):
                block(
                    f"/inputs/controlPlans/{identifier}/{field}",
                    "Independent reviewer and procedure required",
                )
        reviewer = plan["independentReviewerRef"]
        if _present(reviewer) and reviewer in {
            control["accountableOwnerRef"],
            control["implementationAuthorRef"],
            control["verifierRef"],
        }:
            block(
                f"/inputs/controlPlans/{identifier}/independentReviewerRef",
                "Independent reviewer must differ from owner, implementer and verifier",
            )
        expected = next(item for item in catalogue["controls"] if item["id"] == identifier)
        actual = {key: item["criterion"] for key, item in control["criteriaResults"].items()}
        criteria = {
            f"AC-{index:02}": text for index, text in enumerate(expected["acceptanceCriteria"], 1)
        }
        if actual != criteria:
            block(
                f"/assessment/controls/{identifier}/criteriaResults",
                "Frozen criteria cannot be changed",
            )
    try:
        start, end = [_time(inputs["execution"][key]) for key in ["windowStart", "windowEnd"]]
        if end <= start or end <= datetime.now(UTC):
            raise ValueError("window")
    except (AttributeError, TypeError, ValueError):
        block(
            "/inputs/execution", "Unexpired timezone-aware window with positive duration required"
        )
    if config_path is None:
        block("/localConfig", "Supply --config for explicit local configuration verification")
    else:
        _check_config(Path(config_path), subject, inputs, block, result)
    if inventory_path is None:
        block("/localInventory", "Supply --inventory for explicit local target verification")
    else:
        _check_inventory(Path(inventory_path), block, result)
    result["scopeSha256"] = scope_digest(assessment)
    result["reviewSha256"] = review_digest(assessment)
    result["inputPackageSha256"] = canonical_digest(
        _without_locators(
            {
                "assessment": assessment,
                "inputs": inputs,
            }
        )
    )
    result["controlCount"] = len(baseline["controls"])
    result["objectiveCount"] = len(baseline["approvedObjectives"])
    result["conditionalDecisionCount"] = len(baseline["conditionalGateDecisions"])
    result["inputsComplete"] = not issues
    if not issues:
        result["status"] = "INPUTS_COMPLETE_AUTHORIZATION_UNVERIFIED"
    return result


def _check_config(path: Path, subject: dict, inputs: dict, block: Any, result: dict) -> None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("oversized")
        config = yaml.safe_load(raw)
        if not isinstance(config, dict):
            raise ValueError("mapping")
        config["__source_path__"] = str(path.resolve())
        if not validate_config(config).ok:
            raise ValueError("invalid")
        fingerprint = hashlib.sha256(raw).hexdigest()
        result["localConfigSha256"] = fingerprint
        if fingerprint != subject["configSha256"]:
            block("/assessment/subject/configSha256", "Local configuration digest mismatch")
        if _get(config, "spec.mode") != inputs["deployment"]["mode"]:
            block("/inputs/deployment/mode", "Configuration mode mismatch")
        if set(_get(config, "spec.adapters.enabled", [])) != set(subject["selectedAdapters"]):
            block("/assessment/subject/selectedAdapters", "Configuration adapter scope mismatch")
        inventory_hash = canonical_digest(inventory_from_config(config))
        result["renderedInventorySha256"] = inventory_hash
        if inputs["deployment"]["renderedInventorySha256"] != inventory_hash:
            block(
                "/inputs/deployment/renderedInventorySha256", "Rendered inventory digest mismatch"
            )
    except (OSError, ValueError, ConfigurationError, RecursionError, yaml.YAMLError):
        block("/localConfig", "Local configuration cannot be validated")


def _check_inventory(path: Path, block: Any, result: dict) -> None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("oversized")
        inventory = yaml.safe_load(raw)
        if not isinstance(inventory, dict):
            raise ValueError("mapping")
        result["localInventorySha256"] = hashlib.sha256(raw).hexdigest()
        if canonical_digest(inventory) != result.get("renderedInventorySha256"):
            block(
                "/localInventory",
                "Inventory does not match configuration-derived targets/variables",
            )
    except (OSError, ValueError, RecursionError, yaml.YAMLError):
        block("/localInventory", "Local inventory cannot be validated")
