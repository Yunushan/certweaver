"""Enterprise v1 assessment evaluation; trust is supplied outside the assessment.

Editable names, URLs, hashes and PASS flags are claims. A trusted backend must
authenticate authorization and evidence semantics before they can earn credit.
The CLI deliberately has no such backend and cannot approve a release.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from jsonschema import Draft202012Validator, FormatChecker

from .errors import ConfigurationError
from .registry import project_root

CATALOGUE_SHA256 = "01edeb1c958ac83727b1d1a229300f3e5e2cc5e52b8f0bb33f05ce31e9abb224"
SCHEMA_SHA256 = "7f6702e488d5f4be328797b2c92bd7d19c387330001f72351d003bd6db1bead5"
EVALUATOR_VERSION = "1.0.0"
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
WINDOWS = {
    "policy90": timedelta(days=90),
    "ci7": timedelta(days=7),
    "security24": timedelta(hours=24),
    "live30": timedelta(days=30),
    # v1 has no evidence-method discriminator: apply the tighter limit.
    "mixed7_30": timedelta(days=7),
    "review30": timedelta(days=30),
    "providerStanding": timedelta(days=365),
}


def canonical_digest(value: Any) -> str:
    """SHA-256 of UTF-8, sorted keys, compact JSON, no NaN or ASCII escaping."""
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON numeric constant: {value}")


def read_document(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("Assessment exceeds the 16 MiB size limit")
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(result, dict):
            raise ValueError("Assessment must be a JSON object")
        return result
    except (OSError, ValueError, RecursionError) as exc:
        raise ConfigurationError(f"Cannot read enterprise assessment: {exc}") from exc


def _time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or "T" not in value:
        raise ValueError("An ISO timestamp with timezone is required")
    return result.astimezone(UTC)


_formats = FormatChecker()


@_formats.checks("date-time", raises=(ValueError, TypeError))
def _valid_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    _time(value)
    return True


@lru_cache(maxsize=1)
def _framework() -> tuple[dict, Draft202012Validator]:
    root = project_root() / "docs" / "readiness"
    raw = (root / "enterprise-controls.v1.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOGUE_SHA256:
        raise ConfigurationError("Enterprise catalogue differs from the frozen v1 digest")
    catalogue = json.loads(raw)
    schema_path = root / "enterprise-assessment.schema.json"
    if hashlib.sha256(schema_path.read_bytes()).hexdigest() != SCHEMA_SHA256:
        raise ConfigurationError("Enterprise schema differs from the frozen v1 digest")
    schema = read_document(schema_path)
    Draft202012Validator.check_schema(schema)
    return catalogue, Draft202012Validator(schema, format_checker=_formats)


def _without_approval_refs(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _without_approval_refs(v)
            for k, v in value.items()
            if not k.lower().endswith("approvalref")
        }
    if isinstance(value, list):
        return [_without_approval_refs(v) for v in value]
    return value


def scope_digest(document: dict) -> str:
    """Pre-test scope binding; approval references are excluded to avoid cycles."""
    return canonical_digest(
        _without_approval_refs(
            {
                key: document[key]
                for key in (
                    "frameworkId",
                    "frameworkVersion",
                    "catalogueSha256",
                    "subject",
                    "approvedObjectives",
                    "conditionalGateDecisions",
                )
            }
        )
    )


def review_digest(document: dict) -> str:
    """Bind approvals to claims, evidence and registers, excluding derived summaries.

    Approval records live in the trusted system. Their references are locators,
    not signed content; changing a locator never changes what must be approved.
    """
    return canonical_digest(
        _without_approval_refs(
            {
                key: value
                for key, value in document.items()
                if key not in {"$schema", "results", "gates", "approvals", "auditTrail"}
            }
        )
    )


def initialize_enterprise(path: str | Path) -> Path:
    """Copy an unassessed template without overwriting any existing result."""
    _framework()
    target = Path(path)
    raw = (project_root() / "docs/readiness/enterprise-assessment.template.json").read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
    return target.resolve()


@dataclass(frozen=True)
class Approval:
    actor_ref: str
    approved_at: datetime
    expires_at: datetime


class AssuranceBackend(Protocol):
    """Implemented by a controlled, independently configured integration.

    Never construct this from the assessment. Resolve current approval state,
    identity, role/authority, revocation and exact purpose/payload binding in the
    authenticated system. Return None on any uncertainty. For control purposes,
    approve only after inspecting all cumulative maturity requirements and real
    methods/outcomes (static checks cannot stand in for live qualification).
    """

    def approval(
        self, reference: str, *, purpose: str, payload_sha256: str, now: datetime
    ) -> Approval | None: ...

    def evidence(self, uri: str, *, sha256: str) -> bytes | None:
        """Fetch only authorized controlled locations; enforce network/access limits."""
        ...


@dataclass(frozen=True)
class ControlDecision:
    control_id: str
    category: str
    claimed_level: int | None
    earned_level: int
    state: str
    owner: str | None
    evidence_refs: tuple[str, ...]
    reviewer_approval_ref: str | None
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class EnterpriseAssessment:
    evaluator_version: str
    catalogue_sha256: str
    evaluated_at: str
    subject_sha256: str | None
    review_sha256: str | None
    verified_points: float
    maximum: int
    assessed_controls: int
    category_scores: dict[str, float]
    gates: dict[str, str]
    production_decision: str
    controls: tuple[ControlDecision, ...]
    errors: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return (
            not self.errors
            and self.verified_points == 100
            and self.production_decision == "APPROVED"
            and all(status == "PASS" for status in self.gates.values())
        )

    def to_dict(self) -> dict:
        return {**asdict(self), "complete": self.complete}


class _Evaluation:
    def __init__(
        self, document: dict, root: Path, now: datetime, backend: AssuranceBackend | None
    ) -> None:
        self.doc, self.root, self.now, self.backend = document, root.resolve(), now, backend
        self.subject = scope_digest(document)
        self.review = review_digest(document)
        self.errors: list[str] = []
        self.evidence_errors: dict[str, list[str]] = {}

    def approval(
        self,
        reference: str | None,
        purpose: str,
        *,
        scope: bool = False,
        after: datetime | None = None,
        author: str | None = None,
    ) -> Approval | None:
        if not reference or self.backend is None:
            return None
        try:
            result = self.backend.approval(
                reference,
                purpose=purpose,
                payload_sha256=self.subject if scope else self.review,
                now=self.now,
            )
            if (
                result is None
                or not result.actor_ref.strip()
                or result.approved_at.tzinfo is None
                or result.expires_at.tzinfo is None
                or not result.approved_at <= self.now < result.expires_at
                or (after is not None and result.approved_at < after)
                or result.actor_ref == author
            ):
                return None
            return result
        except Exception:  # A trust-service outage or bad response must deny credit.
            return None

    def evidence(self, ref: str) -> list[str]:
        if ref in self.evidence_errors:
            return self.evidence_errors[ref]
        errors: list[str] = []
        self.evidence_errors[ref] = errors
        record = self.doc["evidence"].get(ref)
        if record is None:
            errors.append(f"Unresolved evidence: {ref}")
            return errors
        observed, collected, expires = (
            _time(record[k]) for k in ("observedAt", "collectedAt", "expiresAt")
        )
        if not observed <= collected <= self.now < expires:
            errors.append(f"Invalid evidence chronology/expiry: {ref}")
        if self.now - observed > WINDOWS[record["freshnessPolicy"]]:
            errors.append(f"Stale evidence: {ref}")
        if record["subjectBindingSha256"] != self.subject:
            errors.append(f"Wrong evidence subject: {ref}")
        if record["isSynthetic"]:
            errors.append(f"Synthetic evidence cannot prove enterprise readiness: {ref}")
        try:
            if record["locationKind"] == "BUNDLE_RELATIVE":
                name = record["location"]
                relative = PurePosixPath(name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in name
                    or ":" in name
                    or not relative.parts
                ):
                    raise ValueError("unsafe evidence path")
                path = self.root / name
                if not path.resolve(strict=True).is_relative_to(self.root) or not path.is_file():
                    raise ValueError("evidence is outside bundle or not a regular file")
                # Reject links even if they currently point inside the bundle.
                if any(p.is_symlink() for p in [path, *path.parents] if p != self.root):
                    raise ValueError("linked evidence path")
                with path.open("rb") as stream:
                    raw = stream.read(MAX_EVIDENCE_BYTES + 1)
            else:
                raw = (
                    self.backend.evidence(record["location"], sha256=record["sha256"])
                    if self.backend
                    else None
                )
            if (
                not isinstance(raw, bytes)
                or not raw
                or len(raw) > MAX_EVIDENCE_BYTES
                or hashlib.sha256(raw).hexdigest() != record["sha256"]
            ):
                raise ValueError("evidence missing, empty, too large or digest mismatch")
        except Exception:
            errors.append(f"Evidence content verification failed: {ref}")
        if not self.approval(record["reviewApprovalRef"], f"evidence:{ref}", after=collected):
            errors.append(f"Evidence lacks authenticated review: {ref}")
        return errors

    def run(self, ref: str, control_id: str | None = None) -> list[str]:
        record = self.doc["verificationRuns"].get(ref)
        if record is None:
            return [f"Unresolved verification run: {ref}"]
        errors = []
        start, finish = _time(record["startedAt"]), _time(record["finishedAt"])
        if record["result"] != "PASS":
            errors.append(f"Verification run did not pass: {ref}")
        if not start <= finish <= self.now:
            errors.append(f"Invalid verification chronology: {ref}")
        if record["subjectBindingSha256"] != self.subject:
            errors.append(f"Wrong verification subject: {ref}")
        authorization = self.approval(record["authorizationRef"], f"run:{ref}", scope=True)
        if authorization is None or authorization.approved_at > start:
            errors.append(f"Run lacks prior authenticated authorization: {ref}")
        covered = False
        for evidence_ref in record["evidenceRefs"]:
            evidence_errors = self.evidence(evidence_ref)
            errors.extend(evidence_errors)
            evidence = self.doc["evidence"].get(evidence_ref)
            if evidence and (
                evidence["procedureRef"] != record["procedureRef"]
                or not start <= _time(evidence["observedAt"]) <= finish
            ):
                errors.append(f"Run/evidence procedure or chronology mismatch: {ref}")
            elif evidence and not evidence_errors and control_id in evidence["controlIds"]:
                covered = True
        # A run may collect different observations for different controls. Every
        # observation must remain valid, but only one must cover this control.
        if control_id is not None and not covered:
            errors.append(f"Verification run lacks evidence for control: {ref}/{control_id}")
        return errors

    def control(self, catalogue: dict, scope_approval: Approval | None) -> ControlDecision:
        cid = catalogue["id"]
        record = self.doc["controls"][cid]
        errors: list[str] = []
        level = record["maturityLevel"] or 0
        failed = record["state"] == "FAILED" or any(
            c["status"] == "FAIL" for c in record["criteriaResults"].values()
        )
        if failed:
            errors.append(
                "An observed acceptance failure earns zero until corrected and reverified"
            )
        if level:
            if scope_approval is None:
                errors.append("Scope/objectives/applicability lack authenticated pre-test approval")
            for field in ("accountableOwnerRef", "implementationAuthorRef"):
                if not record[field] or not record[field].strip():
                    errors.append(f"Missing {field}")
            if record["subjectBindingSha256"] != self.subject:
                errors.append("Control subject does not match frozen scope")
            if not record["evidenceRefs"]:
                errors.append("No cumulative maturity evidence")
            for ref in record["evidenceRefs"]:
                errors.extend(self.evidence(ref))
                evidence = self.doc["evidence"].get(ref)
                if evidence and (
                    cid not in evidence["controlIds"]
                    or (
                        scope_approval
                        and scope_approval.approved_at > _time(evidence["observedAt"])
                    )
                ):
                    errors.append(f"Evidence coverage/pre-test scope approval mismatch: {ref}")
                if (
                    evidence
                    and self.now - _time(evidence["observedAt"])
                    > WINDOWS[catalogue["freshnessPolicy"]]
                ):
                    errors.append(f"Evidence exceeds control freshness limit: {ref}")
            # A trusted domain decision is needed even for approved definition or
            # implementation credit; existence of a file proves neither.
            review = self.approval(
                record["reviewerApprovalRef"],
                f"control:{cid}:level:{level}",
                author=record["implementationAuthorRef"],
            )
            if review is None:
                errors.append("No authenticated independent cumulative maturity review")
            if level >= 3:
                if not record["verificationRunRefs"]:
                    errors.append("No executed verification runs")
                for ref in record["verificationRunRefs"]:
                    errors.extend(self.run(ref, cid))
                for criterion in record["criteriaResults"].values():
                    if criterion["status"] != "PASS" or not criterion["observedResult"]:
                        errors.append("Not every acceptance criterion has an observed pass")
                    if not criterion["evidenceRefs"] or not set(criterion["evidenceRefs"]) <= set(
                        record["evidenceRefs"]
                    ):
                        errors.append("Criterion evidence is absent from control evidence")
                    if criterion["verificationRef"] not in record["verificationRunRefs"]:
                        errors.append("Criterion run is absent from control verification")
                    elif not set(criterion["evidenceRefs"]) <= set(
                        self.doc["verificationRuns"]
                        .get(criterion["verificationRef"], {})
                        .get("evidenceRefs", [])
                    ):
                        errors.append("Criterion evidence is absent from its verification run")
                if not record["verifiedAt"]:
                    errors.append("Missing verification timestamp")
                elif not _time(record["verifiedAt"]) <= self.now:
                    errors.append("Future verification timestamp")
                else:
                    verified = _time(record["verifiedAt"])
                    if self.now - verified > WINDOWS[catalogue["freshnessPolicy"]]:
                        errors.append("Control verification is stale")
                    for ref in record["verificationRunRefs"]:
                        run = self.doc["verificationRuns"].get(ref)
                        if run and _time(run["finishedAt"]) > verified:
                            errors.append("Control verified before run completion")
            if level == 4:
                verified, reviewed, due = (
                    _time(record[k]) for k in ("verifiedAt", "reviewedAt", "nextReviewDueAt")
                )
                if not verified <= reviewed <= self.now < due:
                    errors.append("Invalid control review chronology/expiry")
                if self.now - reviewed > timedelta(days=30):
                    errors.append("Independent review is stale")
                if review and (
                    review.approved_at < reviewed or review.actor_ref == record["verifierRef"]
                ):
                    errors.append("Review predates assurance or reviewer is the verifier")
        if record["state"] == "BLOCKED" and not record["blockedReason"]:
            errors.append("Blocked control has no reason")
        for finding in self.doc["findings"]:
            if cid in finding["controlIds"] and finding["state"] != "CLOSED":
                errors.append(f"Unresolved finding: {finding['id']}")
        for exception in self.doc["exceptions"]:
            if cid in exception["controlIds"] and exception["state"] != "CLOSED":
                errors.append(f"Unresolved criterion exception: {exception['id']}")
        known_findings = {f["id"] for f in self.doc["findings"]}
        if not set(record["findingRefs"]) <= known_findings:
            errors.append("Unresolved finding reference")
        if record["exceptionRef"] and record["exceptionRef"] not in {
            e["id"] for e in self.doc["exceptions"]
        }:
            errors.append("Unresolved exception reference")
        return ControlDecision(
            cid,
            catalogue["category"],
            record["maturityLevel"],
            0 if errors or failed else level,
            record["state"],
            record["accountableOwnerRef"],
            tuple(record["evidenceRefs"]),
            record["reviewerApprovalRef"],
            tuple(dict.fromkeys(errors)),
        )


def evaluate_enterprise(
    path: str | Path, *, now: datetime | None = None, backend: AssuranceBackend | None = None
) -> EnterpriseAssessment:
    """Recompute, never edit, a v1 assessment. Missing trust always denies credit."""
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        raise ConfigurationError("Evaluation time must have a timezone")
    moment = moment.astimezone(UTC)
    catalogue, validator = _framework()
    document = read_document(Path(path))
    errors = [
        "/".join(map(str, e.absolute_path)) + ": " + e.message
        for e in validator.iter_errors(document)
    ]
    categories = {c["id"]: 0.0 for c in catalogue["categories"]}
    gates = {g["id"]: "UNKNOWN" for g in catalogue["releaseGates"]}
    if errors:
        return EnterpriseAssessment(
            EVALUATOR_VERSION,
            CATALOGUE_SHA256,
            moment.isoformat(),
            None,
            None,
            0,
            100,
            0,
            categories,
            gates,
            "NOT_APPROVED",
            (),
            tuple(errors),
        )
    evaluation = _Evaluation(document, Path(path).parent, moment, backend)
    scope_approval = evaluation.approval(
        document["subject"]["scopeApprovalRef"], "scope", scope=True
    )
    decisions = tuple(
        evaluation.control(control, scope_approval) for control in catalogue["controls"]
    )
    by_id = {c.control_id: c for c in decisions}
    for control in decisions:
        categories[control.category] += control.earned_level / 4
    points = sum(c.earned_level for c in decisions) / 4
    for gate in catalogue["releaseGates"]:
        required = list(gate["mandatoryControlIds"])
        unknown = False
        for cid in gate["conditionalControlIds"]:
            decision = document["conditionalGateDecisions"][cid]
            if (
                decision["active"] is None
                or not decision["rationale"]
                or not evaluation.approval(
                    decision["reviewApprovalRef"], f"applicability:{cid}", scope=True
                )
            ):
                unknown = True
            elif decision["active"]:
                required.append(cid)
        failed = any(
            by_id[cid].state in {"FAILED", "STALE"} or by_id[cid].limitations for cid in required
        )
        gates[gate["id"]] = (
            "FAIL"
            if failed
            else (
                "UNKNOWN"
                if unknown or any(by_id[c].earned_level != 4 for c in required)
                else "PASS"
            )
        )
        stored = document["gates"][gate["id"]]
        if gates[gate["id"]] == "PASS":
            checked = _time(stored["checkedAt"]) if stored["checkedAt"] else None
            if (
                checked is None
                or checked > moment
                or not stored["rationale"]
                or not evaluation.approval(
                    stored["reviewApprovalRef"], f"gate:{gate['id']}", after=checked
                )
            ):
                gates[gate["id"]] = "UNKNOWN"
        if stored["status"] != gates[gate["id"]]:
            errors.append(f"Stored gate status differs from recomputed decision: {gate['id']}")
    # Inspect unused records too: hiding a failed/changed record by removing its
    # reference must not silently turn a previously failed assessment green.
    for ref in document["evidence"]:
        errors.extend(evaluation.evidence(ref))
    for ref, run in document["verificationRuns"].items():
        covered = {
            cid
            for evidence_ref in run["evidenceRefs"]
            for cid in document["evidence"].get(evidence_ref, {}).get("controlIds", [])
        }
        if not covered:
            errors.append(f"Verification run has no resolvable coverage: {ref}")
        errors.extend(evaluation.run(ref))
    for kind in ("findings", "exceptions", "changeImpactReviews", "auditTrail"):
        records = document[kind]
        ids = [r["id"] for r in records]
        if len(ids) != len(set(ids)):
            errors.append(f"Duplicate IDs in {kind}")
    # Closure needs real inspectable evidence and an authenticated disposition.
    for kind in ("findings", "exceptions"):
        for record in document[kind]:
            if record["state"] == "CLOSED":
                for ref in record["closureEvidenceRefs"]:
                    errors.extend(evaluation.evidence(ref))
                if not evaluation.approval(
                    record["closureApprovalRef"],
                    f"closure:{kind}:{record['id']}",
                    after=_time(record["closedAt"]),
                ):
                    errors.append(f"Unauthenticated closure: {record['id']}")
            elif kind == "exceptions" or record["severity"] in {"P0", "P1"}:
                errors.append(f"Unresolved {kind}: {record['id']}")
    for record in document["changeImpactReviews"]:
        affected, unaffected = (
            set(record["affectedControlIds"]),
            set(record["unaffectedControlIds"]),
        )
        if (
            affected & unaffected
            or affected | unaffected != set(by_id)
            or record["currentSubjectSha256"] != evaluation.subject
            or record["previousSubjectSha256"] == evaluation.subject
        ):
            errors.append(f"Invalid change-impact scope/coverage: {record['id']}")
        for ref in record["evidenceRefs"]:
            errors.extend(evaluation.evidence(ref))
        if not evaluation.approval(
            record["reviewApprovalRef"], f"change:{record['id']}", after=_time(record["reviewedAt"])
        ):
            errors.append(f"Unauthenticated change-impact review: {record['id']}")
    for record in document["auditTrail"]:
        if (
            _time(record["at"]) > moment
            or record["subjectBindingSha256"] != evaluation.subject
            or not evaluation.approval(
                record["controlledRecordRef"], f"audit:{record['id']}", after=_time(record["at"])
            )
        ):
            errors.append(f"Unverified audit record: {record['id']}")
    subject = document["subject"]
    immutable = (
        isinstance(subject["gitCommit"], str)
        and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", subject["gitCommit"])
        and subject["workingTreePatchSha256"] is None
    )
    # A numeric 100 or approval is a final claim, never a summary-only shortcut.
    final = points == 100 and all(v == "PASS" for v in gates.values()) and not errors
    if final:
        if not immutable or document["assessmentState"] != "FINAL":
            errors.append("Final assurance requires an immutable committed FINAL subject")
        for key in (
            "configSha256",
            "deploymentResourcesSha256",
            "pipelineDefinitionSha256",
            "packagingDefinitionSha256",
        ):
            if not re.fullmatch(r"[a-f0-9]{64}", subject[key] or ""):
                errors.append(f"Invalid final subject digest: {key}")
        artifact_ids = [a["artifactId"] for a in subject["releaseArtifacts"]]
        if len(artifact_ids) != len(set(artifact_ids)):
            errors.append("Duplicate release artifact identity")
        for artifact in subject["releaseArtifacts"]:
            if (
                not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])
                or not artifact["provenanceRef"]
            ):
                errors.append(f"Incomplete release artifact identity: {artifact['artifactId']}")
        latest_review = max(_time(c["reviewedAt"]) for c in document["controls"].values())
        implementers = {c["implementationAuthorRef"] for c in document["controls"].values()}
        verifiers = {c["verifierRef"] for c in document["controls"].values()}
        for role, record in document["approvals"].items():
            approval = evaluation.approval(
                record["approvalRecordRef"] if record else None,
                f"release:{role}",
                after=latest_review,
            )
            if (
                approval is None
                or record["actorRef"] != approval.actor_ref
                or record["subjectBindingSha256"] != evaluation.subject
                or _time(record["approvedAt"]) != approval.approved_at
            ):
                errors.append(f"Missing/mismatched authenticated release approval: {role}")
            if (
                role == "independentAssessor"
                and approval
                and approval.actor_ref in (implementers | verifiers)
            ):
                errors.append("Independent release assessor implemented or verified the candidate")
        for key, objective in document["approvedObjectives"].items():
            if not evaluation.approval(
                objective["ownerApprovalRef"], f"objective:{key}", scope=True
            ):
                errors.append(f"Unauthenticated objective approval: {key}")
        if len({r["actorRef"] for r in document["approvals"].values() if r}) < 2:
            errors.append("Release lacks separation of duties")
    stored = document["results"]
    if stored["verifiedPoints"] != points:
        errors.append(
            f"Stored verifiedPoints {stored['verifiedPoints']} differs from computed {points}"
        )
    if stored["assessmentScore"] is not None and stored["assessmentScore"] != points:
        errors.append("Stored assessmentScore differs from computed credit")
    expected_counts = {
        "assessedControls": sum(c.state != "NOT_ASSESSED" for c in decisions),
        "unassessedControls": sum(c.state == "NOT_ASSESSED" for c in decisions),
        "assuredControls": sum(c.earned_level == 4 for c in decisions),
        "failedControls": sum(c.state == "FAILED" for c in decisions),
        "blockedControls": sum(c.state == "BLOCKED" for c in decisions),
        "staleControls": sum(c.state == "STALE" for c in decisions),
    }
    for key, value in expected_counts.items():
        if stored[key] != value:
            errors.append(f"Stored {key} differs from computed count {value}")
    if points == 100 and not all(v == "PASS" for v in gates.values()):
        errors.append("100 requires every independently reviewed category gate to pass")
    computed_verdict = (
        "FAIL"
        if "FAIL" in gates.values()
        else ("UNKNOWN" if "UNKNOWN" in gates.values() else "PASS")
    )
    if stored["gateVerdict"] != computed_verdict:
        errors.append("Stored gateVerdict differs from computed gates")
    approved = final and not errors and stored["productionDecision"] == "APPROVED"
    if errors:
        # A corrupt assessment envelope cannot grant credit. Keep the original
        # claims and specific per-control limitations in the reproducible export.
        decisions = tuple(
            replace(
                c,
                earned_level=0,
                limitations=(
                    *c.limitations,
                    "Assessment integrity/authorization errors prevent accepting credit",
                ),
            )
            for c in decisions
        )
        points = 0
        categories = {key: 0.0 for key in categories}
        gates = {key: "FAIL" for key in gates}
    return EnterpriseAssessment(
        EVALUATOR_VERSION,
        CATALOGUE_SHA256,
        moment.isoformat(),
        evaluation.subject,
        evaluation.review,
        points,
        100,
        sum(c.state != "NOT_ASSESSED" for c in decisions),
        categories,
        gates,
        "APPROVED" if approved else "NOT_APPROVED",
        decisions,
        tuple(dict.fromkeys(errors)),
    )
