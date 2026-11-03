"""Evaluator fixtures exercise logic only; they are not deployment evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from certweaver import cli, enterprise
from certweaver.enterprise import Approval, evaluate_enterprise, review_digest, scope_digest
from certweaver.errors import ConfigurationError
from certweaver.registry import project_root

NOW = datetime(2026, 11, 3, 12, tzinfo=UTC)


def stamp(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat()


def template() -> dict:
    return json.loads(
        (project_root() / "docs/readiness/enterprise-assessment.template.json").read_text(
            encoding="utf-8"
        )
    )


class FixtureAuthority:
    """In-memory authority double, NEVER a production approval integration."""

    def __init__(self, document: dict) -> None:
        self.scope, self.review = scope_digest(document), review_digest(document)
        self.deny: str | None = None
        self.actor: str | None = None
        self.expired = False
        self.offline = False
        self.remote = b"unit-test-only observation\n"

    def approval(self, reference, *, purpose, payload_sha256, now):
        if self.offline:
            raise OSError("fixture authority unavailable")
        pre_test = purpose == "scope" or purpose.startswith(
            ("run:", "applicability:", "objective:")
        )
        if payload_sha256 != (self.scope if pre_test else self.review) or self.deny == purpose:
            return None
        actor = self.actor or (
            purpose.removeprefix("release:")
            if purpose.startswith("release:")
            else "fixture-reviewer"
        )
        return Approval(
            actor,
            NOW - timedelta(minutes=240 if pre_test else 30),
            NOW + timedelta(minutes=-1 if self.expired else 1440),
        )

    def evidence(self, uri, *, sha256):
        if self.offline:
            raise OSError("fixture evidence unavailable")
        return self.remote


def save(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "assessment.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def complete_fixture(tmp_path: Path) -> dict:
    """Build a logic fixture, not a passing assessment of CertWeaver."""
    document = template()
    document["assessmentState"] = "FINAL"
    subject = document["subject"]
    for field, value in subject.items():
        if value is None and field != "workingTreePatchSha256":
            subject[field] = "fixture-only"
    subject["assuranceClaim"] = "PRODUCTION_LAUNCH"
    subject["gitCommit"] = "a" * 40
    for field in (
        "configSha256",
        "deploymentResourcesSha256",
        "pipelineDefinitionSha256",
        "packagingDefinitionSha256",
    ):
        subject[field] = "b" * 64
    for field in ("targetEnvironments", "compatibilityMatrixRefs", "issuerPaths"):
        subject[field] = ["fixture-only"]
    subject["releaseArtifacts"] = [
        {
            "artifactId": "fixture-wheel",
            "kind": "wheel",
            "location": "fixture-only",
            "sha256": "c" * 64,
            "provenanceRef": "fixture-provenance",
        }
    ]
    for objective in document["approvedObjectives"].values():
        objective.update(
            target="1",
            unitAndWindow="fixture unit/window",
            measurementRef="fixture-procedure",
            ownerApprovalRef="fixture-approval",
        )
    for decision in document["conditionalGateDecisions"].values():
        decision.update(active=True, rationale="fixture activated", reviewApprovalRef="fixture")
    binding = scope_digest(document)
    raw = b"unit-test-only observation\n"
    (tmp_path / "observation.txt").write_bytes(raw)
    document["evidence"]["fixture-evidence"] = {
        "controlIds": list(document["controls"]),
        "procedureRef": "fixture-procedure",
        "subjectBindingSha256": binding,
        "observedAt": stamp(-120),
        "collectedAt": stamp(-90),
        "collectorRef": "fixture-operator",
        "location": "observation.txt",
        "locationKind": "BUNDLE_RELATIVE",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "classification": "PUBLIC_SANITIZED",
        "retentionPolicyRef": "fixture-policy",
        "expectedOutcome": "fixture expected",
        "actualOutcome": "fixture observed",
        "methodAndToolVersions": "fixture only",
        "limitations": "not live production evidence",
        "isSynthetic": False,
        "reviewApprovalRef": "fixture-review",
        "freshnessPolicy": "security24",
        "expiresAt": stamp(1440),
        "changeOrCiRunRef": "fixture",
    }
    document["verificationRuns"]["fixture-run"] = {
        "procedureRef": "fixture-procedure",
        "subjectBindingSha256": binding,
        "operatorRef": "fixture-operator",
        "authorizationRef": "fixture-authorization",
        "startedAt": stamp(-180),
        "finishedAt": stamp(-100),
        "expectedOutcome": "fixture",
        "actualOutcome": "fixture",
        "result": "PASS",
        "evidenceRefs": ["fixture-evidence"],
        "stopAndCleanupResult": "fixture cleaned",
    }
    for record in document["controls"].values():
        record.update(
            state="ASSURED",
            maturityLevel=4,
            accountableOwnerRef="fixture-owner",
            implementationAuthorRef="fixture-author",
            verifierRef="fixture-operator",
            reviewerApprovalRef="fixture-review",
            verifiedAt=stamp(-80),
            reviewedAt=stamp(-60),
            nextReviewDueAt=stamp(1440),
            subjectBindingSha256=binding,
            evidenceRefs=["fixture-evidence"],
            verificationRunRefs=["fixture-run"],
        )
        for criterion in record["criteriaResults"].values():
            criterion.update(
                status="PASS",
                observedResult="fixture-only outcome",
                evidenceRefs=["fixture-evidence"],
                verificationRef="fixture-run",
            )
    for gate in document["gates"].values():
        gate.update(
            status="PASS",
            reviewApprovalRef="fixture-review",
            checkedAt=stamp(-30),
            rationale="fixture-only",
        )
    for role in document["approvals"]:
        document["approvals"][role] = {
            "actorRef": role,
            "trustedSystemRef": "unit-test-double-only",
            "approvalRecordRef": "fixture",
            "approvedAt": stamp(-30),
            "subjectBindingSha256": binding,
        }
    document["results"].update(
        assessmentScore=100,
        verifiedPoints=100,
        assessedControls=100,
        unassessedControls=0,
        assuredControls=100,
        gateVerdict="PASS",
        productionDecision="APPROVED",
    )
    return document


def test_template_is_unassessed_and_initialization_does_not_overwrite(tmp_path):
    path = enterprise.initialize_enterprise(tmp_path / "new" / "assessment.json")
    result = evaluate_enterprise(path, now=NOW)
    assert result.verified_points == result.assessed_controls == 0
    assert not result.complete and result.errors == ()
    assert set(result.gates.values()) == {"UNKNOWN"}
    assert len(result.controls) == 100
    with pytest.raises(FileExistsError):
        enterprise.initialize_enterprise(path)


def test_complete_logic_fixture_requires_external_authority(tmp_path):
    document = complete_fixture(tmp_path)
    path = save(tmp_path, document)
    result = evaluate_enterprise(path, now=NOW, backend=FixtureAuthority(document))
    assert result.complete, result.errors or result.controls[0].limitations
    assert result.verified_points == 100
    assert sum(result.category_scores.values()) == 100
    assert result.to_dict()["complete"] is True
    assert not evaluate_enterprise(path, now=NOW).complete
    assert evaluate_enterprise(path, now=NOW).verified_points == 0


@pytest.mark.parametrize("level,state", [(1, "DEFINED"), (2, "IMPLEMENTED"), (3, "VERIFIED")])
def test_cumulative_partial_credit_is_exact_without_approving_release(tmp_path, level, state):
    document = complete_fixture(tmp_path)
    for record in document["controls"].values():
        record.update(state=state, maturityLevel=level)
    document["assessmentState"] = "DRAFT"
    document["results"].update(
        assessmentScore=25 * level,
        verifiedPoints=25 * level,
        assuredControls=0,
        gateVerdict="UNKNOWN",
        productionDecision="NOT_APPROVED",
    )
    for gate in document["gates"].values():
        gate["status"] = "UNKNOWN"
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert result.verified_points == 25 * level, result.controls[0].limitations
    assert not result.complete
    assert set(result.gates.values()) == {"UNKNOWN"}


@pytest.mark.parametrize(
    "attack",
    [
        "missing-control",
        "unknown-control",
        "weight",
        "denominator",
        "level",
        "criterion-text",
        "criterion-missing",
        "failed-criterion",
        "unknown-criterion",
        "unresolved-evidence",
        "unresolved-run",
        "criterion-run",
        "criterion-evidence",
        "run-failed",
        "run-subject",
        "evidence-subject",
        "control-subject",
        "synthetic",
        "tamper",
        "empty",
        "missing-file",
        "escape",
        "absolute",
        "windows-path",
        "backslash",
        "future-observation",
        "stale",
        "expired-evidence",
        "collect-before-observe",
        "verify-before-run",
        "review-before-verify",
        "expired-review",
        "future-review",
        "bad-date",
        "naive-date",
        "unresolved-finding",
        "unresolved-exception",
        "unknown-applicability",
        "dirty-subject",
        "commit",
        "subject-digest",
        "artifact-digest",
        "artifact-provenance",
        "duplicate-artifact",
        "forged-total",
        "gate-membership",
    ],
)
def test_adversarial_assessment_cannot_complete(tmp_path, attack):
    document = complete_fixture(tmp_path)
    control = document["controls"]["GOV-01"]
    evidence = document["evidence"]["fixture-evidence"]
    run = document["verificationRuns"]["fixture-run"]
    criterion = control["criteriaResults"]["AC-01"]
    if attack == "missing-control":
        del document["controls"]["GOV-01"]
    elif attack == "unknown-control":
        document["controls"]["FAKE-01"] = control.copy()
    elif attack == "weight":
        control["weight"] = 2
    elif attack == "denominator":
        document["results"]["maximum"] = 99
    elif attack == "level":
        control["maturityLevel"] = 5
    elif attack == "criterion-text":
        criterion["criterion"] = "easier acceptance"
    elif attack == "criterion-missing":
        del control["criteriaResults"]["AC-01"]
    elif attack == "failed-criterion":
        criterion["status"] = "FAIL"
    elif attack == "unknown-criterion":
        criterion["status"] = "UNKNOWN"
    elif attack == "unresolved-evidence":
        control["evidenceRefs"] = ["missing"]
    elif attack == "unresolved-run":
        control["verificationRunRefs"] = ["missing"]
    elif attack == "criterion-run":
        criterion["verificationRef"] = "missing"
    elif attack == "criterion-evidence":
        criterion["evidenceRefs"] = ["missing"]
    elif attack == "run-failed":
        run["result"] = "FAIL"
    elif attack == "run-subject":
        run["subjectBindingSha256"] = "d" * 64
    elif attack == "evidence-subject":
        evidence["subjectBindingSha256"] = "d" * 64
    elif attack == "control-subject":
        control["subjectBindingSha256"] = "d" * 64
    elif attack == "synthetic":
        evidence["isSynthetic"] = True
    elif attack == "tamper":
        (tmp_path / "observation.txt").write_bytes(b"changed")
    elif attack == "empty":
        (tmp_path / "observation.txt").write_bytes(b"")
    elif attack == "missing-file":
        (tmp_path / "observation.txt").unlink()
    elif attack == "escape":
        evidence["location"] = "../observation.txt"
    elif attack == "absolute":
        evidence["location"] = "/etc/passwd"
    elif attack == "windows-path":
        evidence["location"] = "C:/Windows/win.ini"
    elif attack == "backslash":
        evidence["location"] = "..\\observation.txt"
    elif attack == "future-observation":
        evidence["observedAt"] = stamp(1)
    elif attack == "stale":
        evidence["observedAt"] = stamp(-1500)
    elif attack == "expired-evidence":
        evidence["expiresAt"] = stamp(-1)
    elif attack == "collect-before-observe":
        evidence["collectedAt"] = stamp(-121)
    elif attack == "verify-before-run":
        control["verifiedAt"] = stamp(-101)
    elif attack == "review-before-verify":
        control["reviewedAt"] = stamp(-81)
    elif attack == "expired-review":
        control["nextReviewDueAt"] = stamp(-1)
    elif attack == "future-review":
        control["reviewedAt"] = stamp(1)
    elif attack == "bad-date":
        evidence["observedAt"] = "2026-02-30T12:00:00Z"
    elif attack == "naive-date":
        evidence["observedAt"] = "2026-11-03T12:00:00"
    elif attack == "unresolved-finding":
        control["findingRefs"] = ["missing"]
    elif attack == "unresolved-exception":
        control["exceptionRef"] = "missing"
    elif attack == "unknown-applicability":
        document["conditionalGateDecisions"]["PKI-10"]["active"] = None
    elif attack == "dirty-subject":
        document["subject"]["workingTreePatchSha256"] = "d" * 64
    elif attack == "commit":
        document["subject"]["gitCommit"] = "main"
    elif attack == "subject-digest":
        document["subject"]["configSha256"] = "not-a-digest"
    elif attack == "artifact-digest":
        document["subject"]["releaseArtifacts"][0]["sha256"] = "invalid"
    elif attack == "artifact-provenance":
        document["subject"]["releaseArtifacts"][0]["provenanceRef"] = None
    elif attack == "duplicate-artifact":
        document["subject"]["releaseArtifacts"] *= 2
    elif attack == "forged-total":
        document["results"]["verifiedPoints"] = 99.75
    elif attack == "gate-membership":
        document["gates"]["G-01"]["mandatoryControlIds"] = []
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert not result.complete
    assert result.production_decision == "NOT_APPROVED"


@pytest.mark.parametrize(
    "failure",
    [
        "offline",
        "expired",
        "author",
        "verifier",
        "scope",
        "evidence",
        "control",
        "run",
        "gate",
        "applicability",
        "release",
        "objective",
    ],
)
def test_authority_failure_or_invalid_identity_denies_completion(tmp_path, failure):
    document = complete_fixture(tmp_path)
    backend = FixtureAuthority(document)
    if failure == "offline":
        backend.offline = True
    elif failure == "expired":
        backend.expired = True
    elif failure == "author":
        backend.actor = "fixture-author"
    elif failure == "verifier":
        backend.actor = "fixture-operator"
    else:
        backend.deny = {
            "scope": "scope",
            "evidence": "evidence:fixture-evidence",
            "control": "control:GOV-01:level:4",
            "run": "run:fixture-run",
            "gate": "gate:G-01",
            "applicability": "applicability:PKI-10",
            "release": "release:independentAssessor",
            "objective": "objective:apiAvailability",
        }[failure]
    assert not evaluate_enterprise(save(tmp_path, document), now=NOW, backend=backend).complete


def test_changed_claims_invalidate_preexisting_approvals(tmp_path):
    document = complete_fixture(tmp_path)
    backend = FixtureAuthority(document)
    document["evidence"]["fixture-evidence"]["actualOutcome"] = "changed after review"
    result = evaluate_enterprise(save(tmp_path, document), now=NOW, backend=backend)
    assert result.verified_points == 0


@pytest.mark.parametrize(
    "raw",
    ['{"controls":{},"controls":{}}', '{"x":NaN}', '{"x":Infinity}', "[]", '"wrong"', "{broken"],
)
def test_ambiguous_or_malformed_json_rejected(tmp_path, raw):
    path = tmp_path / "invalid.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        evaluate_enterprise(path, now=NOW)


def test_controlled_evidence_is_never_fetched_without_explicit_backend(tmp_path):
    document = complete_fixture(tmp_path)
    document["evidence"]["fixture-evidence"].update(
        locationKind="CONTROLLED_URI", location="https://fixture.invalid/evidence"
    )
    path = save(tmp_path, document)
    assert evaluate_enterprise(path, now=NOW, backend=FixtureAuthority(document)).complete
    assert not evaluate_enterprise(path, now=NOW).complete


def test_cli_exports_all_decisions_and_exits_incomplete(tmp_path, capsys):
    path = enterprise.initialize_enterprise(tmp_path / "assessment.json")
    args = cli.build_parser().parse_args(["enterprise-score", str(path), "--json"])
    assert args.func(args) == 2
    export = json.loads(capsys.readouterr().out)
    assert export["verified_points"] == 0 and len(export["controls"]) == 100
    args = cli.build_parser().parse_args(["enterprise-score", str(path)])
    assert args.func(args) == 2
    assert "0/100" in capsys.readouterr().out


def test_naive_evaluation_time_is_rejected(tmp_path):
    path = enterprise.initialize_enterprise(tmp_path / "assessment.json")
    with pytest.raises(ConfigurationError):
        evaluate_enterprise(path, now=datetime(2026, 11, 3))


def add_register_records(document):
    binding = scope_digest(document)
    document["findings"] = [
        {
            "id": "fixture-finding",
            "controlIds": ["GOV-01"],
            "severity": "P1",
            "state": "CLOSED",
            "summary": "fixture only",
            "ownerRef": "fixture-owner",
            "openedAt": stamp(-300),
            "dueAt": stamp(1440),
            "closedAt": stamp(-60),
            "closureApprovalRef": "fixture",
            "closureEvidenceRefs": ["fixture-evidence"],
        }
    ]
    document["exceptions"] = [
        {
            "id": "fixture-exception",
            "controlIds": ["GOV-01"],
            "criterionRefs": ["GOV-01/AC-01"],
            "state": "CLOSED",
            "impact": "fixture",
            "compensatingMeasures": "fixture",
            "ownerRef": "fixture-owner",
            "approvalRef": "fixture",
            "approvedAt": stamp(-240),
            "expiresAt": stamp(1440),
            "remediationPlan": "fixture",
            "closedAt": stamp(-60),
            "closureApprovalRef": "fixture",
            "closureEvidenceRefs": ["fixture-evidence"],
            "mayOverrideGate": False,
            "mayEarnMissingCredit": False,
        }
    ]
    document["changeImpactReviews"] = [
        {
            "id": "fixture-change",
            "changeRef": "fixture",
            "previousSubjectSha256": "d" * 64,
            "currentSubjectSha256": binding,
            "affectedControlIds": list(document["controls"]),
            "unaffectedControlIds": [],
            "rationale": "fixture",
            "evidenceRefs": ["fixture-evidence"],
            "reviewApprovalRef": "fixture",
            "reviewedAt": stamp(-60),
        }
    ]
    document["auditTrail"] = [
        {
            "id": "fixture-audit",
            "action": "fixture only",
            "actorRef": "fixture-reviewer",
            "at": stamp(-60),
            "subjectBindingSha256": binding,
            "controlledRecordRef": "fixture",
        }
    ]


def test_closed_registers_and_reviewed_change_history_can_be_assessed(tmp_path):
    document = complete_fixture(tmp_path)
    add_register_records(document)
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert result.complete, result.errors


@pytest.mark.parametrize(
    "attack",
    [
        "open-finding",
        "accepted-risk",
        "active-exception",
        "fake-closure",
        "closure-evidence",
        "duplicate-finding",
        "duplicate-exception",
        "duplicate-change",
        "duplicate-audit",
        "change-overlap",
        "change-missing",
        "change-subject",
        "change-same-subject",
        "change-approval",
        "audit-subject",
        "audit-future",
        "audit-approval",
        "count",
        "gate-total",
        "no-gate-approval",
        "no-release-approval",
        "no-objective-approval",
    ],
)
def test_register_or_summary_integrity_failure_never_reports_accepted_100(tmp_path, attack):
    document = complete_fixture(tmp_path)
    add_register_records(document)
    deny = None
    if attack == "open-finding":
        document["findings"][0]["state"] = "OPEN"
    elif attack == "accepted-risk":
        document["findings"][0]["state"] = "ACCEPTED_RISK"
    elif attack == "active-exception":
        document["exceptions"][0]["state"] = "ACTIVE"
    elif attack == "fake-closure":
        deny = "closure:findings:fixture-finding"
    elif attack == "closure-evidence":
        document["findings"][0]["closureEvidenceRefs"] = ["absent"]
    elif attack == "duplicate-finding":
        document["findings"] *= 2
    elif attack == "duplicate-exception":
        document["exceptions"] *= 2
    elif attack == "duplicate-change":
        document["changeImpactReviews"] *= 2
    elif attack == "duplicate-audit":
        document["auditTrail"] *= 2
    elif attack == "change-overlap":
        document["changeImpactReviews"][0]["unaffectedControlIds"] = ["GOV-01"]
    elif attack == "change-missing":
        document["changeImpactReviews"][0]["affectedControlIds"] = []
    elif attack == "change-subject":
        document["changeImpactReviews"][0]["currentSubjectSha256"] = "e" * 64
    elif attack == "change-same-subject":
        document["changeImpactReviews"][0]["previousSubjectSha256"] = scope_digest(document)
    elif attack == "change-approval":
        deny = "change:fixture-change"
    elif attack == "audit-subject":
        document["auditTrail"][0]["subjectBindingSha256"] = "e" * 64
    elif attack == "audit-future":
        document["auditTrail"][0]["at"] = stamp(1)
    elif attack == "audit-approval":
        deny = "audit:fixture-audit"
    elif attack == "count":
        document["results"]["assuredControls"] = 99
    elif attack == "gate-total":
        document["results"]["gateVerdict"] = "UNKNOWN"
    elif attack == "no-gate-approval":
        deny = "gate:G-01"
    elif attack == "no-release-approval":
        deny = "release:serviceOwner"
    elif attack == "no-objective-approval":
        deny = "objective:apiAvailability"
    backend = FixtureAuthority(document)
    backend.deny = deny
    result = evaluate_enterprise(save(tmp_path, document), now=NOW, backend=backend)
    assert not result.complete
    assert result.verified_points < 100
    assert sum(result.category_scores.values()) == result.verified_points
    assert sum(c.earned_level for c in result.controls) / 4 == result.verified_points


@pytest.mark.parametrize("change", ["catalogue", "schema"])
def test_framework_bytes_are_pinned_not_selected_by_assessment(tmp_path, monkeypatch, change):
    root = tmp_path / "framework"
    destination = root / "docs/readiness"
    destination.mkdir(parents=True)
    for name in ("enterprise-controls.v1.json", "enterprise-assessment.schema.json"):
        raw = (project_root() / "docs/readiness" / name).read_bytes()
        if (change == "catalogue" and name.startswith("enterprise-controls")) or (
            change == "schema" and name.endswith("schema.json")
        ):
            raw += b"\n"
        (destination / name).write_bytes(raw)
    enterprise._framework.cache_clear()
    monkeypatch.setattr(enterprise, "project_root", lambda: root)
    try:
        with pytest.raises(ConfigurationError, match="frozen v1 digest"):
            enterprise._framework()
    finally:
        enterprise._framework.cache_clear()


def test_blocked_control_retains_only_authenticated_lower_level_credit(tmp_path):
    document = template()
    document["subject"]["scopeApprovalRef"] = "fixture-scope"
    binding = scope_digest(document)
    # Reuse the well-shaped observation but bind it to this draft scope.
    complete = complete_fixture(tmp_path)
    evidence = complete["evidence"]["fixture-evidence"]
    evidence.update(controlIds=["GOV-01"], subjectBindingSha256=binding)
    document["evidence"]["fixture-evidence"] = evidence
    document["controls"]["GOV-01"].update(
        state="BLOCKED",
        maturityLevel=1,
        blockedReason="fixture missing live input",
        accountableOwnerRef="fixture-owner",
        implementationAuthorRef="fixture-author",
        subjectBindingSha256=binding,
        evidenceRefs=["fixture-evidence"],
        reviewerApprovalRef="fixture-review",
    )
    document["results"].update(
        verifiedPoints=0.25,
        assessmentScore=0.25,
        assessedControls=1,
        unassessedControls=99,
        blockedControls=1,
    )
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert result.verified_points == 0.25, result.errors
    assert not result.complete


def test_large_input_and_missing_input_fail_cleanly(tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_text('{"field": "too large"}', encoding="utf-8")
    monkeypatch.setattr(enterprise, "MAX_DOCUMENT_BYTES", 8)
    with pytest.raises(ConfigurationError, match="size limit"):
        enterprise.read_document(path)
    with pytest.raises(ConfigurationError):
        enterprise.read_document(tmp_path / "missing.json")


def test_failed_acceptance_cannot_retain_defined_credit(tmp_path):
    document = complete_fixture(tmp_path)
    for record in document["controls"].values():
        record.update(state="DEFINED", maturityLevel=1)
    document["assessmentState"] = "DRAFT"
    document["controls"]["GOV-01"]["criteriaResults"]["AC-01"]["status"] = "FAIL"
    document["results"].update(
        assessmentScore=24.75,
        verifiedPoints=24.75,
        assuredControls=0,
        gateVerdict="FAIL",
        productionDecision="NOT_APPROVED",
    )
    for gate in document["gates"].values():
        gate["status"] = "UNKNOWN"
    document["gates"]["G-01"]["status"] = "FAIL"
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert result.verified_points == 24.75, result.errors
    assert result.controls[0].earned_level == 0
    assert result.gates["G-01"] == "FAIL"
    assert not result.complete


def test_future_gate_check_cannot_authorize_a_release(tmp_path):
    document = complete_fixture(tmp_path)
    document["gates"]["G-01"]["checkedAt"] = stamp(1)
    result = evaluate_enterprise(
        save(tmp_path, document), now=NOW, backend=FixtureAuthority(document)
    )
    assert not result.complete and result.verified_points == 0
