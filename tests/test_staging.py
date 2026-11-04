"""Synthetic intake fixtures test data inspection, never deployment or real approval."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from certweaver import cli, staging
from certweaver.config import load_config
from certweaver.enterprise import canonical_digest, evaluate_enterprise
from certweaver.errors import ConfigurationError
from certweaver.registry import project_root
from certweaver.render import inventory_from_config


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def packet(tmp_path):
    root = staging.initialize_staging(tmp_path / "packet")
    assessment = json.loads((root / "assessment.json").read_text())
    inputs = json.loads((root / "staging-inputs.json").read_text())
    config = tmp_path / "config.yml"
    config.write_bytes((project_root() / "config/certweaver.example.yml").read_bytes())
    loaded = load_config(config)
    inventory = tmp_path / "inventory.yml"
    rendered = inventory_from_config(loaded)
    inventory.write_text(yaml.safe_dump(rendered), encoding="utf-8")
    subject = assessment["subject"]
    for field, value in subject.items():
        if value is None:
            subject[field] = "fixture-identifier"
        elif isinstance(value, list):
            subject[field] = ["controlled:fixture"]
    subject.update(
        assuranceClaim="PRODUCTION_LAUNCH",
        gitCommit="a" * 40,
        workingTreePatchSha256=None,
        configSha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        selectedAdapters=loaded["spec"]["adapters"]["enabled"],
        declaredExclusions=[],
        releaseArtifacts=[
            {
                "artifactId": "fixture-wheel",
                "kind": "wheel",
                "sha256": "b" * 64,
                "location": "controlled:artifact",
                "provenanceRef": "controlled:provenance",
            }
        ],
    )
    for field in [
        "environmentFingerprint",
        "deploymentResourcesSha256",
        "pipelineDefinitionSha256",
        "packagingDefinitionSha256",
    ]:
        subject[field] = "c" * 64
    for value in assessment["approvedObjectives"].values():
        value.update(
            target="1",
            unitAndWindow="fixture units per 1 hour",
            measurementRef="controlled:method",
            ownerApprovalRef="controlled:objective",
        )
    for value in assessment["conditionalGateDecisions"].values():
        value.update(
            active=False,
            rationale="Synthetic input-lint fixture only",
            reviewApprovalRef="controlled:applicability",
        )
    for value in assessment["controls"].values():
        value.update(
            accountableOwnerRef="actor:owner",
            implementationAuthorRef="actor:maker",
            verifierRef="actor:verifier",
        )
    for group, fields in staging.REFERENCE_GROUPS.items():
        inputs[group] = dict.fromkeys(fields, "controlled:fixture")
    inputs["deployment"].update(
        mode=loaded["spec"]["mode"], renderedInventorySha256=canonical_digest(rendered)
    )
    start = datetime.now(UTC) + timedelta(days=1)
    inputs["execution"].update(
        windowStart=start.isoformat(), windowEnd=(start + timedelta(hours=1)).isoformat()
    )
    for role, value in inputs["authorities"].items():
        value.update(actorRef="actor:" + role, deputyRef="deputy:" + role)
    for value in inputs["controlPlans"].values():
        value.update(independentReviewerRef="actor:reviewer", procedureRef="controlled:procedure")
    save(root / "assessment.json", assessment)
    save(root / "staging-inputs.json", inputs)
    return root, assessment, inputs, config, inventory


def inspect(packet):
    root, assessment, inputs, config, inventory = packet
    save(root / "assessment.json", assessment)
    save(root / "staging-inputs.json", inputs)
    return staging.check_staging(root, config_path=config, inventory_path=inventory)


def test_initialize_contains_the_entire_frozen_contract_and_refuses_overwrite(tmp_path):
    root = staging.initialize_staging(tmp_path / "new")
    assert len(list(root.iterdir())) == 6
    plan = json.loads((root / "control-plan.json").read_text())
    approvals = json.loads((root / "approval-checklist.json").read_text())
    assert len(plan["controls"]) == 100
    assert len(plan["releaseGates"]) == 12
    assert len(approvals["scopePurposesBeforeObservation"]) == 33
    assert len(approvals["reviewPurposesAfterObservation"]) == 418
    assert len(approvals["finalAssurancePurposes"]) == 118
    assert "control:EVD-04:level:4" in approvals["reviewPurposesAfterObservation"]
    if os.name == "posix":
        assert root.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
    original = (root / "assessment.json").read_bytes()
    with pytest.raises(FileExistsError):
        staging.initialize_staging(root)
    assert (root / "assessment.json").read_bytes() == original


def test_blank_package_reports_missing_inputs_without_awarding_authority(tmp_path):
    report = staging.check_staging(staging.initialize_staging(tmp_path / "blank"))
    assert report["status"] == "INPUTS_INCOMPLETE"
    assert report["controlCount"] == 100 and report["objectiveCount"] == 24
    assert report["conditionalDecisionCount"] == 8
    assert not report["executionAuthorized"] and report["enterprisePointsAwarded"] == 0
    assert any(
        i["path"] == "/assessment/approvedObjectives/apiAvailability/target"
        for i in report["issues"]
    )
    assert any(i["path"] == "/inputs/controlPlans/EVD-04/procedureRef" for i in report["issues"])


def test_complete_synthetic_input_never_supplies_execution_or_production_authority(
    packet, monkeypatch
):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline inspection attempted external execution")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    report = inspect(packet)
    assert report["issues"] == []
    assert report["inputsComplete"]
    assert report["status"] == "INPUTS_COMPLETE_AUTHORIZATION_UNVERIFIED"
    assert report["executionAuthorized"] is False
    assert report["productionDecision"] == "NOT_APPROVED"
    score = evaluate_enterprise(packet[0] / "assessment.json")
    assert score.verified_points == 0 and not score.complete


@pytest.mark.parametrize(
    "change",
    [
        "missing-control",
        "extra-control",
        "unknown-field",
        "bad-type",
        "missing-objective",
        "wrong-catalogue",
        "missing-assignment",
    ],
)
def test_incomplete_and_changed_structure_is_rejected(packet, change):
    _, assessment, inputs, _, _ = packet
    if change == "missing-control":
        del assessment["controls"]["PKI-01"]
    elif change == "extra-control":
        assessment["controls"]["FAKE-01"] = assessment["controls"]["PKI-01"]
    elif change == "unknown-field":
        inputs["execution"]["trustAll"] = True
    elif change == "bad-type":
        inputs["access"]["secretSystemRef"] = {"PRIVATE-MARKER": "do not echo"}
    elif change == "missing-objective":
        del assessment["approvedObjectives"]["recoveryTimeObjective"]
    elif change == "wrong-catalogue":
        inputs["catalogueSha256"] = "d" * 64
    else:
        del inputs["controlPlans"]["GOV-01"]
    report = inspect(packet)
    assert not report["inputsComplete"]
    assert "PRIVATE-MARKER" not in json.dumps(report)


@pytest.mark.parametrize(
    "change",
    [
        "unset",
        "placeholder",
        "no-number",
        "same-reviewer",
        "same-deputy",
        "undecided",
        "changed-criterion",
        "working-patch",
        "bad-window",
        "no-zone",
        "past-window",
        "missing-provenance",
    ],
)
def test_inconsistent_planning_inputs_are_blocked(packet, change):
    _, assessment, inputs, _, _ = packet
    if change == "unset":
        inputs["access"]["transportAccessRef"] = None
    elif change == "placeholder":
        inputs["access"]["secretSystemRef"] = "TODO"
    elif change == "no-number":
        assessment["approvedObjectives"]["apiAvailability"]["target"] = "excellent"
    elif change == "same-reviewer":
        inputs["controlPlans"]["GOV-01"]["independentReviewerRef"] = "actor:maker"
    elif change == "same-deputy":
        record = inputs["authorities"]["securityOwner"]
        record["deputyRef"] = record["actorRef"]
    elif change == "undecided":
        assessment["conditionalGateDecisions"]["SEC-11"]["active"] = None
    elif change == "changed-criterion":
        assessment["controls"]["DR-01"]["criteriaResults"]["AC-01"]["criterion"] = "Skip restore"
    elif change == "working-patch":
        assessment["subject"]["workingTreePatchSha256"] = "c" * 64
    elif change == "bad-window":
        inputs["execution"]["windowEnd"] = inputs["execution"]["windowStart"]
    elif change == "no-zone":
        inputs["execution"]["windowEnd"] = "2050-01-01T12:00:00"
    elif change == "past-window":
        inputs["execution"].update(
            windowStart="2000-01-01T00:00:00Z", windowEnd="2000-01-02T00:00:00Z"
        )
    else:
        assessment["subject"]["releaseArtifacts"][0]["provenanceRef"] = None
    assert not inspect(packet)["inputsComplete"]


@pytest.mark.parametrize(
    "change",
    [
        "config",
        "inventory",
        "mode",
        "adapter",
        "missing-config",
        "invalid-config",
        "invalid-inventory",
        "config-too-large",
    ],
)
def test_explicit_local_targets_and_subject_are_bound(packet, change, monkeypatch):
    _, assessment, inputs, config, inventory = packet
    if change == "config":
        assessment["subject"]["configSha256"] = "f" * 64
    elif change == "inventory":
        value = yaml.safe_load(inventory.read_text())
        value["all"]["vars"]["unexpected"] = "changed"
        inventory.write_text(yaml.safe_dump(value))
    elif change == "mode":
        inputs["deployment"]["mode"] = "standalone"
    elif change == "adapter":
        assessment["subject"]["selectedAdapters"] = ["step-ca"]
    elif change == "missing-config":
        config.unlink()
    elif change == "invalid-config":
        config.write_text("spec: {mode: invalid}")
    elif change == "invalid-inventory":
        inventory.write_text("[invalid")
    else:
        original = staging._check_config

        def bounded(*args):
            monkeypatch.setattr(staging, "MAX_DOCUMENT_BYTES", 10)
            return original(*args)

        monkeypatch.setattr(staging, "_check_config", bounded)
    assert not inspect(packet)["inputsComplete"]


@pytest.mark.parametrize("body", ['{"x":1,"x":2}', '{"x":NaN}', "[]", "{broken"])
def test_malformed_json_is_rejected_without_payload_disclosure(tmp_path, body):
    path = tmp_path / "private.json"
    path.write_text(body)
    with pytest.raises(ConfigurationError, match="Cannot read staging package JSON"):
        staging._read(path)


def test_input_binding_changes_with_target_but_not_approval_locator(packet):
    first = inspect(packet)
    packet[2]["execution"]["authorizationRef"] = "controlled:new-locator"
    second = inspect(packet)
    assert first["inputPackageSha256"] == second["inputPackageSha256"]
    packet[2]["topology"]["backupTargetRef"] = "controlled:different-target"
    assert second["inputPackageSha256"] != inspect(packet)["inputPackageSha256"]


def test_emitted_schema_cannot_weaken_installed_validation(packet):
    save(packet[0] / "staging-inputs.schema.json", {})
    packet[2]["trustAll"] = True
    assert not inspect(packet)["inputsComplete"]


def test_assessment_cannot_select_a_different_catalogue(packet):
    packet[1]["catalogueSha256"] = "f" * 64
    assert not inspect(packet)["inputsComplete"]


def test_criterion_key_order_does_not_change_semantic_binding(packet):
    control = packet[1]["controls"]["GOV-01"]
    control["criteriaResults"] = dict(reversed(list(control["criteriaResults"].items())))
    assert inspect(packet)["inputsComplete"]


@pytest.mark.parametrize("body", ["[]", "[broken", "spec: {mode: invalid}"])
def test_bad_configuration_contents_are_reported_without_echo(packet, body):
    packet[3].write_text(body)
    assert not inspect(packet)["inputsComplete"]


@pytest.mark.parametrize("body", ["[]", "x" * 100])
def test_nonmapping_and_oversized_inventory_are_blocked(packet, body, monkeypatch):
    packet[4].write_text(body)
    original = staging._check_inventory

    def bounded(*args):
        monkeypatch.setattr(staging, "MAX_DOCUMENT_BYTES", 20)
        return original(*args)

    monkeypatch.setattr(staging, "_check_inventory", bounded)
    assert not inspect(packet)["inputsComplete"]


def test_json_size_limit_and_invalid_packaged_template_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "oversized.json"
    path.write_text('{"value":"' + "x" * 100 + '"}')
    monkeypatch.setattr(staging, "MAX_DOCUMENT_BYTES", 20)
    with pytest.raises(ConfigurationError):
        staging._read(path)
    target = tmp_path / "docs/readiness"
    target.mkdir(parents=True)
    (target / "enterprise-assessment.template.json").write_text("{}")
    monkeypatch.setattr(staging, "project_root", lambda: tmp_path)
    with pytest.raises(ConfigurationError, match="Packaged assessment template"):
        staging._template()


def test_cli_exit_codes_and_private_value_redaction(packet, capsys):
    root, _, inputs, config, inventory = packet
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "staging-check",
            str(root),
            "--config",
            str(config),
            "--inventory",
            str(inventory),
            "--json",
        ]
    )
    assert args.func(args) == 0
    assert not json.loads(capsys.readouterr().out)["executionAuthorized"]
    inputs["access"]["kubeconfigRef"] = None
    inspect(packet)
    args.json = False
    assert args.func(args) == 2
    assert "/inputs/access/kubeconfigRef" in capsys.readouterr().out
