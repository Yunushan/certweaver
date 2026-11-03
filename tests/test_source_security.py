import copy
import hashlib
import json
import os
import runpy
import subprocess
from types import SimpleNamespace

import pytest

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-source-security.py"))


def test_lock_matrix_covers_markers_and_keeps_environment_versions_separate():
    inventories = tools["lock_inventories"](project_root())
    assert {value["profile"] for value in inventories.values()} == {"runtime", "build", "dev"}
    for profile in ["runtime", "build", "dev"]:
        targets = [
            target
            for group in inventories.values()
            if group["profile"] == profile
            for target in group["targets"]
        ]
        assert len(targets) == 12
        assert len({(t["python"], t["platform"]) for t in targets}) == 12
    for group in inventories.values():
        if group["profile"] == "dev":
            for target in group["targets"]:
                assert group["packages"]["ansible-core"].startswith(
                    "2.19." if target["python"].startswith("3.11.") else "2.21."
                )
                if target["platform"] == "win32":
                    assert "colorama" in group["packages"]


def test_uncovered_lock_markers_fail_instead_of_dropping_dependencies(tmp_path, monkeypatch):
    lock = tmp_path / "unsupported.lock"
    lock.write_text(
        "supported==1.0 --hash=sha256:" + "a" * 64 + "\n"
        'uncovered==1.0 ; python_version == "3.15" --hash=sha256:' + "b" * 64 + "\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(
        tools["lock_inventories"].__globals__,
        "runpy",
        SimpleNamespace(run_path=lambda path: {"lock_file": lambda root, profile: lock}),
    )
    with pytest.raises(ValueError, match="marker was not covered"):
        tools["lock_inventories"](tmp_path)


def dependency_report(scan):
    inventories = {
        "runtime/fixture/requirements.txt": {"packages": {"example-library": "1.0"}},
        "dev/fixture/requirements.txt": {"packages": {"other-library": "2.0"}},
    }
    report = {
        "SchemaVersion": 2,
        "ArtifactName": str(scan),
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": tools["RESERVED"] + "/" + key,
                "Type": "pip",
                "Packages": [{"Name": k, "Version": v} for k, v in value["packages"].items()],
            }
            for key, value in inventories.items()
        ],
    }
    return inventories, report


@pytest.mark.parametrize(
    "change",
    [
        None,
        "empty",
        "missing-target",
        "missing-package",
        "wrong-version",
        "duplicate-target",
        "duplicate-package",
        "unknown-target",
        "wrong-root",
        "wrong-type",
        "blocking-finding",
        "malformed-findings",
    ],
)
def test_declared_dependency_inventory_requires_complete_matching_scanner_coverage(
    tmp_path, change
):
    inventories, report = dependency_report(tmp_path)
    if change == "empty":
        report["Results"] = []
    elif change == "missing-target":
        report["Results"].pop()
    elif change == "missing-package":
        report["Results"][0]["Packages"] = []
    elif change == "wrong-version":
        report["Results"][0]["Packages"][0]["Version"] = "9.0"
    elif change == "duplicate-target":
        report["Results"].append(copy.deepcopy(report["Results"][0]))
    elif change == "duplicate-package":
        report["Results"][0]["Packages"] *= 2
    elif change == "unknown-target":
        report["Results"][0]["Target"] += ".wrong"
    elif change == "wrong-root":
        report["ArtifactName"] = str(tmp_path / "unrelated")
    elif change == "wrong-type":
        report["ArtifactType"] = "container_image"
    elif change == "blocking-finding":
        report["Results"][0]["Vulnerabilities"] = [{"Severity": "HIGH"}]
    elif change == "malformed-findings":
        report["Results"][0]["Vulnerabilities"] = {}
    if change:
        with pytest.raises(ValueError):
            tools["reconcile"](report, tmp_path, inventories)
    else:
        result = tools["reconcile"](report, tmp_path, inventories)
        assert result == {k: v["packages"] for k, v in inventories.items()}


def test_source_snapshot_checks_raw_git_objects_despite_index_flags(tmp_path):
    source, snapshot = tmp_path / "source", tmp_path / "snapshot"
    source.mkdir()
    snapshot.mkdir()
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull
    )

    def git(*args):
        return subprocess.run(
            ["git", "-c", "core.autocrlf=false", *args],
            cwd=source,
            env=environment,
            capture_output=True,
            check=True,
        ).stdout

    git("init")
    tracked = source / "tracked.txt"
    tracked.write_bytes(b"expected committed source\n")
    git("add", "tracked.txt")
    git(
        "-c",
        "user.name=Source security fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=" + os.devnull,
        "commit",
        "-m",
        "Synthetic source-object fixture",
    )
    commit = git("rev-parse", "HEAD").decode().strip()
    result = tools["materialize_source"](source, snapshot, commit, environment)
    assert result == {"tracked.txt": hashlib.sha256(tracked.read_bytes()).hexdigest()}
    assert (snapshot / "tracked.txt").read_bytes() == tracked.read_bytes()
    git("update-index", "--assume-unchanged", "tracked.txt")
    tracked.write_bytes(b"hidden modification outside expected tree\n")
    assert git("status", "--porcelain").strip() == b""
    with pytest.raises(ValueError, match="Working source bytes differ"):
        tools["materialize_source"](source, snapshot, commit, environment)


def test_derived_failure_diagnostics_exclude_secret_values_and_source_snippets(tmp_path):
    canary = "synthetic-private-match-canary"
    (tmp_path / "declared-dependencies.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": canary,
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-12345",
                                "PkgName": canary,
                                "Description": canary,
                            }
                        ],
                        "Secrets": [{"Match": canary}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    tools["diagnostics"](tmp_path, "SOURCE_SECURITY_FAILED", "ValueError")
    text = (tmp_path / "diagnostics.json").read_text(encoding="utf-8")
    assert canary not in text
    assert json.loads(text)["blockingAdvisoryIds"] == ["CVE-2026-12345"]
    with pytest.raises(FileExistsError):
        tools["diagnostics"](tmp_path, "SOURCE_SECURITY_FAILED")


@pytest.mark.parametrize(
    "stage", [s for s in tools["STAGES"] if s not in {"output-preparation", "complete"}]
)
def test_cli_failure_identifies_fixed_stage_and_never_emits_exception_text(
    tmp_path, monkeypatch, capsys, stage
):
    output = tmp_path / "private-reports"
    canary = "synthetic-private-error-and-match-canary"

    def fail(root, selected, commit, *, state):
        selected.mkdir(mode=0o700)
        state.owns_output = True
        state.enter(stage)
        (selected / "source-secrets.log").write_text(canary, encoding="utf-8")
        raise ValueError(canary)

    monkeypatch.setitem(tools["main"].__globals__, "check", fail)
    assert tools["main"](["--commit", "a" * 40, "--output-dir", str(output)]) == 1
    public = capsys.readouterr().out
    record_text = (output / "diagnostics.json").read_text(encoding="utf-8")
    record = json.loads(record_text)
    assert canary not in public + record_text
    assert stage in public and record["stage"] == stage
    assert record["failureKind"] == "REJECTED_INPUT_OR_POLICY"
    assert record["advisoryExtraction"] == "UNAVAILABLE"
    assert (output / "source-secrets.log").read_text(encoding="utf-8") == canary


@pytest.mark.parametrize(
    "report",
    ["{", "[]", '{"Results":[null]}', '{"Results":[{}]}', '{"Results":[{"Vulnerabilities":{}}]}'],
)
def test_diagnostic_survives_missing_or_malformed_advisory_data(tmp_path, report):
    (tmp_path / "declared-dependencies.json").write_text(report, encoding="utf-8")
    state = tools["RunState"]()
    state.enter("dependency-inventory")
    tools["diagnostics"](
        tmp_path, "SOURCE_SECURITY_FAILED", "ValueError", state=state, exception=ValueError()
    )
    record = json.loads((tmp_path / "diagnostics.json").read_text(encoding="utf-8"))
    assert record["status"] == "SOURCE_SECURITY_FAILED"
    assert record["stage"] == "dependency-inventory" and record["blockingAdvisoryIds"] == []
    assert record["advisoryExtraction"] == (
        "EXTRACTED" if report.endswith("[{}]}") else "UNAVAILABLE"
    )


@pytest.mark.parametrize("failure", [None, "nonzero", "timeout"])
def test_scanner_output_is_retained_for_success_exit_failure_and_timeout(
    tmp_path, monkeypatch, failure
):
    canary = b"synthetic-private-scanner-output"
    label = "source-secrets"
    expected = {"SchemaVersion": 2, "Results": []}

    def execute(arguments, **kwargs):
        assert arguments[1:3] == ["fs", "--disable-telemetry"]
        assert kwargs["capture_output"] and not kwargs["check"]
        assert kwargs["timeout"] == 600
        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, 600, output=canary, stderr=canary)
        (tmp_path / (label + ".json")).write_text(json.dumps(expected), encoding="utf-8")
        return subprocess.CompletedProcess(arguments, 1 if failure else 0, canary, canary)

    monkeypatch.setattr(tools["subprocess"], "run", execute)
    if failure:
        error_type = tools["ScannerExit"] if failure == "nonzero" else subprocess.TimeoutExpired
        with pytest.raises(error_type) as captured:
            tools["run_scan"]("fixture-tool", tmp_path, tmp_path, {}, label, ["fixture-source"])
        state = tools["RunState"]()
        state.enter("secret-scan")
        tools["diagnostics"](
            tmp_path,
            "SOURCE_SECURITY_FAILED",
            type(captured.value).__name__,
            state=state,
            exception=captured.value,
        )
        public = (tmp_path / "diagnostics.json").read_bytes()
        assert canary not in public
        record = json.loads(public)
        assert record["failureKind"] == (
            "SCANNER_NONZERO" if failure == "nonzero" else "PROCESS_TIMEOUT"
        )
        assert record["scannerExitCode"] == (1 if failure == "nonzero" else None)
    else:
        assert (
            tools["run_scan"]("fixture-tool", tmp_path, tmp_path, {}, label, ["fixture-source"])
            == expected
        )
    assert (tmp_path / (label + ".log")).read_bytes() == canary + b"\n" + canary


def test_existing_output_is_not_overwritten_or_used_for_failed_run_diagnostics(tmp_path, capsys):
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "diagnostics.json"
    marker.write_text("previous controlled evidence", encoding="utf-8")
    assert tools["main"](["--commit", "a" * 40, "--output-dir", str(output)]) == 1
    assert "output-preparation" in capsys.readouterr().out
    assert marker.read_text(encoding="utf-8") == "previous controlled evidence"


def test_diagnostic_write_failure_cannot_turn_a_checked_run_green(tmp_path, monkeypatch, capsys):
    canary = "synthetic-private-filesystem-error"

    def checked(root, output, commit, *, state):
        output.mkdir()
        state.owns_output = True
        state.enter("complete")
        return {"status": "SOURCE_SECURITY_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL"}

    def unwritable(*args, **kwargs):
        raise PermissionError(canary)

    monkeypatch.setitem(tools["main"].__globals__, "check", checked)
    monkeypatch.setitem(tools["main"].__globals__, "diagnostics", unwritable)
    assert tools["main"](["--commit", "a" * 40, "--output-dir", str(tmp_path / "reports")]) == 1
    text = capsys.readouterr().out
    assert "diagnostics" in text and canary not in text and "passed source security" not in text
