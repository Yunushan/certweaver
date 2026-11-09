import json
import runpy
import shutil

import pytest

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-sast.py"))
workflow = runpy.run_path(str(project_root() / "scripts/check-release-workflows.py"))


def fixture_reports():
    raw = {
        "version": "1.181.0",
        "errors": [],
        "paths": {"scanned": ["seed.py"]},
        "results": [
            {
                "check_id": "bandit.B307",
                "path": "seed.py",
                "start": {"line": 2},
                "extra": {"metadata": {"security-severity": "High"}},
            }
        ],
    }
    native = {
        "version": "15.2.4",
        "scan": {
            "status": "success",
            "type": "sast",
            "analyzer": {"id": "semgrep", "version": "6.30.0"},
            "scanner": {"version": "1.181.0"},
        },
        "vulnerabilities": [
            {
                "category": "sast",
                "severity": "High",
                "identifiers": [{"type": "semgrep_id", "value": "bandit.B307"}],
                "location": {"file": "seed.py", "start_line": 2},
            }
        ],
    }
    return raw, native


def test_native_high_finding_is_preserved_even_if_process_succeeds():
    raw, native = fixture_reports()
    assert tools["reports"](raw, native, ["seed.py"]) == [
        {"rule": "bandit.B307", "path": "seed.py", "line": 2, "severity": "High"}
    ]


def test_upstream_uppercase_severity_is_normalized_without_changing_risk():
    raw, native = fixture_reports()
    raw["results"][0]["extra"]["metadata"]["security-severity"] = "MEDIUM"
    native["vulnerabilities"][0]["severity"] = "Medium"
    assert tools["reports"](raw, native, ["seed.py"])[0]["severity"] == "Medium"


@pytest.mark.parametrize(
    "change",
    [
        "omitted-file",
        "extra-file",
        "duplicate-file",
        "scanner-error",
        "wrong-engine",
        "failed-native",
        "wrong-analyzer",
        "wrong-schema",
        "missing-finding",
        "downgrade",
        "wrong-rule",
        "wrong-location",
        "boolean-line",
        "inline-suppression",
        "unknown-severity",
    ],
)
def test_failed_partial_or_inconsistent_reports_cannot_pass(change):
    raw, native = fixture_reports()
    if change == "omitted-file":
        raw["paths"]["scanned"] = []
    elif change == "extra-file":
        raw["paths"]["scanned"].append("other.py")
    elif change == "duplicate-file":
        raw["paths"]["scanned"].append("seed.py")
    elif change == "scanner-error":
        raw["errors"] = [{"type": "Timeout"}]
    elif change == "wrong-engine":
        raw["version"] = "0.0.0"
    elif change == "failed-native":
        native["scan"]["status"] = "failure"
    elif change == "wrong-analyzer":
        native["scan"]["analyzer"]["version"] = "0.0.0"
    elif change == "wrong-schema":
        native["version"] = "0.0.0"
    elif change == "missing-finding":
        native["vulnerabilities"] = []
    elif change == "downgrade":
        native["vulnerabilities"][0]["severity"] = "Medium"
    elif change == "wrong-rule":
        native["vulnerabilities"][0]["identifiers"][0]["value"] = "other"
    elif change == "wrong-location":
        native["vulnerabilities"][0]["location"]["file"] = "../seed.py"
    elif change == "boolean-line":
        native["vulnerabilities"][0]["location"]["start_line"] = True
    elif change == "inline-suppression":
        raw["results"][0]["extra"]["is_ignored"] = True
    else:
        raw["results"][0]["extra"]["metadata"]["security-severity"] = "Unrecognized"
    with pytest.raises(ValueError):
        tools["reports"](raw, native, ["seed.py"])


@pytest.mark.parametrize("payload", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'])
def test_ambiguous_json_is_rejected(tmp_path, payload):
    report = tmp_path / "report.json"
    report.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        tools["document"](report)


def test_scanner_environment_drops_ambient_identity_and_filter_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "SYNTHETIC_DO_NOT_FORWARD")
    monkeypatch.setenv("SAST_EXCLUDED_PATHS", "src,tests")
    monkeypatch.setenv("SAST_SCANNER_ALLOWED_CLI_OPTS", "--config https://example.invalid")
    selected = tools["environment"](tmp_path)
    assert "SEMGREP_APP_TOKEN" not in selected
    assert "SAST_SCANNER_ALLOWED_CLI_OPTS" not in selected
    assert selected["SAST_EXCLUDED_PATHS"] == ""
    assert selected["GITLAB_FEATURES"] == ""
    assert selected["SEMGREP_SEND_METRICS"] == "off"
    assert selected["SCANNER_VERSION"] == tools["VERSION"]


def test_failure_diagnostics_do_not_forward_arbitrary_scanner_messages(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "failed"
    secret = "SYNTHETIC_SCANNER_STDERR_MUST_NOT_ESCAPE"

    def failed(root, destination, commit, *, state):
        destination.mkdir()
        state.update(stage="qualification", ownsOutput=True)
        raise ValueError(secret)

    monkeypatch.setitem(tools["main"].__globals__, "check", failed)
    assert tools["main"](["--commit", "a" * 40, "--output-dir", str(output)]) == 1
    assert secret not in capsys.readouterr().out
    diagnostic = (output / "diagnostics.json").read_text(encoding="utf-8")
    assert secret not in diagnostic
    assert json.loads(diagnostic) == {
        "status": "SAST_FAILED",
        "stage": "qualification",
        "errorType": "ValueError",
    }


@pytest.mark.parametrize(
    "change",
    [
        "removed",
        "mutable-image",
        "conditional",
        "allowed-failure",
        "incoming",
        "bypass-stages",
        "wrong-commit",
        "raw-report",
        "public-report",
        "skip-gate",
        "override-rules",
    ],
)
def test_sast_ci_bypasses_are_rejected(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github/workflows", tmp_path / ".github/workflows")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    (tmp_path / "ci").mkdir()
    shutil.copyfile(
        root / "ci/gitlab-consumer-bootstrap.py", tmp_path / "ci/gitlab-consumer-bootstrap.py"
    )
    assert workflow["check_workflows"](tmp_path) == []
    value = workflow["load"](tmp_path / ".gitlab-ci.yml")
    job = value["python-yaml-sast"]
    if change == "removed":
        del value["python-yaml-sast"]
    elif change == "mutable-image":
        job["image"]["name"] = "registry.gitlab.com/security-products/semgrep:6"
    elif change == "conditional":
        job["rules"] = [{"if": "false"}]
    elif change == "allowed-failure":
        job["allow_failure"] = "true"
    elif change == "incoming":
        job["dependencies"] = ["package"]
    elif change == "bypass-stages":
        job["needs"] = []
    elif change == "wrong-commit":
        job["script"][0] = job["script"][0].replace("$CI_COMMIT_SHA", "main")
    elif change == "raw-report":
        job["artifacts"]["paths"].append(".certweaver/sast/raw.json")
    elif change == "public-report":
        job["artifacts"]["access"] = "all"
    elif change == "skip-gate":
        job["script"] = ["/analyzer run"]
    else:
        job["variables"]["SAST_EXCLUDED_PATHS"] = "src"
    import yaml

    (tmp_path / ".gitlab-ci.yml").write_text(yaml.safe_dump(value), encoding="utf-8")
    assert workflow["check_workflows"](tmp_path)


def test_sast_lock_matches_guarded_image_and_versions():
    policy = json.loads((project_root() / "ci/sast.lock.json").read_text(encoding="utf-8"))
    assert policy["image"] == tools["IMAGE"]
    assert policy["scannerVersion"] == tools["VERSION"]
    assert policy["analyzerVersion"] == tools["ANALYZER_VERSION"]
    assert len(policy["rulesSha256"]) == 27
