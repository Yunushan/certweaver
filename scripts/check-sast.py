"""Qualify pinned GitLab SAST and gate exact committed Python/YAML source.

Scanner exit zero is not a finding disposition. Keep original reports private;
only the native GitLab report and bounded derived result are CI artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import subprocess
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath

IMAGE = (
    "registry.gitlab.com/security-products/semgrep:6.30.0@sha256:"
    "c412f7fa397fb934a2862c7156c88384c202e913873528ef6a2785786fd57e44"
)
VERSION = "1.181.0"
ANALYZER_VERSION = "6.30.0"
SEVERITIES = {"Info", "Unknown", "Low", "Medium", "High", "Critical"}
ALIASES = {
    "roles/pki_adapter/files/verify-git-checkout": "certweaver_sast_helpers/git_checkout.py",
    "roles/cluster_addons/files/protect-kubeconfig": "certweaver_sast_helpers/kubeconfig.py",
}
MAX_REPORT = 64 * 1024 * 1024
STAGES = {"output", "policy", "qualification", "source", "scan", "integrity", "result", "complete"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "Duplicate report key")
        value[key] = item
    return value


def document(path):
    require(not path.is_symlink() and path.is_file(), "Missing regular scan report")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT + 1)
    require(0 < len(raw) <= MAX_REPORT, "Unbounded scan report")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    require(type(value) is dict, "Scan report must be an object")
    return value


def reject_constant(value):
    raise ValueError("Non-finite report value")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_name(value):
    require(isinstance(value, str), "Invalid scan path")
    path = PurePosixPath(value)
    require(
        path.parts
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in value
        and ":" not in value
        and str(path) == value,
        "Unsafe scan path",
    )
    return value


def reports(raw, native, expected):
    """Require complete explicit coverage and agreement between both scanner views."""
    require(
        raw.get("version") == VERSION
        and raw.get("errors") == []
        and isinstance(raw.get("results"), list)
        and type(raw.get("paths")) is dict
        and isinstance(raw["paths"].get("scanned"), list),
        "Scanner failed, omitted coverage or changed identity",
    )
    paths = [safe_name(p) for p in raw["paths"]["scanned"]]
    require(
        len(paths) == len(set(paths)) and set(paths) == set(expected),
        "Scanner omitted or added a required source target",
    )
    scan = native.get("scan", {})
    require(
        native.get("version") == "15.2.4"
        and isinstance(native.get("vulnerabilities"), list)
        and scan.get("status") == "success"
        and scan.get("type") == "sast"
        and scan.get("analyzer", {}).get("id") == "semgrep"
        and scan.get("analyzer", {}).get("version") == ANALYZER_VERSION
        and scan.get("scanner", {}).get("version") == VERSION,
        "Native GitLab scan failed or changed identity/schema",
    )
    expected_findings = []
    for finding in raw["results"]:
        require(
            type(finding) is dict and type(finding.get("extra")) is dict,
            "Malformed scanner finding",
        )
        extra = finding["extra"]
        severity = extra.get("metadata", {}).get("security-severity")
        severity = severity.capitalize() if isinstance(severity, str) else severity
        identity = finding.get("check_id")
        path = safe_name(finding.get("path"))
        line = finding.get("start", {}).get("line")
        require(
            severity in SEVERITIES
            and isinstance(identity, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", identity)
            and path in expected
            and type(line) is int
            and line > 0
            and extra.get("is_ignored", False) is False,
            "Unclassified, ignored or out-of-scope scanner finding",
        )
        expected_findings.append((identity, path, line, severity))
    observed = []
    for finding in native["vulnerabilities"]:
        require(
            type(finding) is dict and isinstance(finding.get("identifiers"), list),
            "Malformed native GitLab finding",
        )
        ids = [
            v.get("value")
            for v in finding["identifiers"]
            if type(v) is dict and v.get("type") == "semgrep_id"
        ]
        require(
            len(ids) == 1 and finding.get("category") == "sast",
            "Missing unique native rule identity",
        )
        location = finding.get("location", {})
        require(
            type(location) is dict and type(location.get("start_line")) is int,
            "Invalid native source location",
        )
        observed.append(
            (
                ids[0],
                safe_name(location.get("file")),
                location.get("start_line"),
                finding.get("severity"),
            )
        )
    require(
        Counter(observed) == Counter(expected_findings),
        "Native report omitted, suppressed or changed a finding",
    )
    return [
        {"rule": rule, "path": path, "line": line, "severity": severity}
        for rule, path, line, severity in sorted(expected_findings)
    ]


def environment(work):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(work),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "CI_PROJECT_DIR": str(work),
        "ANALYZER_TARGET_DIR": str(work),
        "SEARCH_MAX_DEPTH": "32",
        "SAST_EXCLUDED_PATHS": "",
        "SAST_SEMGREP_EXCLUDED_PATHS": "",
        "SAST_SEMGREP_METRICS": "false",
        "SECURE_LOG_LEVEL": "error",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SCANNER_VERSION": VERSION,
        "GITLAB_FEATURES": "",
    }


def analyze(work, targets, *, retained=None):
    env = environment(work)
    # No registry fetch, repository ruleset, plugin, autofix, build or baseline.
    commands = [
        [
            "semgrep",
            "scan",
            "--config",
            "/rules",
            "--json",
            "--output",
            "raw.json",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--strict",
            "--metrics",
            "off",
            "--disable-version-check",
            "--jobs",
            "2",
            "--",
            *targets,
        ],
        ["/analyzer", "run"],
    ]
    for command in commands:
        result = subprocess.run(
            command, cwd=work, env=env, capture_output=True, check=False, timeout=600
        )
        require(result.returncode == 0, "SAST process failed")
    if retained is not None:
        retained.mkdir(mode=0o700, exist_ok=True)
        for name in ("raw.json", "gl-sast-report.json"):
            with (retained / name).open("xb") as stream:
                stream.write((work / name).read_bytes())
    return reports(document(work / "raw.json"), document(work / "gl-sast-report.json"), targets)


def qualify(parent, retained=None):
    outcomes = {}
    for label, text in {
        "clean": "def greet(name):\n    return 'Hello ' + name\n",
        "seeded": "def unsafe(expression):\n    return eval(expression)\n",
    }.items():
        work = parent / label
        work.mkdir(mode=0o700)
        (work / "fixture.py").write_text(text, encoding="utf-8")
        findings = analyze(
            work,
            ["fixture.py"],
            retained=retained / ("qualification-" + label) if retained else None,
        )
        if label == "clean":
            require(findings == [], "Clean SAST qualification failed")
        else:
            require(
                findings
                == [{"rule": "bandit.B307", "path": "fixture.py", "line": 2, "severity": "High"}],
                "Seeded high-severity SAST qualification failed",
            )
        outcomes[label] = {
            "findings": len(findings),
            "blocking": sum(f["severity"] in {"High", "Critical"} for f in findings),
        }
    return outcomes


def check(root, output, commit, *, state=None):
    state = state if state is not None else {}
    state.update(stage="output", ownsOutput=False)
    require(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit), "Immutable commit required")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    state.update(stage="policy", ownsOutput=True)
    source = runpy.run_path(str(root / "scripts/check-source-security.py"))
    policy = document(root / "ci/sast.lock.json")
    require(
        policy["image"] == IMAGE and policy["scannerVersion"] == VERSION,
        "Changed SAST policy identity",
    )
    actual_rules = {
        p.relative_to("/rules").as_posix(): digest(p)
        for p in sorted(Path("/rules").rglob("*"))
        if p.is_file()
    }
    require(actual_rules and actual_rules == policy["rulesSha256"], "Changed SAST rules")
    with tempfile.TemporaryDirectory(prefix="certweaver-sast-") as temporary:
        parent = Path(temporary)
        state["stage"] = "qualification"
        qualification = qualify(parent, output)
        work = parent / "source"
        work.mkdir(mode=0o700)
        state["stage"] = "source"
        source_hashes = source["materialize_source"](root, work, commit, environment(parent))
        require(
            not any(name.startswith("certweaver_sast_helpers/") for name in source_hashes),
            "Reserved SAST helper namespace",
        )
        targets = sorted(
            name for name in source_hashes if Path(name).suffix.lower() in {".py", ".yml", ".yaml"}
        )
        for original, alias in ALIASES.items():
            require(original in source_hashes, "Missing extensionless Python helper")
            target = work / alias
            target.parent.mkdir(mode=0o700, exist_ok=True)
            target.write_bytes((work / original).read_bytes())
            targets.append(alias)
        targets.sort()
        require(targets, "Empty SAST scope")
        state["stage"] = "scan"
        findings = analyze(work, targets, retained=output)
        state["stage"] = "integrity"
        require(
            all(digest(work / name) == expected for name, expected in source_hashes.items()),
            "Scanner changed committed source",
        )
        report = work / "gl-sast-report.json"
        state["stage"] = "result"
        blocking = [f for f in findings if f["severity"] in {"High", "Critical"}]
        result = {
            "status": "SAST_BLOCKED" if blocking else "SAST_PASSED_NOT_PRODUCTION_APPROVAL",
            "sourceCommit": commit,
            "image": IMAGE,
            "scannerVersion": VERSION,
            "scope": "Committed Python/YAML including tests and two aliased Python helpers; "
            "not complete language coverage, dependency review or production approval",
            "sourceSha256": source_hashes,
            "scannedTargets": targets,
            "qualification": qualification,
            "findings": findings,
            "blockingFindings": len(blocking),
            "nativeReportSha256": digest(report),
            "rawReportSha256": digest(work / "raw.json"),
            "rulesSha256": actual_rules,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        state["stage"] = "complete"
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    state = {"stage": "output", "ownsOutput": False}
    try:
        result = check(
            Path(__file__).resolve().parents[1],
            args.output_dir.absolute(),
            args.commit,
            state=state,
        )
        print("SAST completed; blocking findings: " + str(result["blockingFindings"]))
        return 1 if result["blockingFindings"] else 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.SubprocessError,
    ) as exc:
        stage = state["stage"] if state["stage"] in STAGES else "UNKNOWN"
        if state["ownsOutput"]:
            diagnostic = {"status": "SAST_FAILED", "stage": stage, "errorType": type(exc).__name__}
            try:
                with (args.output_dir / "diagnostics.json").open("x", encoding="utf-8") as stream:
                    json.dump(diagnostic, stream, indent=2)
            except OSError:
                pass
        print("ERROR: SAST failed at stage " + stage)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
