from __future__ import annotations

import json
import runpy
import subprocess
from pathlib import Path

import pytest

from certweaver.registry import project_root

scanner = runpy.run_path(str(project_root() / "scripts/check-secret-scanner.py"))


def fixture_runner(mode, observed):
    def run(command, **kwargs):
        target = Path(command[-1])
        observed.append(target)
        if mode == "timeout":
            raise subprocess.TimeoutExpired(command, 90)
        if mode == "unavailable":
            raise FileNotFoundError("fixture scanner unavailable")
        clean = target.name == "clean"
        paths = (
            []
            if clean
            else [
                str(p.relative_to(target))
                for p in target.rglob("fixture.*")
                if p.name in {"fixture.pem", "fixture.md"}
            ]
        )
        assert len(paths) == (0 if clean else 6)
        report = {
            "Results": [{"Target": path, "Secrets": [{"RuleID": "private-key"}]} for path in paths]
        }
        code = 0 if clean else 1
        if mode == "always-clean":
            report, code = {}, 0
        elif mode == "always-fails":
            code = 1
        elif mode == "error-code":
            code = 2
        elif mode == "partial" and not clean:
            report["Results"].pop()
        elif mode == "wrong-target" and not clean:
            report["Results"][0]["Target"] = "wrong.pem"
        elif mode == "duplicate-target" and not clean:
            report["Results"][0] = report["Results"][1]
        elif mode == "invalid-shape":
            report = []
        output = Path(command[command.index("--output") + 1])
        if mode != "missing-report":
            output.write_text(
                "bad json" if mode == "bad-json" else json.dumps(report), encoding="utf-8"
            )
        return subprocess.CompletedProcess(command, code, b"", b"not shown")

    return run


def test_scanner_qualification_requires_clean_and_all_three_archive_detections(monkeypatch):
    observed = []
    monkeypatch.setattr(subprocess, "run", fixture_runner("valid", observed))
    result = scanner["qualify_scanner"]("fixture-trivy")
    assert result["status"] == "SCANNER_QUALIFIED_WITH_SYNTHETIC_FIXTURES"
    assert [o["secretFindings"] for o in result["observations"]] == [0, 6]
    assert all(not path.exists() for path in observed)


@pytest.mark.parametrize(
    "mode",
    [
        "always-clean",
        "always-fails",
        "error-code",
        "partial",
        "wrong-target",
        "duplicate-target",
        "invalid-shape",
        "missing-report",
        "bad-json",
        "timeout",
        "unavailable",
    ],
)
def test_broken_scanner_does_not_qualify_and_fixtures_are_removed(monkeypatch, mode):
    observed = []
    monkeypatch.setattr(subprocess, "run", fixture_runner(mode, observed))
    with pytest.raises((ValueError, OSError, subprocess.TimeoutExpired)):
        scanner["qualify_scanner"]("fixture-trivy")
    assert all(not path.exists() for path in observed)
