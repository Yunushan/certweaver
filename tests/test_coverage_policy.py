from __future__ import annotations

import json
import runpy

import pytest

from certweaver.registry import project_root

check_coverage = runpy.run_path(str(project_root() / "scripts/check-coverage.py"))["check_coverage"]


@pytest.mark.parametrize(
    "lines,branches,ok",
    [
        ((90, 100), (85, 100), True),
        ((1134, 1231), (501, 590), False),  # 84.915% must not be rounded up to 85%.
        ((89, 100), (100, 100), False),
        ((100, 100), (84, 100), False),
        ((0, 0), (0, 0), False),
        ((True, 1), (85, 100), False),
        ((100, 90), (85, 100), False),
    ],
)
def test_coverage_floor_boundaries(tmp_path, lines, branches, ok):
    path = tmp_path / "coverage.json"
    path.write_text(
        json.dumps(
            {
                "meta": {"branch_coverage": True},
                "totals": {
                    "covered_lines": lines[0],
                    "num_statements": lines[1],
                    "covered_branches": branches[0],
                    "num_branches": branches[1],
                },
            }
        ),
        encoding="utf-8",
    )
    assert (not check_coverage(path)) == ok


def test_missing_or_unmeasured_branch_report_fails(tmp_path):
    path = tmp_path / "coverage.json"
    assert check_coverage(path)
    path.write_text('{"meta":{"branch_coverage":false}}', encoding="utf-8")
    assert check_coverage(path) == ["Branch coverage was not measured"]
