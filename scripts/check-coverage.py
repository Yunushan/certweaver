"""Enforce enterprise TST-01 line/branch floors without rounding upward."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def check_coverage(path: Path) -> list[str]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        if not report["meta"]["branch_coverage"]:
            return ["Branch coverage was not measured"]
        totals = report["totals"]
        errors = []
        for label, covered_key, total_key, floor in (
            ("Line", "covered_lines", "num_statements", 90),
            ("Branch", "covered_branches", "num_branches", 85),
        ):
            covered, total = totals[covered_key], totals[total_key]
            if (
                type(covered) is not int
                or type(total) is not int
                or not 0 <= covered <= total
                or total == 0
            ):
                errors.append(f"{label} coverage has invalid/empty counts")
            elif covered * 100 < floor * total:
                errors.append(
                    f"{label} coverage {covered}/{total} ({covered / total:.4%}) is below {floor}%"
                )
        return errors
    except (OSError, ValueError, KeyError, TypeError):
        return ["Coverage JSON is missing or invalid"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, nargs="?", default=Path(".certweaver/coverage.json"))
    errors = check_coverage(parser.parse_args().report)
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("Enterprise coverage policy passed: line >=90%, branch >=85% (unrounded)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
