from __future__ import annotations

import runpy
import shutil

import pytest
import yaml

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-managed-strategy.py"))
POSITIONS = [
    (name, index)
    for name in tools["MANAGED_PLAYBOOKS"]
    for index, _ in enumerate(tools["load"](project_root() / f"playbooks/{name}.yml"))
]


def test_all_managed_plays_pin_the_builtin_strategy_and_fatal_failure_policy():
    tools["guard"](project_root())


@pytest.mark.parametrize("filename,index", POSITIONS)
@pytest.mark.parametrize("change", ["missing", "free"])
def test_no_managed_phase_can_inherit_or_select_nonfatal_scheduling(
    tmp_path, filename, index, change
):
    shutil.copytree(project_root() / "playbooks", tmp_path / "playbooks")
    tools["guard"](tmp_path)
    path = tmp_path / f"playbooks/{filename}.yml"
    plays = tools["load"](path)
    if change == "missing":
        del plays[index]["strategy"]
    else:
        plays[index]["strategy"] = "free"
    path.write_text(yaml.safe_dump(plays), encoding="utf-8")
    with pytest.raises(ValueError, match="built-in linear strategy"):
        tools["guard"](tmp_path)


@pytest.mark.parametrize("strategy", ["linear", "{{ requested_strategy }}"])
def test_strategy_is_literal_and_uses_the_builtin_namespace(tmp_path, strategy):
    shutil.copytree(project_root() / "playbooks", tmp_path / "playbooks")
    path = tmp_path / "playbooks/rke2-ha.yml"
    plays = tools["load"](path)
    plays[0]["strategy"] = strategy
    path.write_text(yaml.safe_dump(plays), encoding="utf-8")
    with pytest.raises(ValueError, match="built-in linear strategy"):
        tools["guard"](tmp_path)


@pytest.mark.parametrize("change", ["github-missing", "github-conditional", "gitlab-missing"])
def test_managed_strategy_execution_is_required_in_both_ci_providers(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github", tmp_path / ".github")
    shutil.copytree(root / "ci", tmp_path / "ci")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    workflows = runpy.run_path(str(root / "scripts/check-release-workflows.py"))
    assert workflows["check_workflows"](tmp_path) == []
    if change.startswith("github"):
        path = tmp_path / ".github/workflows/ci.yml"
        document = workflows["load"](path)
        steps = document["jobs"]["test"]["steps"]
        selected = next(s for s in steps if "check-managed-strategy.py" in s.get("run", ""))
        if change == "github-missing":
            steps.remove(selected)
        else:
            selected["if"] = "false"
    else:
        path = tmp_path / ".gitlab-ci.yml"
        document = workflows["load"](path)
        document["lint-test"]["script"] = [
            s for s in document["lint-test"]["script"] if "check-managed-strategy.py" not in s
        ]
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert any("check-managed-strategy.py" in e for e in workflows["check_workflows"](tmp_path))
