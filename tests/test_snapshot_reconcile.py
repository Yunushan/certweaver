from __future__ import annotations

import runpy
import shutil

import pytest
import yaml

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-snapshot-config.py"))


@pytest.mark.parametrize(
    "change",
    [
        "stale-stage",
        "shared-directory",
        "prefix",
        "register",
        "public-directory",
        "late-protection",
        "stage-change",
        "manifest-change",
        "cleanup-change",
        "shared-env",
        "shared-manifest",
        "diff-errors",
        "diff-condition",
        "external-diff",
        "diff-temp",
        "show-secrets",
        "unbounded",
        "apply-always",
        "apply-hidden",
        "early-apply",
        "cleanup-path",
        "cleanup-condition",
        "missing-utility",
    ],
)
def test_snapshot_reconciliation_safety_and_convergence_cannot_be_removed(tmp_path, change):
    root = project_root()
    for directory in [
        "roles/snapshot_config",
        "roles/rke2_server",
        "roles/cluster_addons",
        "roles/common",
        "playbooks",
    ]:
        shutil.copytree(root / directory, tmp_path / directory)
    tools["guard"](tmp_path)
    path = tmp_path / "roles/cluster_addons/tasks/main.yml"
    main = yaml.safe_load(path.read_text(encoding="utf-8"))
    block = next(t for t in main if t["name"] == "Reconcile RKE2 S3 snapshot secret")
    tasks = block["block"]

    def task(prefix):
        return next(t for t in tasks if t["name"].startswith(prefix))

    if change == "stale-stage":
        tasks.pop(0)
    elif change == "shared-directory":
        task("Allocate invocation")["ansible.builtin.tempfile"]["path"] = "/tmp"
    elif change == "prefix":
        task("Allocate invocation")["ansible.builtin.tempfile"]["prefix"] = "shared"
    elif change == "register":
        task("Allocate invocation")["register"] = "other_stage"
    elif change == "public-directory":
        task("Protect invocation")["ansible.builtin.file"]["mode"] = "0755"
    elif change == "late-protection":
        selected = task("Protect invocation")
        tasks.remove(selected)
        tasks.append(selected)
    elif change in {"stage-change", "manifest-change"}:
        task("Stage RKE2" if change == "stage-change" else "Write rendered")["changed_when"] = True
    elif change == "cleanup-change":
        block["always"][0]["changed_when"] = True
    elif change in {"shared-env", "shared-manifest"}:
        task("Stage RKE2" if change == "shared-env" else "Write rendered")["ansible.builtin.copy"][
            "dest"
        ] = "/run/shared"
    elif change == "diff-errors":
        task("Compare RKE2")["failed_when"] = False
    elif change == "diff-condition":
        task("Compare RKE2")["when"] = False
    elif change in {"external-diff", "diff-temp"}:
        task("Compare RKE2")["environment"][
            "KUBECTL_EXTERNAL_DIFF" if change == "external-diff" else "TMPDIR"
        ] = "/tmp/shared"
    elif change in {"show-secrets", "unbounded"}:
        arguments = task("Compare RKE2")["ansible.builtin.command"]["argv"]
        arguments.remove(
            "--show-secrets=false" if change == "show-secrets" else "--request-timeout=30s"
        )
    elif change == "apply-always":
        task("Apply RKE2").pop("when")
    elif change == "apply-hidden":
        task("Apply RKE2")["changed_when"] = False
    elif change == "early-apply":
        selected = task("Apply RKE2")
        tasks.remove(selected)
        tasks.insert(2, selected)
    elif change == "cleanup-path":
        block["always"][0]["ansible.builtin.file"]["path"] = "/run"
    elif change == "cleanup-condition":
        block["always"][0]["when"] = False
    elif change == "missing-utility":
        common = tmp_path / "roles/common/defaults/main.yml"
        document = yaml.safe_load(common.read_text(encoding="utf-8"))
        document["certweaver_common_packages"].remove("diffutils")
        common.write_text(yaml.safe_dump(document), encoding="utf-8")
    path.write_text(yaml.safe_dump(main), encoding="utf-8")
    with pytest.raises((ValueError, KeyError, IndexError, StopIteration)):
        tools["guard"](tmp_path)


@pytest.mark.parametrize("change", ["github-missing", "github-conditional", "gitlab-missing"])
def test_secret_reconciliation_fixture_is_required_in_both_ci_providers(tmp_path, change):
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
        selected = next(s for s in steps if "check-snapshot-reconcile.py" in s.get("run", ""))
        if change == "github-missing":
            steps.remove(selected)
        else:
            selected["if"] = "false"
    else:
        path = tmp_path / ".gitlab-ci.yml"
        document = workflows["load"](path)
        document["lint-test"]["script"] = [
            s for s in document["lint-test"]["script"] if "check-snapshot-reconcile.py" not in s
        ]
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert any("check-snapshot-reconcile.py" in e for e in workflows["check_workflows"](tmp_path))
