from __future__ import annotations

import hashlib
import json
import runpy
import shutil

import pytest
import yaml

from certweaver.registry import project_root

health = runpy.run_path(str(project_root() / "scripts/check-cluster-health.py"))


def test_managed_cluster_health_callers_are_mandatory():
    health["guard"](project_root())


@pytest.mark.parametrize(
    "change",
    [
        "rke2-removed",
        "k3s-skipped",
        "ignore-failure",
        "wrong-role",
        "preflight-removed",
        "preflight-one-node",
        "preflight-target-version",
        "not-serial",
        "continue-upgrade",
        "continue-bootstrap",
        "rke2-runtime-removed",
        "k3s-runtime-skipped",
        "runtime-phase-selected",
        "runtime-condition-bypassed",
        "runtime-errors-ignored",
        "deploy-preflight-removed",
        "deploy-bootstrap-only",
        "deploy-preflight-skipped",
        "deploy-preflight-selected",
        "rolling-parallel",
        "rolling-wrong-group",
        "rolling-server-first",
        "rolling-prepare-separate",
        "rolling-pre-version-removed",
        "rolling-pre-version-optional",
        "rolling-pre-health-removed",
        "rolling-pre-health-optional",
        "rolling-pre-health-selected",
        "rolling-ignore-unreachable",
        "rolling-force-handlers",
        "rolling-k3s-parallel",
        "flush-removed",
        "notify-after-flush",
    ],
)
def test_health_guard_rejects_fail_open_deployment_changes(tmp_path, change):
    root = project_root()
    for directory in ["roles/rke2_server/tasks", "roles/k3s_server/tasks", "playbooks"]:
        shutil.copytree(root / directory, tmp_path / directory)
    health["guard"](tmp_path)
    path = tmp_path / "roles/rke2_server/tasks/main.yml"
    if change in {"k3s-skipped", "k3s-runtime-skipped"}:
        path = tmp_path / "roles/k3s_server/tasks/main.yml"
    if change.startswith("preflight-") or change in {"not-serial", "continue-upgrade"}:
        path = tmp_path / "playbooks/upgrade.yml"
    if change == "continue-bootstrap":
        path = tmp_path / "playbooks/rke2-ha.yml"
    if change.startswith("deploy-"):
        path = tmp_path / "playbooks/rke2-ha.yml"
    if change.startswith("rolling-"):
        path = (
            tmp_path
            / "playbooks"
            / ("k3s-ha.yml" if change == "rolling-k3s-parallel" else "rke2-ha.yml")
        )
    document = yaml.safe_load(path.read_text())
    if change == "rke2-removed":
        document.pop()
    elif change == "k3s-skipped":
        document[-1]["when"] = False
    elif change == "ignore-failure":
        document[-1]["ignore_errors"] = True
    elif change == "wrong-role":
        document[-1]["ansible.builtin.include_role"]["name"] = "common"
    elif change == "preflight-removed":
        document.pop(1)
    elif change == "preflight-one-node":
        document[1]["hosts"] = "cluster_bootstrap"
    elif change == "preflight-target-version":
        document[1]["roles"][0]["vars"]["certweaver_cluster_health_phase"] = "post-reconcile"
    elif change == "not-serial":
        document[2]["serial"] = 3
    elif change == "rke2-runtime-removed":
        document.pop(1)
    elif change == "k3s-runtime-skipped":
        document[1]["when"] = False
    elif change == "runtime-phase-selected":
        document[1]["vars"]["certweaver_cluster_health_phase"] = "post-reconcile"
    elif change == "runtime-condition-bypassed":
        document[1]["when"] = False
    elif change == "runtime-errors-ignored":
        document[1]["ignore_errors"] = True
    elif change == "deploy-preflight-removed":
        document.pop(1)
    elif change == "deploy-bootstrap-only":
        document[1]["hosts"] = "cluster_bootstrap"
    elif change == "deploy-preflight-skipped":
        document[1]["roles"][0]["when"] = False
    elif change == "deploy-preflight-selected":
        document[1]["roles"][0]["vars"]["certweaver_cluster_health_phase"] = "post-reconcile"
    elif change in {"rolling-parallel", "rolling-k3s-parallel"}:
        document[3]["serial"] = 2
    elif change == "rolling-wrong-group":
        document[2]["hosts"] = "cluster_servers"
    elif change == "rolling-server-first":
        document[2]["roles"].insert(0, document[2]["roles"].pop())
    elif change == "rolling-prepare-separate":
        document.insert(
            2, {"hosts": "cluster_servers", "any_errors_fatal": True, "roles": [{"role": "common"}]}
        )
    elif change == "rolling-pre-version-removed":
        document[2]["pre_tasks"].pop(0)
    elif change == "rolling-pre-version-optional":
        document[2]["pre_tasks"][0]["when"] = False
    elif change == "rolling-pre-health-removed":
        document[2]["pre_tasks"].pop()
    elif change == "rolling-pre-health-optional":
        document[2]["pre_tasks"][1]["when"] = False
    elif change == "rolling-pre-health-selected":
        document[2]["pre_tasks"][1]["vars"]["certweaver_cluster_health_phase"] = "post-reconcile"
    elif change == "rolling-ignore-unreachable":
        document[2]["ignore_unreachable"] = True
    elif change == "rolling-force-handlers":
        document[2]["force_handlers"] = True
    elif change == "flush-removed":
        document[:] = [t for t in document if t.get("ansible.builtin.meta") != "flush_handlers"]
    elif change == "notify-after-flush":
        document[-2]["notify"] = "Restart RKE2"
    else:
        document[0].pop("any_errors_fatal")
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ValueError):
        health["guard"](tmp_path)


@pytest.mark.parametrize("change", ["good", "digest", "source", "platform", "symlink"])
def test_fixture_client_is_verified_before_execution(tmp_path, change):
    (tmp_path / "ci").mkdir()
    content = b"synthetic client is never executed in this unit test"
    source = tmp_path / "source"
    source.write_bytes(content)
    record = {
        "version": "v1.36.5",
        "platform": "linux-amd64",
        "url": "https://dl.k8s.io/release/v1.36.5/bin/linux/amd64/kubectl",
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    if change == "digest":
        record["sha256"] = "0" * 64
    elif change == "source":
        record["url"] = "https://example.invalid/kubectl"
    elif change == "platform":
        record["platform"] = "linux-arm64"
    elif change == "symlink":
        source = tmp_path / "link"
        try:
            source.symlink_to(tmp_path / "source")
        except OSError:
            pytest.skip("Creating symlinks requires permission on this host")
    (tmp_path / "ci/cluster-health-client.lock.json").write_text(json.dumps(record))
    target = tmp_path / "target"
    if change == "good":
        health["acquire_client"](tmp_path, target, source)
        assert target.read_bytes() == content
    else:
        with pytest.raises(ValueError):
            health["acquire_client"](tmp_path, target, source)
        assert not target.exists()


def test_health_profiles_use_distribution_client_and_protected_kubeconfig():
    defaults = yaml.safe_load(
        (project_root() / "roles/cluster_health/defaults/main.yml").read_text()
    )
    assert defaults["certweaver_cluster_health_profiles"] == {
        "rke2-ha": {
            "argv": ["/var/lib/rancher/rke2/bin/kubectl"],
            "kubeconfig": "/etc/rancher/rke2/rke2.yaml",
        },
        "k3s-ha": {
            "argv": ["/usr/local/bin/k3s", "kubectl"],
            "kubeconfig": "/etc/rancher/k3s/k3s.yaml",
        },
    }
    assert defaults["certweaver_cluster_health_phase"] == "post-reconcile"
