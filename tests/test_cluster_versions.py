from __future__ import annotations

import runpy
import shutil

import pytest
import yaml

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root

versions = runpy.run_path(str(project_root() / "scripts/check-cluster-versions.py"))


def configuration(product):
    filename = (
        "config/certweaver.example.yml" if product == "rke2" else "examples/configs/k3s-ha.yml"
    )
    return load_config(project_root() / filename)


@pytest.mark.parametrize("product,suffix", [("rke2", "rke2r"), ("k3s", "k3s")])
@pytest.mark.parametrize("release", ["1.33.12", "1.34.0", "1.9.10"])
def test_selected_distribution_versions_are_literal_and_canonical(product, suffix, release):
    config = configuration(product)
    config["spec"]["versions"][product] = f"v{release}+{suffix}10"
    assert validate_config(config).ok


@pytest.mark.parametrize("product", ["rke2", "k3s"])
@pytest.mark.parametrize(
    "value",
    [
        "stable",
        "1.33.12",
        "v1.33",
        "v1.34.0-rc1+rke2r1",
        "v2.0.0+rke2r1",
        "v1.033.12+rke2r1",
        "v1.33.12+rke2r0",
        "v1.33.12+rke2r1\n",
        42,
        {},
    ],
)
def test_nonliteral_or_wrong_distribution_selection_is_rejected(product, value):
    config = configuration(product)
    config["spec"]["versions"][product] = value
    assert any("literal stable Kubernetes 1.x" in e for e in validate_config(config).errors)


@pytest.mark.parametrize("product", ["rke2", "k3s"])
def test_missing_managed_version_and_template_deploy_boundary(product):
    config = configuration(product)
    del config["spec"]["versions"][product]
    assert any("literal stable Kubernetes 1.x" in e for e in validate_config(config).errors)
    config["spec"]["environment"] = "staging"
    assert validate_config(config).ok
    assert any("literal stable Kubernetes 1.x" in w for w in validate_config(config).warnings)
    assert any(
        "literal stable Kubernetes 1.x" in e
        for e in validate_config(config, for_deployment=True).errors
    )


def test_unused_distribution_version_does_not_gate_docker_deployment():
    config = load_config(project_root() / "examples/configs/docker.yml")
    config["spec"]["versions"]["rke2"] = "unused"
    assert validate_config(config).ok


def test_version_preflight_and_installer_guards_are_present():
    versions["guard"](project_root())


@pytest.mark.parametrize(
    "change",
    [
        "rke2-gate-removed",
        "k3s-gate-skipped",
        "gate-forced",
        "gate-ignored",
        "installer-unconditional",
        "installer-string-comparison",
        "upgrade-preflight-removed",
        "upgrade-preflight-optional",
        "upgrade-one-host",
        "deploy-preflight-removed",
        "preflight-not-fatal",
        "preflight-after-mutation",
    ],
)
def test_observed_version_guard_cannot_be_bypassed(tmp_path, change):
    for name in ["roles/rke2_server/tasks", "roles/k3s_server/tasks", "playbooks"]:
        shutil.copytree(project_root() / name, tmp_path / name)
    path = tmp_path / "roles/rke2_server/tasks/main.yml"
    if change == "k3s-gate-skipped":
        path = tmp_path / "roles/k3s_server/tasks/main.yml"
    if change.startswith("upgrade-") or change.startswith("preflight-"):
        path = tmp_path / "playbooks/upgrade.yml"
    if change == "deploy-preflight-removed":
        path = tmp_path / "playbooks/rke2-ha.yml"
    document = yaml.safe_load(path.read_text())
    if change in {"rke2-gate-removed", "upgrade-preflight-removed", "deploy-preflight-removed"}:
        document.pop(0)
    elif change == "k3s-gate-skipped":
        document[0]["when"] = False
    elif change == "gate-forced":
        document[0]["vars"] = {"certweaver_cluster_version_install_needed": False}
    elif change == "gate-ignored":
        document[0]["ignore_errors"] = True
    elif change.startswith("installer-"):
        task = next(t for t in document if t["name"].startswith("Install or upgrade pinned"))
        if change == "installer-unconditional":
            task.pop("when")
        else:
            task["when"] = "selected != installed"
    elif change == "upgrade-preflight-optional":
        document[0]["roles"][0]["vars"]["certweaver_cluster_version_require_installed"] = False
    elif change == "upgrade-one-host":
        document[0]["hosts"] = "cluster_bootstrap"
    elif change == "preflight-not-fatal":
        document[0].pop("any_errors_fatal")
    else:
        document.insert(0, document.pop(2))
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ValueError):
        versions["guard"](tmp_path)
