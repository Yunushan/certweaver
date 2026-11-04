import json

import pytest
import yaml
from jinja2 import Environment

from certweaver.config import load_config
from certweaver.registry import project_root
from certweaver.render import execution_plan, inventory_from_config


def test_inventory_groups_bootstrap_and_joiners() -> None:
    config = load_config(project_root() / "config" / "certweaver.example.yml")
    inventory = inventory_from_config(config)
    children = inventory["all"]["children"]
    assert list(children["cluster_bootstrap"]["hosts"]) == ["rke2-01"]
    assert set(children["cluster_joiners"]["hosts"]) == {"rke2-02", "rke2-03"}
    assert inventory["all"]["vars"]["certweaver_api_front_port"] == 8443
    assert inventory["all"]["vars"]["certweaver_fetch_kubeconfig"] is False
    assert inventory["all"]["vars"]["certweaver_rke2_install_script_checksum"].startswith("sha256:")
    assert inventory["all"]["vars"]["certweaver_rke2_etcd_s3_enabled"] is True


def test_plan_includes_all_enabled_adapters() -> None:
    config = load_config(project_root() / "config" / "certweaver.example.yml")
    plan = "\n".join(execution_plan(config))
    assert "cert-manager" in plan
    assert "trust-manager" in plan
    assert "Traefik" in plan


def test_plan_describes_external_load_balancer() -> None:
    config = load_config(project_root() / "config" / "certweaver.example.yml")
    config["spec"]["platform"]["loadBalancer"]["enabled"] = False
    plan = "\n".join(execution_plan(config))
    assert "externally managed load-balancer endpoint" in plan
    assert "Configure HAProxy" not in plan


@pytest.mark.parametrize("distribution", ["rke2", "k3s"])
@pytest.mark.parametrize("patch,revision", [(0, 1), (12, 2), (12, 10)])
def test_selected_distribution_identity_survives_inventory_and_installer_binding(
    distribution: str, patch: int, revision: int
) -> None:
    filename = (
        "config/certweaver.example.yml" if distribution == "rke2" else "examples/configs/k3s-ha.yml"
    )
    config = load_config(project_root() / filename)
    suffix = "rke2r" if distribution == "rke2" else "k3s"
    desired = f"v1.34.{patch}+{suffix}{revision}"
    config["spec"]["versions"][distribution] = desired
    variables = inventory_from_config(config)["all"]["vars"]
    assert variables[f"certweaver_{distribution}_version"] == desired
    tasks_path = project_root() / "roles" / f"{distribution}_server" / "tasks" / "main.yml"
    tasks = yaml.safe_load(tasks_path.read_text(encoding="utf-8"))
    install = next(task for task in tasks if task["name"].startswith("Install or upgrade pinned"))
    binding = install["environment"][f"INSTALL_{distribution.upper()}_VERSION"]
    assert Environment().from_string(binding).render(**variables) == desired
    defaults_path = project_root() / "roles" / f"{distribution}_server" / "defaults/main.yml"
    defaults = yaml.safe_load(defaults_path.read_text(encoding="utf-8"))
    installer_url = Environment().from_string(
        defaults[f"certweaver_{distribution}_install_script_url"]
    ).render(**variables)
    repository = "rancher/rke2" if distribution == "rke2" else "k3s-io/k3s"
    assert installer_url == (
        f"https://raw.githubusercontent.com/{repository}/{desired.replace('+', '%2B')}/install.sh"
    )


@pytest.mark.parametrize("disabled", [True, False])
def test_rke2_packaged_ingress_selection_is_explicit(disabled: bool) -> None:
    config = load_config(project_root() / "config/certweaver.example.yml")
    config["spec"]["rke2"]["disablePackagedIngress"] = disabled
    variables = inventory_from_config(config)["all"]["vars"]
    assert variables["certweaver_rke2_disable_packaged_ingress"] is disabled
    assert variables["certweaver_rke2_disable_components"] == (
        ["rke2-ingress-nginx", "rke2-traefik", "rke2-traefik-crd"] if disabled else []
    )
    # Render the actual ownership section, including the distribution selection
    # that prevents a new RKE2 default from choosing a competing controller.
    template = (project_root() / "roles/rke2_server/templates/config.yaml.j2").read_text(
        encoding="utf-8"
    )
    section = template[template.index("{% if certweaver_rke2_disable_packaged_ingress") :]
    section = section[: section.index("{% if certweaver_rke2_profile")]
    environment = Environment()
    environment.filters["bool"] = bool
    environment.filters["to_json"] = json.dumps
    rendered = yaml.safe_load(environment.from_string(section).render(**variables)) or {}
    assert rendered.get("ingress-controller") == (["none"] if disabled else None)
    assert rendered.get("disable", []) == variables["certweaver_rke2_disable_components"]
