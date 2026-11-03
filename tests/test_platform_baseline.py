"""Protect the offline gate's deployed-input translation and failure boundaries."""

import runpy

import pytest
import yaml

from certweaver.config import load_config
from certweaver.registry import project_root
from certweaver.render import inventory_from_config

tools = runpy.run_path(str(project_root() / "scripts/check-platform-baseline.py"))


def test_baseline_translates_actual_deployment_overrides_and_private_values_paths():
    root = project_root()
    variables = inventory_from_config(load_config(root / "config/certweaver.example.yml"))["all"][
        "vars"
    ]
    variables["certweaver_chart_archive_path"] = "/private/verified.tgz"
    tasks = yaml.safe_load(
        (root / "roles/cluster_addons/tasks/main.yml").read_text(encoding="utf-8")
    )
    task = next(
        t for t in tasks if t["name"] == "Install Traefik without independent ACME resolver"
    )
    args = tools["template_arguments"](task, variables, root)
    assert args[:3] == ["template", "traefik", "/private/verified.tgz"]
    assert str(root / "kubernetes/traefik/values.yaml") in args
    assert "ports.web.nodePort=30080" in args
    assert "ports.websecure.nodePort=30443" in args
    assert not {"--wait", "--timeout", "--create-namespace"} & set(args)


@pytest.mark.parametrize("flag", ["--disable-openapi-validation", "--skip-schema-validation"])
def test_unhandled_deployment_flags_cannot_silently_escape_the_offline_gate(flag):
    task = {
        "ansible.builtin.command": {"argv": ["helm", "upgrade", "--install", "x", "x.tgz", flag]}
    }
    with pytest.raises(ValueError, match="Unhandled deployed chart flag"):
        tools["template_arguments"](task, {}, project_root())


def test_fresh_cluster_baseline_rejects_a_retired_api_before_resource_checks():
    with pytest.raises(ValueError, match="Retired API"):
        tools["inspect_rendered"](
            "traefik", [{"apiVersion": "policy/v1beta1", "kind": "PodDisruptionBudget"}]
        )


@pytest.mark.parametrize(
    "flags,accepted",
    [
        (["--controllers=-certificaterequests-approver"], True),
        ([], False),
        (["--controllers=*"], False),
        (["--controllers=-certificaterequests-approver", "--controllers=*"], False),
    ],
)
def test_automatic_approval_guard_rejects_missing_or_overridden_negative_selection(flags, accepted):
    resources = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "cert-manager"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"args": flags}],
                        "priorityClassName": "system-cluster-critical",
                    }
                }
            },
        }
    ]
    if accepted:
        tools["inspect_rendered"]("certManager", resources)
    else:
        with pytest.raises(ValueError, match="Automatic CertificateRequest approval"):
            tools["inspect_rendered"]("certManager", resources)
