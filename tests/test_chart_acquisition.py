from __future__ import annotations

import runpy
import shutil

import pytest
import yaml

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root
from certweaver.render import inventory_from_config

PIN = "sha256:" + "a" * 64  # Format-only fixture; never production approval.


@pytest.mark.parametrize(
    "addon,version",
    [
        ("certManager", "certManager"),
        ("approverPolicy", "approverPolicy"),
        ("trustManager", "trustManager"),
        ("csiDriver", "csiDriver"),
        ("traefik", "traefikChart"),
    ],
)
def test_each_enabled_core_chart_requires_its_own_archive_identity(addon, version):
    data = load_config(project_root() / "config/certweaver.example.yml")
    data["spec"]["addons"][addon]["enabled"] = True
    del data["spec"]["versions"]["chartChecksums"][addon]
    assert any(f"chartChecksums.{addon}" in e for e in validate_config(data).errors)
    data["spec"]["environment"] = "staging"
    assert validate_config(data).ok
    assert any(f"chartChecksums.{addon}" in w for w in validate_config(data).warnings)
    assert not validate_config(data, for_deployment=True).ok
    data["spec"]["versions"]["chartChecksums"][addon] = PIN
    data["spec"]["versions"][version] = "v1.2.3"
    assert validate_config(data, for_deployment=True).ok
    assert inventory_from_config(data)["all"]["vars"]["certweaver_chart_checksums"][addon] == PIN


@pytest.mark.parametrize("version", ["latest", "^1.0.0", ">=1.2.3", "*", "1.2", 42, {}])
def test_chart_ranges_and_nonversion_values_are_rejected(version):
    data = load_config(project_root() / "config/certweaver.example.yml")
    data["spec"]["addons"]["traefik"]["chartVersion"] = version
    assert any("literal release version" in e for e in validate_config(data).errors)


@pytest.mark.parametrize(
    "slug,key", [("step-ca", "step_ca_chart"), ("openbao-pki", "openbao_chart")]
)
def test_kubernetes_adapter_chart_inputs_are_mandatory_only_for_chart_paths(slug, key):
    data = load_config(project_root() / "examples/configs/standalone.yml")
    data["spec"]["adapters"]["enabled"] = [slug]
    data["spec"]["adapters"]["options"][slug] = {"installMode": "kubernetes"}
    assert any(key in e for e in validate_config(data, for_deployment=True).errors)
    data["spec"]["adapters"]["versions"][key] = "1.2.3"
    data["spec"]["adapters"]["checksums"][key] = PIN
    assert validate_config(data, for_deployment=True).ok


def test_spire_and_crds_have_independent_versions_and_checksums():
    data = load_config(project_root() / "config/certweaver.example.yml")
    data["spec"]["adapters"]["enabled"] = ["spire"]
    for key, version in [("spire_chart", "1.2.3"), ("spire_crds_chart", "0.4.5")]:
        data["spec"]["adapters"]["versions"][key] = version
        data["spec"]["adapters"]["checksums"][key] = PIN
    assert validate_config(data, for_deployment=True).ok
    del data["spec"]["adapters"]["checksums"]["spire_crds_chart"]
    assert any("spire_crds_chart" in e for e in validate_config(data).errors)


@pytest.mark.parametrize("change", ["remote-ref", "no-helper", "unverified", "dependency-update"])
def test_source_guard_rejects_unverified_chart_installation(tmp_path, change):
    shutil.copytree(project_root() / "roles", tmp_path / "roles")
    path = tmp_path / "roles/cluster_addons/tasks/main.yml"
    document = yaml.safe_load(path.read_text())
    index = next(i for i, task in enumerate(document) if task["name"] == "Install cert-manager")
    install = document[index]
    if change == "remote-ref":
        install["ansible.builtin.command"]["argv"][4] = "oci://example.invalid/unverified"
    elif change == "no-helper":
        document.pop(index - 1)
    elif change == "unverified":
        install["when"].remove("certweaver_chart_verified | default(false) | bool")
    else:
        install["ansible.builtin.command"]["argv"].append("--dependency-update")
    path.write_text(yaml.safe_dump(document))
    inspect = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))[
        "inspect"
    ]
    assert inspect(tmp_path)["guardErrors"]


def test_source_inventory_retains_all_nine_chart_sources_and_expected_archive_hash_inputs():
    inspect = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))[
        "inspect"
    ]
    report = inspect(project_root())
    charts = [e for e in report["entries"] if e["kind"] == "helm-chart"]
    assert len(charts) == 9 and not report["guardErrors"]
    assert all(e["declaration"]["checksum"] and e["declaration"]["version"] for e in charts)


@pytest.mark.parametrize(
    "slug,addon",
    [
        ("cert-manager", "certManager"),
        ("trust-manager", "trustManager"),
        ("cert-manager-csi-driver", "csiDriver"),
        ("traefik-acme", "traefik"),
    ],
)
def test_adapter_cannot_claim_a_disabled_core_chart(slug, addon):
    data = load_config(project_root() / "config/certweaver.example.yml")
    data["spec"]["adapters"]["enabled"] = [slug]
    data["spec"]["addons"][addon]["enabled"] = False
    assert any("Adapter " + slug + " requires enabled" in e for e in validate_config(data).errors)
