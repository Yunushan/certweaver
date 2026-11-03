from __future__ import annotations

import runpy
import shutil
import sys

import pytest
import yaml

from certweaver import cli
from certweaver.config import load_config, validate_config
from certweaver.registry import project_root
from certweaver.render import inventory_from_config

PIN = "sha256:" + "a" * 64  # Format-only fixture, never a deployment approval.


def adapter_config(slug):
    source = "windows.yml" if slug == "win-acme" else "standalone.yml"
    data = load_config(project_root() / "examples/configs" / source)
    data["spec"]["adapters"]["enabled"] = [slug]
    data["spec"]["adapters"]["options"] = {}
    return data


@pytest.mark.parametrize(
    "slug,key",
    [
        ("lego", "lego"),
        ("caddy-auto-https", "caddy"),
        ("step-ca", "step_ca"),
        ("traefik-acme", "traefik"),
        ("cfssl", "cfssl"),
    ],
)
def test_binary_adapters_require_reviewed_versions_and_hashes_for_deployment(slug, key):
    data = adapter_config(slug)
    assert validate_config(data).ok  # Templates remain inspectable, with warnings.
    assert validate_config(data).warnings
    assert not validate_config(data, for_deployment=True).ok
    data["spec"]["environment"] = "production"
    assert not validate_config(data).ok
    data["spec"]["adapters"]["versions"][key] = "1.2.3-rc.1"
    for name in ["cfssl", "cfssljson", "cfssl-bundle"] if key == "cfssl" else [key]:
        data["spec"]["adapters"]["checksums"][name] = PIN
    assert validate_config(data, for_deployment=True).errors == []


@pytest.mark.parametrize(
    "checksum", ["", "REPLACE_WITH_SHA256", "sha256:" + "a" * 63, "md5:" + "a" * 32]
)
def test_invalid_digest_is_never_a_deployment_pin(checksum):
    data = adapter_config("lego")
    data["spec"]["adapters"]["versions"]["lego"] = "1.2.3"
    data["spec"]["adapters"]["checksums"]["lego"] = checksum
    assert any("SHA-256" in e for e in validate_config(data, for_deployment=True).errors)


@pytest.mark.parametrize(
    "version", ["latest", "REPLACE_WITH_VERSION", "v1.2.3", "../../other", "1.2", ""]
)
def test_invalid_binary_version_cannot_enter_an_acquisition_path(version):
    data = adapter_config("lego")
    data["spec"]["adapters"]["versions"]["lego"] = version
    data["spec"]["adapters"]["checksums"]["lego"] = PIN
    assert any("release version" in e for e in validate_config(data, for_deployment=True).errors)


def test_architecture_specific_digests_are_supported_and_bad_supplied_pins_are_visible():
    data = adapter_config("lego")
    data["spec"]["adapters"]["versions"]["lego"] = "1.2.3"
    data["spec"]["adapters"]["checksums"] = {"lego_amd64": PIN, "lego_arm64": PIN}
    assert validate_config(data, for_deployment=True).ok
    data["spec"]["adapters"]["checksums"]["lego_arm64"] = "invalid"
    assert not validate_config(data, for_deployment=True).ok


@pytest.mark.parametrize("installation", ["kubernetes", "docker"])
def test_step_ca_archive_requirement_only_applies_to_its_binary_path(installation):
    data = adapter_config("step-ca")
    data["spec"]["adapters"]["options"]["step-ca"] = {"installMode": installation}
    if installation == "docker":
        data["spec"]["adapters"]["versions"]["step_ca_image"] = PIN
    else:
        data["spec"]["adapters"]["versions"]["step_ca_chart"] = "1.2.3"
        data["spec"]["adapters"]["checksums"]["step_ca_chart"] = PIN
    assert validate_config(data, for_deployment=True).ok


def test_kubernetes_traefik_integration_does_not_require_a_host_binary_checksum():
    data = load_config(project_root() / "config/certweaver.example.yml")
    assert validate_config(data, for_deployment=True).ok


@pytest.mark.parametrize("checksum", ["a" * 64, PIN])
def test_win_acme_accepts_raw_or_prefixed_sha256(checksum):
    data = adapter_config("win-acme")
    data["spec"]["adapters"]["versions"]["win_acme"] = "2.2.9.1"
    data["spec"]["adapters"]["checksums"]["win_acme"] = checksum
    data["spec"]["adapters"]["options"]["win-acme"] = {
        "downloadUrl": "https://example.invalid/fixture.zip"
    }
    assert validate_config(data, for_deployment=True).ok


@pytest.mark.parametrize(
    "url", [None, 1, "http://example.invalid/fixture.zip", "file:///tmp/archive.zip"]
)
def test_win_acme_rejects_invalid_or_insecure_acquisition_urls(url):
    data = adapter_config("win-acme")
    data["spec"]["adapters"]["options"]["win-acme"] = {"downloadUrl": url}
    assert any("HTTPS" in e for e in validate_config(data, for_deployment=True).errors)


@pytest.mark.parametrize("value", [None, True, [], "standalone"])
def test_malformed_adapter_options_return_errors_instead_of_crashing(value):
    data = adapter_config("lego")
    data["spec"]["adapters"]["options"]["step-ca"] = value
    assert any("must be a mapping" in e for e in validate_config(data).errors)


@pytest.mark.parametrize("value", [None, [], {}, "unsupported"])
def test_unimplemented_step_ca_mode_is_rejected(value):
    data = adapter_config("step-ca")
    data["spec"]["adapters"]["options"]["step-ca"] = {"installMode": value}
    assert any("installMode" in e for e in validate_config(data).errors)


def test_deploy_rejects_template_pins_before_inventory_or_ansible_execution(tmp_path, monkeypatch):
    data = adapter_config("lego")
    config, inventory = tmp_path / "template.yml", tmp_path / "inventory.yml"
    data.pop("__source_path__")
    config.write_text(yaml.safe_dump(data), encoding="utf-8")
    monkeypatch.setattr(cli.shutil, "which", lambda _: "ansible-playbook")
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(
        sys, "argv", ["certweaver", "deploy", "-c", str(config), "-i", str(inventory)]
    )
    with pytest.raises(SystemExit) as failure:
        cli.main()
    assert failure.value.code == 2
    assert not inventory.exists() and not calls


@pytest.mark.parametrize("version", ["REPLACE_WITH_VERSION", "latest", "4.2.1", "4.2.1.0"])
def test_posh_acme_version_is_validated_and_rendered(version):
    data = load_config(project_root() / "examples/configs/windows.yml")
    data["spec"]["adapters"]["enabled"] = ["posh-acme"]
    data["spec"]["adapters"]["versions"]["posh_acme"] = version
    valid = version.startswith("4")
    assert validate_config(data, for_deployment=True).ok is valid
    assert inventory_from_config(data)["all"]["vars"]["certweaver_posh_acme_version"] == version


def test_source_inventory_keeps_unresolved_identity_owners_and_license_reviews_visible():
    scanner = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))
    report = scanner["inspect"](project_root())
    assert report["guardErrors"] == []
    assert report["status"] == "SOURCE_DECLARATIONS_NOT_COMPLETE_DEPLOYMENT_INVENTORY"
    assert len([e for e in report["entries"] if e["kind"] == "adapter-registry"]) == 20
    assert all(
        e["owner"] is None and e["resolvedCandidateIdentity"] is None for e in report["entries"]
    )


@pytest.mark.parametrize(
    "change", ["missing-checksum", "optional-checksum", "tls-disabled", "remote-archive"]
)
def test_source_guard_rejects_unverified_acquisition_regressions(tmp_path, change):
    shutil.copytree(project_root() / "roles", tmp_path / "roles")
    path = tmp_path / "roles/pki_adapter/tasks/_download_verified.yml"
    tasks = yaml.safe_load(path.read_text())
    download = next(t for t in tasks if "block" in t)["block"][1]
    arguments = download["ansible.builtin.get_url"]
    if change == "missing-checksum":
        arguments.pop("checksum")
    elif change == "optional-checksum":
        arguments["checksum"] = "{{ checksum | default(omit) }}"
    elif change == "tls-disabled":
        arguments["validate_certs"] = False
    else:
        tasks.append(
            {
                "name": "Unsafe fixture",
                "ansible.builtin.unarchive": {
                    "src": "https://example.invalid/archive.tar.gz",
                    "dest": "/tmp",
                },
            }
        )
    path.write_text(yaml.safe_dump(tasks), encoding="utf-8")
    scanner = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))
    assert scanner["inspect"](tmp_path)["guardErrors"]


IMAGE_ADAPTERS = [
    ("step-ca", "step_ca_image", "step-ca.container.j2", "docker.io/smallstep/step-ca"),
    ("openbao-pki", "openbao_image", "openbao.container.j2", "docker.io/openbao/openbao"),
    ("ejbca-community", "ejbca_image", "ejbca.container.j2", "docker.io/keyfactor/ejbca-ce"),
]


@pytest.mark.parametrize("slug,key,template,repository", IMAGE_ADAPTERS)
def test_container_paths_require_image_digests_and_render_exact_qualified_references(
    slug, key, template, repository
):
    from jinja2 import Environment, StrictUndefined

    data = adapter_config(slug)
    data["spec"]["adapters"]["options"][slug] = {"installMode": "docker"}
    assert validate_config(data).ok
    assert any("image digest" in w for w in validate_config(data).warnings)
    assert not validate_config(data, for_deployment=True).ok
    data["spec"]["environment"] = "production"
    assert any("image digest" in e for e in validate_config(data).errors)
    data["spec"]["adapters"]["versions"][key] = "sha256:" + "ABCDEF12" * 8
    assert validate_config(data, for_deployment=True).ok
    variables = inventory_from_config(data)["all"]["vars"]
    source = (project_root() / "roles/pki_adapter/templates" / template).read_text()
    result = Environment(undefined=StrictUndefined).from_string(source).render(**variables)
    assert "Image=" + repository + "@sha256:" + "abcdef12" * 8 in result.splitlines()
    if slug == "step-ca":
        assert variables["certweaver_adapter_versions"]["step_ca_image"].startswith("sha256:")
        assert variables["certweaver_adapter_versions"]["step_ca"] == ""


@pytest.mark.parametrize("slug,key,template,repository", IMAGE_ADAPTERS)
@pytest.mark.parametrize("pin", ["latest", "v1.2.3", "stable", "sha256:" + "a" * 63, "b" * 64])
def test_container_tags_and_invalid_digests_cannot_enter_deployment(
    slug, key, template, repository, pin
):
    data = adapter_config(slug)
    data["spec"]["adapters"]["options"][slug] = {"installMode": "docker"}
    data["spec"]["adapters"]["versions"][key] = pin
    assert any("image digest" in e for e in validate_config(data, for_deployment=True).errors)


@pytest.mark.parametrize("mode", ["rke2-ha", "k3s-ha", "existing-kubernetes"])
def test_cluster_default_installation_does_not_require_quadlet_image_digest(mode):
    data = load_config(project_root() / "config/certweaver.example.yml")
    data["spec"]["mode"] = mode
    data["spec"]["adapters"]["enabled"] = ["step-ca", "openbao-pki"]
    data["spec"]["adapters"]["options"] = {}
    assert not any("image digest" in e for e in validate_config(data, for_deployment=True).errors)
    data["spec"]["adapters"]["options"]["step-ca"] = {"installMode": "docker"}
    data["spec"]["adapters"]["options"]["openbao-pki"] = {"installMode": "docker"}
    errors = validate_config(data, for_deployment=True).errors
    assert sum("image digest" in e for e in errors) == 2


@pytest.mark.parametrize("slug", ["step-ca", "openbao-pki"])
@pytest.mark.parametrize("value", [None, [], {}, "unsupported"])
def test_container_installation_mode_cannot_silently_skip_requested_adapter(slug, value):
    data = adapter_config(slug)
    data["spec"]["adapters"]["options"][slug] = {"installMode": value}
    assert any("installMode" in e for e in validate_config(data, for_deployment=True).errors)


@pytest.mark.parametrize(
    "change",
    ["quadlet-tag", "quadlet-short-name", "compose-tag", "compose-optional", "compose-short-name"],
)
def test_source_guard_rejects_mutable_container_reference_regressions(tmp_path, change):
    root = project_root()
    shutil.copytree(root / "roles", tmp_path / "roles")
    shutil.copytree(root / "docker", tmp_path / "docker")
    if change.startswith("quadlet-"):
        path = tmp_path / "roles/pki_adapter/templates/openbao.container.j2"
        text = path.read_text()
        if change == "quadlet-tag":
            text = text.replace("@{{", ":{{")
        else:
            text = text.replace("docker.io/openbao/openbao", "openbao/openbao")
        path.write_text(text)
    else:
        path = tmp_path / "docker/compose.pki.yml"
        document = yaml.safe_load(path.read_text())
        image = document["services"]["openbao"]["image"]
        if change == "compose-tag":
            image = image.replace("@${", ":${")
        elif change == "compose-short-name":
            image = image.removeprefix("docker.io/")
        else:
            image = image.replace(":?", ":-")
        document["services"]["openbao"]["image"] = image
        path.write_text(yaml.safe_dump(document))
    scanner = runpy.run_path(str(root / "scripts/check-adapter-acquisition.py"))
    assert scanner["inspect"](tmp_path)["guardErrors"]


@pytest.mark.parametrize("slug,_,template,repository", IMAGE_ADAPTERS)
@pytest.mark.parametrize("changed", [False, True])
def test_container_service_reconciles_changed_unit_without_restarting_unchanged_unit(
    slug, _, template, repository, changed
):
    from jinja2 import Environment, StrictUndefined

    scanner = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))
    path = project_root() / "roles/pki_adapter/tasks/adapters" / (slug + ".yml")
    entries = list(scanner["tasks"](yaml.safe_load(path.read_text())))
    render = next(
        t for t in entries if t.get("ansible.builtin.template", {}).get("src") == template
    )
    service = next(t for t in entries if "name" in t.get("ansible.builtin.systemd", {}))
    variables = {render["register"]: {"changed": changed}}
    if slug == "openbao-pki":
        variables["certweaver_openbao_configuration"] = {"changed": False}
    selected = (
        Environment(undefined=StrictUndefined)
        .from_string(service["ansible.builtin.systemd"]["state"])
        .render(**variables)
    )
    assert selected == ("restarted" if changed else "started")


def test_openbao_configuration_change_restarts_existing_service():
    from jinja2 import Environment, StrictUndefined

    scanner = runpy.run_path(str(project_root() / "scripts/check-adapter-acquisition.py"))
    source = project_root() / "roles/pki_adapter/tasks/adapters/openbao-pki.yml"
    service = next(
        t
        for t in scanner["tasks"](yaml.safe_load(source.read_text()))
        if "name" in t.get("ansible.builtin.systemd", {})
    )
    assert (
        Environment(undefined=StrictUndefined)
        .from_string(service["ansible.builtin.systemd"]["state"])
        .render(
            certweaver_openbao_quadlet={"changed": False},
            certweaver_openbao_configuration={"changed": True},
        )
        == "restarted"
    )
