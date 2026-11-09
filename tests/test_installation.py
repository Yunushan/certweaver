"""Installation and placement contracts; these are not live CA qualification."""

import copy
import runpy

import pytest
import yaml

from certweaver.config import load_config, validate_config
from certweaver.errors import ConfigurationError
from certweaver.installation import (
    CLIENTS,
    CONTAINERS,
    backend,
    container_model,
    options_for_host,
    topology_issues,
    verified_manifest_images,
)
from certweaver.registry import load_registry, project_root
from certweaver.render import inventory_from_config

IMAGE = "registry.example.invalid/pki/tool@sha256:" + "a" * 64


@pytest.mark.parametrize("slug", sorted(CONTAINERS))
def test_compose_installation_binds_image_and_preserves_literal_arguments(slug):
    options = {
        "container": {
            "image": IMAGE,
            "command": ["--config", "/config/$PROFILE.conf"],
            "mounts": [{"source": "/srv/pki", "target": "/config"}],
            "envFiles": ["/etc/secrets/adapter.env"],
        }
    }
    original = copy.deepcopy(options)
    service = yaml.safe_load(yaml.safe_dump(container_model(options, slug)))["services"]["app"]
    assert service["image"] == IMAGE
    assert service["command"] == ["--config", "/config/$$PROFILE.conf"]
    assert service["restart"] == ("no" if slug in CLIENTS else "unless-stopped")
    assert service["volumes"][0]["read_only"] is True
    assert service["volumes"][0]["bind"]["create_host_path"] is False
    assert options == original


@pytest.mark.parametrize(
    "image",
    [
        "tool:latest",
        "vendor/tool@sha256:" + "a" * 64,
        "registry.test/tool:1.0",
        IMAGE + "\n",
        "https://" + IMAGE,
        IMAGE.replace("a" * 64, "A" * 64),
    ],
)
def test_mutable_or_ambiguous_image_identity_is_rejected(image):
    with pytest.raises(ConfigurationError):
        container_model({"container": {"image": image}}, "certbot")


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", "sh -c unsafe"),
        ("entrypoint", [1]),
        ("mounts", [{"source": "relative", "target": "/x"}]),
        ("mounts", [{"source": "/x", "target": "/y", "readOnly": "false"}]),
        ("envFiles", ["relative.env"]),
        ("privileged", True),
        ("healthcheck", {"test": ["NONE"]}),
        ("user", "root\nExecStart=bad"),
    ],
)
def test_invalid_runtime_shapes_fail_before_rendering(field, value):
    with pytest.raises(ConfigurationError):
        container_model({"container": {"image": IMAGE, field: value}}, "step-ca")


def test_host_options_are_isolated_and_never_mutate_shared_input():
    options = {"components": ["agent"], "hosts": {"ca-01": {"components": ["server"]}}}
    assert options_for_host(options, "ca-01") == {"components": ["server"]}
    assert options_for_host(options, "ca-02") == {"components": ["agent"]}
    assert options["components"] == ["agent"]


@pytest.mark.parametrize("mode", ["rke2-ha", "k3s-ha", "existing-kubernetes"])
def test_cluster_and_host_placement_are_distinct(mode):
    assert backend("cert-manager", mode, {}) == "kubernetes"
    assert backend("certbot", mode, {}) == "host"
    assert backend("step-ca", mode, {}) == "kubernetes"
    assert backend("step-ca", mode, {"installMode": "standalone"}) == "host"


def test_spire_compose_can_install_server_and_agent_on_one_node():
    model = container_model(
        {
            "containers": {
                "server": {"image": IMAGE, "command": ["run", "-config", "/config/server.conf"]},
                "agent": {"image": IMAGE, "command": ["run", "-config", "/config/agent.conf"]},
            }
        },
        "spire",
    )
    assert set(model["services"]) == {"server", "agent"}
    assert all(service["image"] == IMAGE for service in model["services"].values())


@pytest.mark.parametrize("command", [["server", "-dev"], ["server", "--dev=true"]])
def test_managed_openbao_never_selects_development_server_mode(command):
    with pytest.raises(ConfigurationError, match="development"):
        container_model({"container": {"image": IMAGE, "command": command}}, "openbao-pki")


def test_native_spire_requires_actual_configuration_and_components():
    nodes = [{"name": "server"}, {"name": "agent"}]
    assert topology_issues("raw", nodes, ["spire"], {"spire": {}})
    settings = {
        "spire": {
            "hosts": {
                "server": {"components": ["server"], "serverConfigFile": "/reviewed/server.conf"},
                "agent": {"components": ["agent"], "agentConfigFile": "/reviewed/agent.conf"},
            }
        }
    }
    assert topology_issues("raw", nodes, ["spire"], settings) == []


def test_managed_cluster_places_host_clients_on_every_selected_host_and_charts_once():
    config = load_config(project_root() / "config/certweaver.example.yml")
    config["spec"]["adapters"]["enabled"] = ["cert-manager", "certbot"]
    config["spec"]["adapters"]["options"] = {
        "certbot": {"hosts": {"rke2-02": {"packages": ["python3-certbot-dns-rfc2136"]}}}
    }
    hosts = inventory_from_config(config)["all"]["children"]["cluster_servers"]["hosts"]
    assert hosts["rke2-01"]["certweaver_enabled_adapters"] == ["cert-manager", "certbot"]
    assert hosts["rke2-02"]["certweaver_enabled_adapters"] == ["certbot"]
    assert hosts["rke2-03"]["certweaver_enabled_adapters"] == ["certbot"]
    assert "packages" not in hosts["rke2-01"]["certweaver_adapter_options"]["certbot"]
    assert hosts["rke2-02"]["certweaver_adapter_options"]["certbot"]["packages"]


def test_host_specific_binary_backend_cannot_bypass_acquisition_preflight():
    config = load_config(project_root() / "config/certweaver.example.yml")
    config["spec"]["adapters"]["enabled"] = ["step-ca"]
    config["spec"]["adapters"]["options"] = {
        "step-ca": {"hosts": {"rke2-02": {"installMode": "standalone"}}}
    }
    errors = validate_config(config, for_deployment=True).errors
    assert any("step_ca" in error and "release version" in error for error in errors)


def test_rendered_application_checks_init_sidecar_and_primary_images():
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "spec": {
            "containers": [{"name": "app", "image": IMAGE}, {"name": "sidecar", "image": IMAGE}],
            "initContainers": [{"name": "init", "image": IMAGE}],
        },
    }
    assert verified_manifest_images(yaml.safe_dump(pod), IMAGE)
    pod["spec"]["initContainers"][0]["image"] = "tool:latest"
    with pytest.raises(ConfigurationError, match="digest"):
        verified_manifest_images(yaml.safe_dump(pod), IMAGE)


@pytest.mark.parametrize(
    "bad",
    [
        "--trusted-host example.invalid",
        "-r extra.lock",
        "package @ https://example.invalid/code.whl",
        "package==1.0",
        "package==1.0 --hash=md5:" + "a" * 32,
    ],
)
def test_application_build_lock_does_not_allow_installer_option_or_identity_bypasses(tmp_path, bad):
    validate = runpy.run_path(
        str(project_root() / "roles/pki_adapter/files/validate-build-lock.py")
    )["validate"]
    lock = tmp_path / "requirements.lock"
    lock.write_text(bad + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        validate(lock)


def test_application_build_lock_accepts_complete_hashed_toolchain(tmp_path):
    validate = runpy.run_path(
        str(project_root() / "roles/pki_adapter/files/validate-build-lock.py")
    )["validate"]
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "\n".join(
            f"{name}==1.0 --hash=sha256:" + "a" * 64
            for name in ["pip", "setuptools", "wheel", "flask"]
        )
        + "\n",
        encoding="utf-8",
    )
    assert validate(lock) is None


@pytest.mark.parametrize("options", [None, {"hosts": []}, {"hosts": {"host": []}}])
def test_invalid_host_override_fails_explicitly(options):
    with pytest.raises(ConfigurationError):
        options_for_host(options, "host")


@pytest.mark.parametrize(
    "options",
    [
        {"hosts": []},
        {"hosts": {"other": {}}},
        {"hosts": {"host": []}},
        {"nodes": []},
        {"nodes": ["other"]},
        {"nodes": ["host", "host"]},
        {"nodes": "host"},
        {"files": {}},
        {"files": [None]},
        {"files": [{"source": "relative", "name": "file"}]},
        {"files": [{"source": "/input", "name": "../escape"}]},
        {"files": [{"source": "/input", "name": "config"}]},
        {"files": [{"source": "/input", "name": "secret", "mode": []}]},
        {"files": [{"source": "/input", "name": "secret", "mode": "0644"}]},
    ],
)
def test_invalid_placement_and_file_inputs_are_rejected(options):
    assert topology_issues("raw", [{"name": "host"}], ["certbot"], {"certbot": options})


def test_host_selection_excludes_unselected_inputs_and_accepts_confined_files():
    nodes = [{"name": "host"}, {"name": "second"}]
    settings = {"nodes": ["host"], "files": [{"source": "/input", "name": "key", "mode": "0600"}]}
    assert not topology_issues("raw", nodes, ["certbot"], {"certbot": settings})
    assert topology_issues("docker", nodes, ["step-ca"], {"step-ca": {"installMode": "standalone"}})
    assert topology_issues(
        "rke2-ha", nodes, ["cert-manager"], {"cert-manager": {"nodes": ["second"]}}
    )


@pytest.mark.parametrize(
    "slug,settings",
    [
        ("spire", {"components": []}),
        ("spire", {"components": ["server"], "serverConfigFile": "relative"}),
        ("lemur", {}),
        (
            "lemur",
            {
                "requirementsFile": "/lock",
                "configFile": "/config",
                "runMigrations": True,
                "migrationHost": "unknown",
            },
        ),
        ("step-ca", {}),
        ("step-ca", {"serviceConfigFile": "/config", "passwordFile": "relative"}),
        ("caddy-auto-https", {}),
        ("traefik-acme", {}),
        ("openbao-pki", {}),
        ("freeipa-certmonger", {"role": []}),
        ("freeipa-certmonger", {"role": "server", "configureServer": True}),
        ("freeipa-certmonger", {"role": "client"}),
    ],
)
def test_native_configuration_and_identity_prerequisites_are_fail_closed(slug, settings):
    assert topology_issues("raw", [{"name": "host"}], [slug], {slug: settings}, True)


@pytest.mark.parametrize(
    "slug,settings",
    [
        ("step-ca", {"serviceConfigFile": "/config", "passwordFile": "/etc/private/password"}),
        ("openbao-pki", {"serviceConfigFile": "/config"}),
        ("caddy-auto-https", {"serviceConfigFile": "/config"}),
        ("traefik-acme", {"serviceConfigFile": "/config"}),
        (
            "lemur",
            {
                "requirementsFile": "/lock",
                "configFile": "/config",
                "runMigrations": True,
                "migrationHost": "host",
            },
        ),
        ("freeipa-certmonger", {"role": "replica"}),
        (
            "freeipa-certmonger",
            {
                "role": "client",
                "realm": "EXAMPLE.TEST",
                "domain": "example.test",
                "server": "ipa.example.test",
                "keytabFile": "/private/keytab",
            },
        ),
        (
            "freeipa-certmonger",
            {
                "role": "server",
                "configureServer": True,
                "realm": "EXAMPLE.TEST",
                "domain": "example.test",
                "hostname": "ipa.example.test",
                "directoryManagerPasswordFile": "/dm",
                "adminPasswordFile": "/admin",
            },
        ),
    ],
)
def test_explicit_native_profiles_pass_format_preflight_without_claiming_live_health(
    slug, settings
):
    assert not topology_issues("raw", [{"name": "host"}], [slug], {slug: settings}, True)


@pytest.mark.parametrize(
    "options,slug",
    [
        ({}, "unknown"),
        ([], "certbot"),
        ({"container": []}, "certbot"),
        ({"containers": {}}, "spire"),
        ({"containers": {"unknown": {}}}, "spire"),
        ({"containers": {"server": {}}, "container": {}}, "spire"),
    ],
)
def test_unsupported_container_contracts_are_rejected(options, slug):
    with pytest.raises(ConfigurationError):
        container_model(options, slug)


@pytest.mark.parametrize(
    "updates",
    [
        {"mounts": {}},
        {"mounts": [{"source": "/x", "target": "relative"}]},
        {"user": "root"},
        {"hostPID": "true"},
        {"healthcheck": {}},
        {
            "healthcheck": {
                "test": ["CMD", "check"],
                "interval": "0s",
                "timeout": "5s",
                "retries": 3,
            }
        },
        {
            "healthcheck": {
                "test": ["CMD", "check"],
                "interval": "10s",
                "timeout": "5s",
                "retries": True,
            }
        },
        {
            "healthcheck": {
                "test": ["CMD", "check"],
                "interval": "10s",
                "timeout": "5s",
                "retries": 0,
            }
        },
    ],
)
def test_container_runtime_boundaries_reject_unsafe_shapes(updates):
    with pytest.raises(ConfigurationError):
        container_model({"container": {"image": IMAGE, "command": ["server"], **updates}}, "spire")


def test_container_health_mount_permissions_and_host_pid_are_explicit():
    runtime = {
        "image": IMAGE,
        "command": ["run"],
        "user": "1000:1000",
        "hostPID": True,
        "mounts": [{"source": "/state", "target": "/state", "readOnly": False}],
        "healthcheck": {"test": ["CMD", "check"], "interval": "10s", "timeout": "5s", "retries": 3},
    }
    service = container_model({"container": runtime}, "spire")["services"]["app"]
    assert service["pid"] == "host" and service["volumes"][0]["read_only"] is False
    assert service["healthcheck"]["retries"] == 3
    with pytest.raises(ConfigurationError):
        container_model({"container": runtime}, "step-ca")
    runtime["hostPID"] = False
    assert "pid" not in container_model({"container": runtime}, "spire")["services"]["app"]
    assert container_model({"container": {"image": IMAGE, "command": ["server"]}}, "openbao-pki")[
        "services"
    ]["app"]["cap_add"] == ["IPC_LOCK"]


@pytest.mark.parametrize(
    "manifest",
    [
        "spec: {containers: {image: bad}}",
        "spec: {containers: [null]}",
        "spec: {containers: [{image: latest}]}",
        "spec: {containers: []}",
        "invalid: [",
        "loop: &loop {next: *loop}",
    ],
)
def test_rendered_manifest_must_be_parseable_bounded_and_contain_approved_images(manifest):
    with pytest.raises(ConfigurationError):
        verified_manifest_images(manifest, IMAGE)


def test_manifest_multi_document_ephemeral_images_and_inspection_limits():
    manifest = "---\nkind: List\nitems:\n- spec:\n    ephemeralContainers:\n    - image: " + IMAGE
    assert verified_manifest_images(manifest, IMAGE)
    with pytest.raises(ConfigurationError, match="inspection limit"):
        verified_manifest_images(" " * (16 * 1024 * 1024 + 1), IMAGE)
    with pytest.raises(ConfigurationError):
        verified_manifest_images("value: " + "[" * 120 + "0" + "]" * 120, IMAGE)
    assert backend("win-acme", "windows", {}) == "windows"
    assert backend("boulder", "docker", {}) == "boulder-lab"
    assert backend("certbot", "docker", {}) == "docker"


@pytest.mark.parametrize("mode", ["raw", "docker", "rke2-ha"])
def test_production_ejbca_database_guard_applies_to_every_backend(mode):
    options = {"ejbca-community": {}}
    assert topology_issues(
        mode, [{"name": "host"}], ["ejbca-community"], options, environment="production"
    )
    options["ejbca-community"]["externalDatabase"] = True
    assert not topology_issues(
        mode, [{"name": "host"}], ["ejbca-community"], options, environment="production"
    )


@pytest.mark.parametrize(
    "slug,mode",
    [(slug, mode) for slug, adapter in load_registry().items() for mode in adapter.modes],
)
def test_all_declared_adapter_modes_accept_complete_format_profiles_and_place_hosts(slug, mode):
    """Synthetic identities prove format/placement, never upstream artifact approval."""
    config = load_config(project_root() / "examples/configs" / (mode + ".yml"))
    spec = config["spec"]
    spec["environment"] = "staging"
    spec["addons"] = {}
    core = {
        "cert-manager": "certManager",
        "trust-manager": "trustManager",
        "cert-manager-csi-driver": "csiDriver",
        "traefik-acme": "traefik",
    }
    if mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"} and slug in core:
        spec["addons"] = {"certManager": {"enabled": True}, core[slug]: {"enabled": True}}
    nodes = spec["platform"]["nodes"]
    if len(nodes) == 1:
        nodes.append({**nodes[0], "name": "second-fixture", "address": "192.0.2.22"})
    versions = {
        key: "1.2.3"
        for key in [
            "step_ca",
            "step_ca_chart",
            "openbao",
            "openbao_chart",
            "ejbca_chart",
            "lego",
            "cfssl",
            "spire",
            "spire_chart",
            "spire_crds_chart",
            "caddy",
            "traefik",
            "win_acme",
            "posh_acme",
        ]
    }
    versions.update(
        {key: "a" * 40 for key in ["acme_sh_ref", "dehydrated_ref", "boulder_ref", "lemur_ref"]}
    )
    versions.update(
        {key: "sha256:" + "a" * 64 for key in ["step_ca_image", "openbao_image", "ejbca_image"]}
    )
    settings = {
        "components": ["server", "agent"],
        "serverConfigFile": "/reviewed/server.conf",
        "agentConfigFile": "/reviewed/agent.conf",
        "requirementsFile": "/reviewed/python.lock",
        "configFile": "/reviewed/config.py",
        "binaryUrl": "https://example.invalid/release.tar.gz",
        "externalDatabase": True,
        "downloadUrl": "https://example.invalid/win-acme.zip",
    }
    if mode == "docker" and slug != "boulder":
        settings["container"] = {"image": IMAGE, "command": ["reviewed-fixture-command"]}
    spec["adapters"] = {
        "enabled": [slug],
        "acknowledge": [slug],
        "versions": versions,
        "checksums": {
            key: "sha256:" + "a" * 64 for key in [*versions, "cfssljson", "cfssl-bundle"]
        },
        "options": {slug: settings},
        "startServices": False,
    }
    result = validate_config(config, for_deployment=True)
    assert result.ok, result.errors
    inventory = inventory_from_config(config)["all"]["children"]
    hosts = inventory["pki_windows" if mode == "windows" else "pki_linux"]["hosts"]
    selected = [name for name, host in hosts.items() if slug in host["certweaver_enabled_adapters"]]
    assert selected == (
        [nodes[0]["name"]]
        if backend(slug, mode, settings) == "kubernetes"
        else [n["name"] for n in nodes]
    )
