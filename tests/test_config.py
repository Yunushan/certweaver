from pathlib import Path

import pytest

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root


def sample() -> dict:
    return load_config(project_root() / "config" / "certweaver.example.yml")


def test_sample_is_valid_except_expected_missing_secret_warnings() -> None:
    result = validate_config(sample())
    assert result.errors == []
    assert any("Secret file" in warning for warning in result.warnings)


def test_one_node_is_rejected_for_production_ha() -> None:
    data = sample()
    data["spec"]["platform"]["nodes"] = data["spec"]["platform"]["nodes"][:1]
    result = validate_config(data)
    assert any("at least three" in error for error in result.errors)


def test_colocated_rke2_port_collision_is_rejected() -> None:
    data = sample()
    data["spec"]["platform"]["vip"]["ports"]["api"] = 6443
    result = validate_config(data)
    assert any("cannot bind VIP port 6443" in error for error in result.errors)


def test_open_management_cidr_is_rejected_for_production() -> None:
    data = sample()
    data["spec"]["platform"]["network"]["managementCidrs"] = ["0.0.0.0/0"]
    result = validate_config(data)
    assert any("managementCidrs" in error and "0.0.0.0/0" in error for error in result.errors)


def test_duplicate_keepalived_priority_is_rejected() -> None:
    data = sample()
    data["spec"]["platform"]["nodes"][1]["keepalivedPriority"] = 150
    result = validate_config(data)
    assert any("Keepalived priorities" in error for error in result.errors)


def test_production_cert_manager_auto_approval_is_rejected() -> None:
    data = sample()
    data["spec"]["addons"]["certManager"]["disableAutoApproval"] = False
    result = validate_config(data)
    assert any("automatic approval" in error for error in result.errors)


def test_production_requires_privileged_installer_checksum() -> None:
    data = sample()
    data["spec"]["versions"]["rke2InstallerChecksum"] = ""
    result = validate_config(data)
    assert any("rke2InstallerChecksum" in error for error in result.errors)


def test_production_requires_kernel_default_protection() -> None:
    data = sample()
    data["spec"]["rke2"]["protectKernelDefaults"] = False
    result = validate_config(data)
    assert any("protectKernelDefaults" in error for error in result.errors)


def test_production_requires_off_host_etcd_snapshot_replication() -> None:
    data = sample()
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["enabled"] = False
    result = validate_config(data)
    assert any("off-host etcd snapshot" in error for error in result.errors)


def test_traefik_acme_resolver_conflict_is_rejected() -> None:
    data = sample()
    data["spec"]["adapters"]["options"]["traefik-acme"]["resolverEnabled"] = True
    result = validate_config(data)
    assert any("Traefik ACME resolver" in error for error in result.errors)


@pytest.mark.parametrize("environment", ["production", "development"])
def test_managed_traefik_rejects_competing_packaged_rke2_ingress(environment: str) -> None:
    data = sample()
    data["spec"]["environment"] = environment
    data["spec"]["rke2"]["disablePackagedIngress"] = False
    assert any("ingress ownership" in error for error in validate_config(data).errors)
    data["spec"]["addons"]["traefik"]["enabled"] = False
    assert not any("ingress ownership" in error for error in validate_config(data).errors)


def test_lab_adapter_requires_acknowledgement() -> None:
    data = sample()
    data["spec"]["mode"] = "docker"
    data["spec"]["platform"]["nodes"] = [{"name": "docker-01", "address": "10.0.0.10"}]
    data["spec"]["adapters"]["enabled"] = ["boulder"]
    result = validate_config(data)
    assert any("lab-only" in error for error in result.errors)


@pytest.mark.parametrize("nodes", [None, "node-01", ["node-01"], [{"name": "node-01"}]])
def test_malformed_nodes_return_schema_errors(nodes: object) -> None:
    data = sample()
    data["spec"]["platform"]["nodes"] = nodes
    assert any("Schema:" in error for error in validate_config(data).errors)


@pytest.mark.parametrize("section", [None, "enabled", [True]])
def test_malformed_addons_return_errors_instead_of_crashing(section: object) -> None:
    data = sample()
    data["spec"]["addons"]["certManager"] = section
    assert any("must be a mapping" in error for error in validate_config(data).errors)


def test_string_false_cannot_bypass_production_encryption_control() -> None:
    data = sample()
    data["spec"]["rke2"]["secretsEncryption"] = "false"
    assert any("must be a boolean" in error for error in validate_config(data).errors)


def test_deployment_requires_a_target_node() -> None:
    data = sample()
    data["spec"]["platform"]["nodes"] = []
    assert any("At least one deployment node" in error for error in validate_config(data).errors)


def test_unsupported_ipv6_ha_fails_before_rendering_ipv4_firewall_rules() -> None:
    data = sample()
    data["spec"]["platform"]["nodes"][0]["address"] = "2001:db8::1"
    data["spec"]["platform"]["network"]["managementCidrs"] = ["2001:db8::/64"]
    errors = validate_config(data).errors
    assert any("requires an IPv4 address" in error for error in errors)
    assert any("IPv4 CIDRs" in error for error in errors)


def test_external_load_balancer_can_use_conventional_api_ports() -> None:
    data = sample()
    data["spec"]["platform"]["loadBalancer"].update(enabled=False, provider="external")
    data["spec"]["platform"]["vip"]["ports"].update(api=6443, registration=9345)
    assert validate_config(data).errors == []


def test_non_colocated_managed_load_balancer_is_rejected() -> None:
    data = sample()
    data["spec"]["platform"]["loadBalancer"]["colocated"] = False
    assert any(
        "currently runs on cluster servers" in error for error in validate_config(data).errors
    )


@pytest.mark.parametrize("version", [None, "", "latest", "stable", 1.33])
def test_production_cluster_version_must_be_pinned(version: object) -> None:
    data = sample()
    data["spec"]["versions"]["rke2"] = version
    assert validate_config(data).errors


def test_production_helm_checksum_is_required() -> None:
    data = sample()
    del data["spec"]["versions"]["helmChecksums"]
    assert any("Helm archive SHA-256" in error for error in validate_config(data).errors)


def test_empty_s3_credentials_file_is_rejected(tmp_path: Path) -> None:
    data = sample()
    secret_file = tmp_path / "empty-s3.env"
    secret_file.write_text("", encoding="utf-8")
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    assert any("must not be empty" in error for error in validate_config(data).errors)


@pytest.mark.parametrize("key", ["etcd-s3-insecure", "etcd-s3-skip-ssl-verify"])
@pytest.mark.parametrize(
    "value", ["true", "True", "TRUE", "1", "t", "T", '"false"', "false ", "", "false #comment"]
)
def test_production_snapshot_transport_cannot_disable_or_ambiguate_tls(
    tmp_path: Path, key: str, value: str
) -> None:
    data = sample()
    secret_file = tmp_path / "s3.env"
    secret_file.write_text(f"etcd-s3-secret-key=private-canary\n{key}={value}", encoding="utf-8")
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    errors = validate_config(data).errors
    assert f"Production RKE2 S3 configuration requires {key}=false" in errors
    assert "private-canary" not in "\n".join(errors)


@pytest.mark.parametrize("value", ["false", "False", "FALSE", "0", "f", "F"])
def test_production_snapshot_explicit_verified_tls_accepts_go_false_values(
    tmp_path: Path, value: str
) -> None:
    data = sample()
    secret_file = tmp_path / "s3.env"
    secret_file.write_bytes(
        (
            "\ufeff# Synthetic credentials\r\n\r\n"
            "  etcd-s3-secret-key=synthetic=secret==\r\n"
            f"etcd-s3-insecure={value}\r\n"
            f"etcd-s3-skip-ssl-verify={value}\r\n"
        ).encode()
    )
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    assert validate_config(data).errors == []


@pytest.mark.parametrize(
    "content",
    [
        "etcd-s3-insecure",
        "etcd-s3-skip-ssl-verify",
        "etcd-s3-secret-key",
        "etcd-s3-insecure =false",
        "private-canary invalid-key=false",
        "etcd-s3-insecure=false\netcd-s3-insecure=false",
        "etcd-s3-skip-ssl-verify=false\netcd-s3-skip-ssl-verify=true",
        "# comments alone do not configure backups\n",
        "etcd-s3-insecure=false\retcd-s3-skip-ssl-verify=true",
    ],
)
def test_production_snapshot_file_rejects_implicit_malformed_or_duplicate_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str
) -> None:
    # A bare env-file key must never import a controller/remote environment value.
    monkeypatch.setenv("etcd-s3-insecure", "true")
    data = sample()
    secret_file = tmp_path / "s3.env"
    secret_file.write_bytes(content.encode("utf-8"))
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    errors = validate_config(data).errors
    assert errors and all("S3 configuration" in e for e in errors)
    assert "private-canary" not in "\n".join(errors)


@pytest.mark.parametrize("environment", ["production", "development"])
def test_snapshot_tls_defaults_remain_valid_without_explicit_switches(
    tmp_path: Path, environment: str
) -> None:
    data = sample()
    data["spec"]["environment"] = environment
    secret_file = tmp_path / "s3.env"
    secret_file.write_text("etcd-s3-bucket=synthetic-backups\n", encoding="utf-8")
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    assert validate_config(data).errors == []


def test_development_can_explicitly_select_local_insecure_snapshot_transport(
    tmp_path: Path,
) -> None:
    data = sample()
    data["spec"]["environment"] = "development"
    secret_file = tmp_path / "s3.env"
    secret_file.write_text("etcd-s3-insecure=true\n", encoding="utf-8")
    data["spec"]["rke2"]["etcdSnapshots"]["s3"]["configSecretFile"] = str(secret_file)
    assert validate_config(data).errors == []


@pytest.mark.parametrize("issuer", ["letsEncryptStaging", "letsEncryptProduction", "internalCa"])
def test_unimplemented_issuer_automation_cannot_silently_succeed(issuer: str) -> None:
    data = sample()
    data["spec"]["addons"]["issuers"][issuer]["enabled"] = True
    data["spec"]["addons"]["issuers"][issuer]["email"] = 123
    assert any(
        f"Managed issuer {issuer} is not implemented" in error
        for error in validate_config(data).errors
    )
