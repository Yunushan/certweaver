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


def test_lab_adapter_requires_acknowledgement() -> None:
    data = sample()
    data["spec"]["mode"] = "docker"
    data["spec"]["platform"]["nodes"] = [{"name": "docker-01", "address": "10.0.0.10"}]
    data["spec"]["adapters"]["enabled"] = ["boulder"]
    result = validate_config(data)
    assert any("lab-only" in error for error in result.errors)
