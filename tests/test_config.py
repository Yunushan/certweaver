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


def test_lab_adapter_requires_acknowledgement() -> None:
    data = sample()
    data["spec"]["mode"] = "docker"
    data["spec"]["platform"]["nodes"] = [{"name": "docker-01", "address": "10.0.0.10"}]
    data["spec"]["adapters"]["enabled"] = ["boulder"]
    result = validate_config(data)
    assert any("lab-only" in error for error in result.errors)
