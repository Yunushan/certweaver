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
    assert inventory["all"]["vars"]["certweaver_rke2_install_script_checksum"].startswith(
        "sha256:"
    )
    assert inventory["all"]["vars"]["certweaver_rke2_etcd_s3_enabled"] is True


def test_plan_includes_all_enabled_adapters() -> None:
    config = load_config(project_root() / "config" / "certweaver.example.yml")
    plan = "\n".join(execution_plan(config))
    assert "cert-manager" in plan
    assert "trust-manager" in plan
    assert "Traefik" in plan
