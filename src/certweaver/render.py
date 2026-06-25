from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from .config import _get
from .registry import load_registry


class _IndentDumper(yaml.SafeDumper):
    """Emit readable, indented block sequences for generated inventories."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _resolve_secret(config: dict[str, Any], value: str | None) -> str | None:
    if not value:
        return value
    source = Path(config.get("__source_path__", ".")).parent
    return str((source / value).resolve())


def _adapter_version_defaults() -> dict[str, str]:
    """Return the stable public variable names consumed by adapter roles."""
    return {
        "step_ca": "",
        "step_ca_chart": "",
        "openbao_chart": "",
        "openbao_image": "",
        "acme_sh_ref": "",
        "certbot": "",
        "ejbca_image": "",
        "lego": "",
        "dogtag": "",
        "freeipa": "",
        "cfssl": "",
        "dehydrated_ref": "",
        "spire_chart": "",
        "boulder_ref": "",
        "caddy": "",
        "traefik": "",
        "lemur_ref": "",
        "win_acme": "",
        "posh_acme": "",
    }


def inventory_from_config(config: dict[str, Any]) -> dict[str, Any]:
    spec = config["spec"]
    mode = spec["mode"]
    platform = spec.get("platform", {})
    vip = platform.get("vip", {})
    lb = platform.get("loadBalancer", {})
    versions = spec.get("versions", {})
    secrets = spec.get("secrets", {})
    addons = deepcopy(spec.get("addons", {}))
    adapters = spec.get("adapters", {})
    rke2 = spec.get("rke2", {})
    k3s = spec.get("k3s", {})
    network = platform.get("network", {})

    if versions.get("traefikChart"):
        addons.setdefault("traefik", {}).setdefault("chartVersion", versions["traefikChart"])

    adapter_versions = _adapter_version_defaults()
    adapter_versions.update(adapters.get("versions", {}))

    common_vars = {
        "certweaver_mode": mode,
        "certweaver_environment": spec.get("environment", "production"),
        "certweaver_vip": vip.get("address"),
        "certweaver_vip_dns": vip.get("dnsName", ""),
        "certweaver_vip_interface": vip.get("interface"),
        "certweaver_vip_prefix_length": vip.get("prefixLength", 24),
        "certweaver_api_front_port": vip.get("ports", {}).get("api", 8443),
        "certweaver_registration_front_port": vip.get("ports", {}).get(
            "registration", 9346
        ),
        "certweaver_http_front_port": vip.get("ports", {}).get("http", 80),
        "certweaver_https_front_port": vip.get("ports", {}).get("https", 443),
        "certweaver_ingress_http_nodeport": lb.get("ingressNodePorts", {}).get(
            "http", 30080
        ),
        "certweaver_ingress_https_nodeport": lb.get("ingressNodePorts", {}).get(
            "https", 30443
        ),
        "certweaver_load_balancer_enabled": lb.get("enabled", True),
        "certweaver_load_balancer_colocated": lb.get("colocated", True),
        "certweaver_keepalived_router_id": lb.get("virtualRouterId", 51),
        "certweaver_manage_firewalld": network.get("manageFirewalld", True),
        "certweaver_management_cidrs": network.get("managementCidrs", []),
        "certweaver_ingress_cidrs": network.get("ingressCidrs", ["0.0.0.0/0"]),
        "certweaver_keepalived_auth_file": _resolve_secret(
            config, secrets.get("keepalivedAuthFile")
        ),
        "certweaver_rke2_token_file": _resolve_secret(config, secrets.get("rke2TokenFile")),
        "certweaver_rke2_version": versions.get("rke2"),
        "certweaver_k3s_version": versions.get("k3s"),
        "certweaver_helm_version": versions.get("helm", "v3.21.2"),
        "certweaver_helm_checksum": versions.get("helmChecksum", ""),
        "certweaver_helm_checksums": versions.get("helmChecksums", {}),
        "certweaver_cert_manager_version": versions.get("certManager"),
        "certweaver_approver_policy_version": versions.get("approverPolicy"),
        "certweaver_trust_manager_version": versions.get("trustManager"),
        "certweaver_csi_driver_version": versions.get("csiDriver"),
        "certweaver_addons": addons,
        "certweaver_enabled_adapters": adapters.get("enabled", []),
        "certweaver_adapter_install_mode": adapters.get("installMode", "auto"),
        "certweaver_adapter_start_services": adapters.get("startServices", False),
        "certweaver_adapter_options": adapters.get("options", {}),
        "certweaver_adapter_versions": adapter_versions,
        "certweaver_adapter_checksums": adapters.get("checksums", {}),
        "certweaver_allow_risky_adapters": adapters.get("acknowledge", []),
        "certweaver_cluster_name": config.get("metadata", {}).get(
            "name", "certweaver"
        ),
        "certweaver_rke2_cni": rke2.get("cni", "canal"),
        "certweaver_rke2_selinux": rke2.get("selinux", True),
        "certweaver_rke2_secrets_encryption": rke2.get("secretsEncryption", True),
        "certweaver_rke2_audit_enabled": rke2.get("auditPolicy", True),
        "certweaver_rke2_protect_kernel_defaults": rke2.get(
            "protectKernelDefaults", False
        ),
        "certweaver_rke2_disable_components": (
            ["rke2-ingress-nginx"] if rke2.get("disablePackagedIngress", True) else []
        ),
        "certweaver_rke2_etcd_snapshot_enabled": rke2.get("etcdSnapshots", {}).get(
            "enabled", True
        ),
        "certweaver_rke2_etcd_snapshot_schedule": rke2.get("etcdSnapshots", {}).get(
            "scheduleCron", "0 */6 * * *"
        ),
        "certweaver_rke2_etcd_snapshot_retention": rke2.get("etcdSnapshots", {}).get(
            "retention", 28
        ),
        "certweaver_k3s_selinux": k3s.get("selinux", True),
        "certweaver_k3s_secrets_encryption": k3s.get("secretsEncryption", True),
        "certweaver_k3s_protect_kernel_defaults": k3s.get(
            "protectKernelDefaults", False
        ),
        "certweaver_existing_kubeconfig_source": platform.get(
            "existingKubeconfig", "/root/.kube/config"
        ),
        "certweaver_fetch_kubeconfig": platform.get(
            "fetchKubeconfig", mode in {"rke2-ha", "k3s-ha"}
        ),
        "certweaver_win_acme_version": adapter_versions.get("win_acme", ""),
        "certweaver_win_acme_url": adapters.get("options", {})
        .get("win-acme", {})
        .get("downloadUrl", ""),
        "certweaver_win_acme_checksum": adapters.get("checksums", {}).get(
            "win_acme", ""
        ),
        "certweaver_posh_acme_repository": adapters.get("options", {})
        .get("posh-acme", {})
        .get("repository", "PSGallery"),
    }

    all_hosts: dict[str, Any] = {}
    bootstrap_hosts: dict[str, Any] = {}
    joiner_hosts: dict[str, Any] = {}
    for idx, node in enumerate(platform.get("nodes", [])):
        host_vars: dict[str, Any] = {
            "ansible_host": node["address"],
            "ansible_user": node.get("ansibleUser", node.get("sshUser", "rocky")),
            "ansible_port": node.get("sshPort", 22),
            "keepalived_priority": node.get("keepalivedPriority", 150 - idx * 10),
            "certweaver_node_interface": node.get("interface", vip.get("interface")),
        }
        if mode == "windows":
            host_vars.update(
                {
                    "ansible_connection": node.get("connection", "winrm"),
                    "ansible_port": node.get("winrmPort", 5986),
                    "ansible_winrm_transport": node.get("winrmTransport", "ntlm"),
                    "ansible_winrm_server_cert_validation": node.get(
                        "winrmServerCertValidation", "validate"
                    ),
                }
            )
        all_hosts[node["name"]] = host_vars
        (bootstrap_hosts if idx == 0 else joiner_hosts)[node["name"]] = {}

    children: dict[str, Any] = {}
    if mode in {"rke2-ha", "k3s-ha"}:
        children.update(
            {
                "cluster_servers": {"hosts": all_hosts},
                "cluster_bootstrap": {"hosts": bootstrap_hosts},
                "cluster_joiners": {"hosts": joiner_hosts},
                "pki_linux": {"hosts": all_hosts},
            }
        )
    elif mode == "existing-kubernetes":
        children.update(
            {
                "cluster_bootstrap": {"hosts": bootstrap_hosts or all_hosts},
                "pki_linux": {"hosts": all_hosts},
            }
        )
    elif mode == "windows":
        children["pki_windows"] = {"hosts": all_hosts}
    else:
        children["pki_linux"] = {"hosts": all_hosts}

    return {"all": {"vars": common_vars, "children": children}}


def write_inventory(config: dict[str, Any], destination: str | Path) -> Path:
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.dump(
            inventory_from_config(config),
            Dumper=_IndentDumper,
            sort_keys=False,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    return target


def execution_plan(config: dict[str, Any]) -> list[str]:
    mode = _get(config, "spec.mode")
    enabled = _get(config, "spec.adapters.enabled", []) or []
    registry = load_registry()
    plan = [f"Mode: {mode}"]
    if mode in {"rke2-ha", "k3s-ha"}:
        nodes = _get(config, "spec.platform.nodes", [])
        vip = _get(config, "spec.platform.vip.address")
        plan.extend(
            [
                f"Prepare {len(nodes)} Linux server nodes",
                f"Configure HAProxy + Keepalived with floating VIP {vip}",
                f"Bootstrap first {mode.split('-')[0].upper()} server",
                "Join remaining servers serially and confirm quorum",
                "Create external kubeconfig pointing to the VIP API endpoint",
                "Install cert-manager platform add-ons with pinned charts",
            ]
        )
    elif mode == "existing-kubernetes":
        plan.append("Validate the supplied kubeconfig and install cluster add-ons")
    else:
        plan.append("Prepare target hosts for selected adapters")
    for slug in enabled:
        adapter = registry.get(slug)
        if adapter:
            plan.append(f"Install/configure {adapter.name} [{adapter.maturity}]")
    plan.append("Run smoke tests and produce a sanitized deployment report")
    return plan
