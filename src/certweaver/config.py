from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .errors import ConfigurationError
from .registry import load_registry, project_root

VALID_MODES = {
    "rke2-ha",
    "k3s-ha",
    "existing-kubernetes",
    "standalone",
    "docker",
    "raw",
    "windows",
}


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def require_ok(self) -> None:
        if self.errors:
            raise ConfigurationError("\n".join(self.errors))


def load_config(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"Unable to read configuration {source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a mapping")
    data["__source_path__"] = str(source.resolve())
    return data


def _get(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _validate_cidr_list(values: list[str], label: str, result: ValidationResult) -> None:
    for value in values:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            result.errors.append(f"{label} contains an invalid CIDR: {value!r}")


def _is_any_network(value: str) -> bool:
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen == 0
    except ValueError:
        return False


def _looks_placeholder(value: str | None) -> bool:
    if not value:
        return True
    lowered = value.lower()
    return (
        "replace" in lowered
        or "example." in lowered
        or lowered.endswith(".invalid")
        or lowered.endswith("@example.invalid")
    )


def validate_config(data: dict[str, Any]) -> ValidationResult:
    result = ValidationResult()
    schema_file = project_root() / "config" / "certweaver.schema.json"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
    clean_data = {k: v for k, v in data.items() if not k.startswith("__")}
    for error in sorted(Draft202012Validator(schema).iter_errors(clean_data), key=str):
        location = ".".join(str(p) for p in error.absolute_path) or "<root>"
        result.errors.append(f"Schema: {location}: {error.message}")

    mode = _get(data, "spec.mode")
    environment = _get(data, "spec.environment", "production")
    if mode not in VALID_MODES:
        result.errors.append(f"Unsupported deployment mode: {mode!r}")
        return result

    nodes = _get(data, "spec.platform.nodes", []) or []
    names = [node.get("name") for node in nodes]
    addresses = [node.get("address") for node in nodes]
    priorities = [
        node.get("keepalivedPriority")
        for node in nodes
        if node.get("keepalivedPriority") is not None
    ]
    if len(names) != len(set(names)):
        result.errors.append("Node names must be unique")
    if len(addresses) != len(set(addresses)):
        result.errors.append("Node addresses must be unique")
    if len(priorities) != len(set(priorities)):
        result.errors.append("Keepalived priorities must be unique")

    management_cidrs = _get(data, "spec.platform.network.managementCidrs", []) or []
    ingress_cidrs = _get(data, "spec.platform.network.ingressCidrs", ["0.0.0.0/0"]) or []
    _validate_cidr_list(management_cidrs, "managementCidrs", result)
    _validate_cidr_list(ingress_cidrs, "ingressCidrs", result)
    if environment == "production" and any(_is_any_network(cidr) for cidr in management_cidrs):
        result.errors.append("Production managementCidrs must not allow 0.0.0.0/0 or ::/0")

    if mode in {"rke2-ha", "k3s-ha"}:
        if environment == "production" and len(nodes) < 3:
            result.errors.append("Production HA mode requires at least three server nodes")
        if nodes and len(nodes) % 2 == 0:
            result.errors.append("Embedded-etcd server count must be odd")

        lb_enabled = _get(data, "spec.platform.loadBalancer.enabled", True)
        lb_colocated = _get(data, "spec.platform.loadBalancer.colocated", True)
        vip = _get(data, "spec.platform.vip.address")
        vip_interface = _get(data, "spec.platform.vip.interface")
        if lb_enabled and not vip:
            result.errors.append("HA mode with the managed load balancer requires a VIP address")
        if lb_enabled and lb_colocated and not vip_interface:
            result.errors.append("Co-located Keepalived requires spec.platform.vip.interface")
        try:
            if vip:
                ipaddress.ip_address(vip)
        except ValueError:
            result.errors.append(f"VIP address is invalid: {vip!r}")
        if vip and vip in addresses:
            result.errors.append("VIP must not be identical to a node address")

        frontend_ports = {
            "api": _get(data, "spec.platform.vip.ports.api", 8443),
            "registration": _get(data, "spec.platform.vip.ports.registration", 9346),
            "http": _get(data, "spec.platform.vip.ports.http", 80),
            "https": _get(data, "spec.platform.vip.ports.https", 443),
        }
        enabled_frontends = ["api", "registration"]
        if _get(data, "spec.addons.traefik.enabled", False):
            enabled_frontends.extend(["http", "https"])
        used = [frontend_ports[name] for name in enabled_frontends]
        if len(used) != len(set(used)):
            result.errors.append("Enabled VIP frontend ports must be unique")

        if lb_colocated:
            api_port = frontend_ports["api"]
            registration_port = frontend_ports["registration"]
            if api_port == 6443:
                result.errors.append(
                    "Co-located HAProxy cannot bind VIP port 6443 while the Kubernetes API "
                    "binds 0.0.0.0:6443; use 8443 or a dedicated load balancer"
                )
            if mode == "rke2-ha" and registration_port == 9345:
                result.errors.append(
                    "Co-located HAProxy cannot bind VIP port 9345 while RKE2 binds "
                    "0.0.0.0:9345; use 9346 or a dedicated load balancer"
                )
            if mode == "k3s-ha" and registration_port == 6443:
                result.errors.append(
                    "Co-located HAProxy cannot bind the K3s registration frontend to 6443; "
                    "use 9346 or a dedicated load balancer"
                )

        manage_firewalld = _get(data, "spec.platform.network.manageFirewalld", True)
        if environment == "production" and manage_firewalld and not management_cidrs:
            result.errors.append(
                "Production HA with managed firewalld requires at least one management CIDR"
            )
        if environment == "production":
            if mode == "rke2-ha":
                if not _get(data, "spec.rke2.secretsEncryption", True):
                    result.errors.append("Production RKE2 requires secrets encryption")
                if not _get(data, "spec.rke2.auditPolicy", True):
                    result.errors.append("Production RKE2 requires Kubernetes audit logging")
                if not _get(data, "spec.rke2.etcdSnapshots.enabled", True):
                    result.errors.append("Production RKE2 requires scheduled etcd snapshots")
                if not _get(data, "spec.rke2.protectKernelDefaults", False):
                    result.warnings.append(
                        "Production RKE2 should enable protectKernelDefaults after applying "
                        "the matching CIS/sysctl baseline"
                    )
            if mode == "k3s-ha":
                if not _get(data, "spec.k3s.secretsEncryption", True):
                    result.errors.append("Production K3s requires secrets encryption")
                if not _get(data, "spec.k3s.protectKernelDefaults", False):
                    result.warnings.append(
                        "Production K3s should enable protectKernelDefaults after applying "
                        "the matching CIS/sysctl baseline"
                    )

    adapters = load_registry()
    enabled = _get(data, "spec.adapters.enabled", []) or []
    acknowledgements = set(_get(data, "spec.adapters.acknowledge", []) or [])
    for slug in enabled:
        adapter = adapters.get(slug)
        if not adapter:
            result.errors.append(f"Unknown adapter: {slug}")
            continue
        if mode not in adapter.modes:
            result.errors.append(f"Adapter {slug} does not support deployment mode {mode}")
        if adapter.maturity in {"lab-only", "legacy"} and slug not in acknowledgements:
            result.errors.append(
                f"Adapter {slug} is marked {adapter.maturity}; add it to "
                "spec.adapters.acknowledge after reviewing its risk"
            )

    if mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}:
        cert_manager_enabled = _get(data, "spec.addons.certManager.enabled", False)
        if "cert-manager" not in enabled:
            result.warnings.append("Kubernetes mode does not enable cert-manager")
        if _get(data, "spec.addons.approverPolicy.enabled", False) and not cert_manager_enabled:
            result.errors.append("approver-policy requires spec.addons.certManager.enabled")
        if _get(data, "spec.addons.trustManager.enabled", False) and not cert_manager_enabled:
            result.errors.append("trust-manager requires spec.addons.certManager.enabled")
        if _get(data, "spec.addons.csiDriver.enabled", False) and not cert_manager_enabled:
            result.errors.append("cert-manager CSI Driver requires spec.addons.certManager.enabled")
        if _get(data, "spec.addons.approverPolicy.enabled", False) and not _get(
            data, "spec.addons.certManager.disableAutoApproval", False
        ):
            result.errors.append(
                "approver-policy requires cert-manager automatic approval to be disabled"
            )
        if environment == "production" and cert_manager_enabled and not _get(
            data, "spec.addons.certManager.disableAutoApproval", False
        ):
            result.errors.append(
                "Production cert-manager deployments must disable automatic approval"
            )
        if (
            "traefik-acme" in enabled
            and _get(data, "spec.adapters.options.traefik-acme.resolverEnabled", False)
            and cert_manager_enabled
        ):
            result.errors.append(
                "Traefik ACME resolver must stay disabled when cert-manager owns certificates"
            )

        issuer_base = "spec.addons.issuers"
        for issuer in ("letsEncryptStaging", "letsEncryptProduction"):
            if _get(data, f"{issuer_base}.{issuer}.enabled", False):
                email = _get(data, f"{issuer_base}.{issuer}.email")
                if _looks_placeholder(email):
                    result.errors.append(
                        f"{issuer} requires a real operator email before production use"
                    )
        if _get(data, f"{issuer_base}.internalCa.enabled", False):
            provider = _get(data, f"{issuer_base}.internalCa.provider")
            provider_adapters = {
                "step-ca": "step-ca",
                "openbao": "openbao-pki",
                "openbao-pki": "openbao-pki",
                "ejbca": "ejbca-community",
                "ejbca-community": "ejbca-community",
            }
            provider_adapter = provider_adapters.get(str(provider))
            if provider_adapter and provider_adapter not in enabled:
                result.warnings.append(
                    f"Internal CA provider {provider!r} is not enabled as a local adapter; "
                    "verify that an external issuer endpoint is configured"
                )

    source = Path(data.get("__source_path__", ".")).parent
    secret_fields: tuple[str, ...] = ()
    if mode in {"rke2-ha", "k3s-ha"}:
        secret_fields = (
            "spec.secrets.rke2TokenFile",
            "spec.secrets.keepalivedAuthFile",
        )
    for dotted in secret_fields:
        value = _get(data, dotted)
        if not value:
            continue
        secret_path = source / value
        if not secret_path.exists():
            result.warnings.append(f"Secret file does not exist yet: {value}")
            continue
        try:
            secret = secret_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            result.errors.append(f"Unable to read secret file {value}: {exc}")
            continue
        if dotted.endswith("rke2TokenFile") and len(secret) < 16:
            result.errors.append("RKE2 token file must contain at least 16 characters")
        if dotted.endswith("keepalivedAuthFile") and len(secret) < 8:
            result.errors.append("Keepalived auth file must contain at least 8 characters")

    versions = _get(data, "spec.versions", {}) or {}
    if environment == "production":
        required_versions: list[str] = []
        if mode == "rke2-ha":
            required_versions.extend(["rke2", "helm"])
        elif mode == "k3s-ha":
            required_versions.extend(["k3s", "helm"])
        elif mode == "existing-kubernetes":
            required_versions.append("helm")
        if mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}:
            addon_version_keys = {
                "certManager": "certManager",
                "approverPolicy": "approverPolicy",
                "trustManager": "trustManager",
                "csiDriver": "csiDriver",
                "traefik": "traefikChart",
            }
            for addon, version_key in addon_version_keys.items():
                if _get(data, f"spec.addons.{addon}.enabled", False):
                    required_versions.append(version_key)
        for required in dict.fromkeys(required_versions):
            value = versions.get(required)
            if value in (None, "", "latest"):
                result.warnings.append(
                    f"Production deployment should pin spec.versions.{required}"
                )
        if (
            mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}
            and not versions.get("helmChecksum")
            and not versions.get("helmChecksums")
        ):
            result.warnings.append(
                "Production Kubernetes deployment should pin a Helm archive SHA-256 checksum"
            )

    return result
