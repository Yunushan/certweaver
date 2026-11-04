from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .errors import ConfigurationError
from .registry import load_registry, project_root
from .snapshot import SnapshotConfigurationError
from .snapshot import validate_file as validate_snapshot_file

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
    except (OSError, UnicodeError) as exc:
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


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"sha256:[a-fA-F0-9]{64}", value))


def _managed_cluster_version_issues(data: dict[str, Any]) -> list[str]:
    mode = _get(data, "spec.mode")
    if mode not in {"rke2-ha", "k3s-ha"}:
        return []
    product, suffix = ("rke2", "rke2r") if mode == "rke2-ha" else ("k3s", "k3s")
    selected = _get(data, f"spec.versions.{product}")
    if (
        not isinstance(selected, str)
        or len(selected) > 100
        or not re.fullmatch(
            rf"v1\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\+{suffix}[1-9][0-9]*", selected
        )
    ):
        return [
            f"Managed {product} requires a literal stable Kubernetes 1.x release "
            f"with its distribution revision in spec.versions.{product}"
        ]
    return []


def _chart_acquisition_issues(data: dict[str, Any]) -> list[str]:
    mode = _get(data, "spec.mode")
    cluster_modes = {"rke2-ha", "k3s-ha", "existing-kubernetes"}
    issues = []
    requirements = []
    if mode in cluster_modes:
        versions = _get(data, "spec.versions", {})
        checksums = versions.get("chartChecksums", {})
        for addon, version_key in {
            "certManager": "certManager",
            "approverPolicy": "approverPolicy",
            "trustManager": "trustManager",
            "csiDriver": "csiDriver",
            "traefik": "traefikChart",
        }.items():
            if _get(data, f"spec.addons.{addon}.enabled", False):
                version = versions.get(version_key, "")
                if addon == "traefik":
                    version = _get(data, "spec.addons.traefik.chartVersion", version)
                requirements.append(
                    (
                        f"spec.versions.{version_key}",
                        version,
                        f"spec.versions.chartChecksums.{addon}",
                        checksums.get(addon),
                    )
                )
    enabled = _get(data, "spec.adapters.enabled", [])
    options = _get(data, "spec.adapters.options", {})
    adapter_charts = []
    for slug, key, fallback in [
        (
            "step-ca",
            "step_ca_chart",
            "kubernetes"
            if mode in cluster_modes
            else "docker"
            if mode == "docker"
            else "standalone",
        ),
        ("openbao-pki", "openbao_chart", "kubernetes" if mode in cluster_modes else "docker"),
    ]:
        if slug in enabled and options.get(slug, {}).get("installMode", fallback) == "kubernetes":
            adapter_charts.append(key)
    if "spire" in enabled and mode in cluster_modes:
        adapter_charts.extend(["spire_crds_chart", "spire_chart"])
    versions = _get(data, "spec.adapters.versions", {})
    checksums = _get(data, "spec.adapters.checksums", {})
    requirements.extend(
        (
            f"spec.adapters.versions.{key}",
            versions.get(key, ""),
            f"spec.adapters.checksums.{key}",
            checksums.get(key),
        )
        for key in adapter_charts
    )
    for version_path, version, checksum_path, checksum in requirements:
        if not isinstance(version, str) or not re.fullmatch(
            r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?", version
        ):
            issues.append(f"Chart requires a literal release version in {version_path}")
        if not _is_sha256(checksum):
            issues.append(f"Chart requires a reviewed SHA-256 archive identity in {checksum_path}")
    return issues


def _adapter_acquisition_issues(data: dict[str, Any]) -> list[str]:
    mode = _get(data, "spec.mode")
    enabled = set(_get(data, "spec.adapters.enabled", []))
    versions = _get(data, "spec.adapters.versions", {})
    checksums = _get(data, "spec.adapters.checksums", {})
    options = _get(data, "spec.adapters.options", {})
    requirements = {
        slug: key
        for slug, key in {
            "lego": "lego",
            "caddy-auto-https": "caddy",
            "cfssl": "cfssl",
        }.items()
        if slug in enabled
    }
    if "traefik-acme" in enabled and mode in {"standalone", "raw", "docker"}:
        requirements["traefik-acme"] = "traefik"
    cluster_modes = {"rke2-ha", "k3s-ha", "existing-kubernetes"}
    step_mode = options.get("step-ca", {}).get(
        "installMode",
        "kubernetes" if mode in cluster_modes else "docker" if mode == "docker" else "standalone",
    )
    if "step-ca" in enabled and step_mode == "standalone":
        requirements["step-ca"] = "step_ca"
    issues = []
    for slug, key in {
        "acme-sh": "acme_sh_ref",
        "dehydrated": "dehydrated_ref",
        "boulder": "boulder_ref",
        "lemur": "lemur_ref",
    }.items():
        if slug in enabled and not re.fullmatch(r"[a-f0-9]{40}", versions.get(key, "")):
            issues.append(
                f"Adapter {slug} requires a reviewed full lowercase Git commit "
                f"in spec.adapters.versions.{key}; "
                "branches, tags and abbreviated refs are not accepted"
            )
    image_requirements = {}
    if "step-ca" in enabled and step_mode == "docker":
        image_requirements["step-ca"] = "step_ca_image"
    openbao_mode = options.get("openbao-pki", {}).get(
        "installMode", "kubernetes" if mode in cluster_modes else "docker"
    )
    if "openbao-pki" in enabled and openbao_mode == "docker":
        image_requirements["openbao-pki"] = "openbao_image"
    if "ejbca-community" in enabled:
        image_requirements["ejbca-community"] = "ejbca_image"
    for slug, key in image_requirements.items():
        if not _is_sha256(versions.get(key, "")):
            issues.append(
                f"Adapter {slug} requires a reviewed SHA-256 image digest "
                f"in spec.adapters.versions.{key}; image tags are mutable"
            )
    for slug, key in requirements.items():
        if not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?", versions.get(key, "")
        ):
            issues.append(
                f"Adapter {slug} requires a reviewed numeric release version "
                f"in spec.adapters.versions.{key}"
            )
        components = ("cfssl", "cfssljson", "cfssl-bundle") if key == "cfssl" else (key,)
        for component in components:
            values = [
                checksums[name]
                for name in (component, component + "_amd64", component + "_arm64")
                if name in checksums
            ]
            if not values or not all(_is_sha256(value) for value in values):
                issues.append(
                    f"Adapter {slug} requires a reviewed SHA-256 in "
                    f"spec.adapters.checksums.{component} (or an architecture-specific key)"
                )
    if "win-acme" in enabled:
        checksum = checksums.get("win_acme", "")
        if not (_is_sha256(checksum) or re.fullmatch(r"[a-fA-F0-9]{64}", checksum)):
            issues.append(
                "Adapter win-acme requires a reviewed SHA-256 in spec.adapters.checksums.win_acme"
            )
        if not re.fullmatch(
            r"v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?",
            versions.get("win_acme", ""),
        ):
            issues.append(
                "Adapter win-acme requires a reviewed numeric release version "
                "in spec.adapters.versions.win_acme"
            )
        download_url = options.get("win-acme", {}).get("downloadUrl", "")
        if not isinstance(download_url, str) or not re.match(r"https://[^/]+/", download_url):
            issues.append("Adapter win-acme requires an HTTPS release downloadUrl")
    if "posh-acme" in enabled and not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,3}", versions.get("posh_acme", "")
    ):
        issues.append(
            "Adapter posh-acme requires a reviewed numeric spec.adapters.versions.posh_acme"
        )
    return issues


def validate_config(data: dict[str, Any], *, for_deployment: bool = False) -> ValidationResult:
    result = ValidationResult()
    schema_file = project_root() / "config" / "certweaver.schema.json"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
    clean_data = {k: v for k, v in data.items() if not k.startswith("__")}
    for error in sorted(Draft202012Validator(schema).iter_errors(clean_data), key=str):
        location = ".".join(str(p) for p in error.absolute_path) or "<root>"
        result.errors.append(f"Schema: {location}: {error.message}")

    # Semantic checks and inventory rendering require the shapes established by
    # the schema. Report malformed input instead of raising an AttributeError.
    if result.errors:
        return result

    mapping_paths = [
        "spec.rke2.etcdSnapshots",
        "spec.rke2.etcdSnapshots.s3",
        "spec.addons.issuers",
        "spec.addons.issuers.letsEncryptStaging",
        "spec.addons.issuers.letsEncryptProduction",
        "spec.addons.issuers.internalCa",
    ]
    for section in ("addons", "adapters.options"):
        mapping_paths.extend(f"spec.{section}.{key}" for key in _get(data, f"spec.{section}", {}))
    missing = object()
    for dotted in mapping_paths:
        value = _get(data, dotted, missing)
        if value is not missing and not isinstance(value, dict):
            result.errors.append(f"{dotted} must be a mapping")
    boolean_paths = [
        "spec.rke2.secretsEncryption",
        "spec.rke2.auditPolicy",
        "spec.rke2.selinux",
        "spec.rke2.protectKernelDefaults",
        "spec.rke2.disablePackagedIngress",
        "spec.rke2.etcdSnapshots.enabled",
        "spec.rke2.etcdSnapshots.s3.enabled",
        "spec.k3s.secretsEncryption",
        "spec.k3s.selinux",
        "spec.k3s.protectKernelDefaults",
        "spec.addons.issuers.letsEncryptStaging.enabled",
        "spec.addons.issuers.letsEncryptProduction.enabled",
        "spec.addons.issuers.internalCa.enabled",
        "spec.addons.monitoring.prometheusRules",
        "spec.addons.trustManager.secretTargets",
    ]
    for addon in ("certManager", "approverPolicy", "trustManager", "csiDriver", "traefik"):
        boolean_paths.append(f"spec.addons.{addon}.enabled")
    boolean_paths.extend(
        f"spec.addons.certManager.{key}"
        for key in ("disableAutoApproval", "highAvailability", "networkPolicy", "prometheus")
    )
    for dotted in boolean_paths:
        value = _get(data, dotted, missing)
        if value is not missing and not isinstance(value, bool):
            result.errors.append(f"{dotted} must be a boolean")
    for dotted in (
        "spec.rke2.etcdSnapshots.s3.secretName",
        "spec.rke2.etcdSnapshots.s3.configSecretFile",
    ):
        value = _get(data, dotted, missing)
        if value is not missing and (not isinstance(value, str) or not value.strip()):
            result.errors.append(f"{dotted} must be a nonempty string")
    if result.errors:
        return result

    mode = _get(data, "spec.mode")
    environment = _get(data, "spec.environment", "production")
    if _get(data, "spec.platform.fetchKubeconfig", False) and mode not in {
        "rke2-ha",
        "k3s-ha",
        "existing-kubernetes",
    }:
        result.errors.append("Kubeconfig export requires a managed or existing Kubernetes mode")
    output = _get(data, "spec.platform.kubeconfigOutput")
    if output is not None and (
        not output.startswith(("/", "~/"))
        or output.endswith("/")
        or "//" in output
        or "\\" in output
        or "{" in output
        or "}" in output
        or any(ord(c) < 32 or ord(c) == 127 for c in output)
        or {".", ".."}.intersection(output.split("/"))
    ):
        result.errors.append("spec.platform.kubeconfigOutput requires a literal POSIX file path")
    if mode not in VALID_MODES:
        result.errors.append(f"Unsupported deployment mode: {mode!r}")
        return result

    nodes = _get(data, "spec.platform.nodes", []) or []
    if not nodes:
        result.errors.append("At least one deployment node is required")
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
        for node in nodes:
            try:
                address = ipaddress.ip_address(node["address"])
                if address.version != 4:
                    raise ValueError("IPv6 HA is not implemented")
            except ValueError:
                result.errors.append(
                    f"HA node {node['name']!r} requires an IPv4 address; "
                    "managed Keepalived and firewall rules currently support IPv4 only"
                )
        if environment == "production" and len(nodes) < 3:
            result.errors.append("Production HA mode requires at least three server nodes")
        if nodes and len(nodes) % 2 == 0:
            result.errors.append("Embedded-etcd server count must be odd")

        lb_enabled = _get(data, "spec.platform.loadBalancer.enabled", True)
        lb_colocated = _get(data, "spec.platform.loadBalancer.colocated", True)
        lb_provider = _get(data, "spec.platform.loadBalancer.provider", "haproxy-keepalived")
        if lb_enabled and (not lb_colocated or lb_provider == "external"):
            result.errors.append(
                "The managed load balancer currently runs on cluster servers; "
                "use colocated=true or disable it and supply an external VIP endpoint"
            )
        vip = _get(data, "spec.platform.vip.address")
        vip_interface = _get(data, "spec.platform.vip.interface")
        if not vip:
            result.errors.append("HA mode requires a managed or external VIP address")
        if lb_enabled and lb_colocated and not vip_interface:
            result.errors.append("Co-located Keepalived requires spec.platform.vip.interface")
        try:
            if vip and ipaddress.ip_address(vip).version != 4:
                raise ValueError("IPv6 HA is not implemented")
        except ValueError:
            result.errors.append(f"VIP address must be a valid IPv4 address: {vip!r}")
        if vip and vip in addresses:
            result.errors.append("VIP must not be identical to a node address")

        frontend_ports = {
            "api": _get(data, "spec.platform.vip.ports.api", 8443),
            "registration": _get(data, "spec.platform.vip.ports.registration", 9346),
            "http": _get(data, "spec.platform.vip.ports.http", 80),
            "https": _get(data, "spec.platform.vip.ports.https", 443),
        }
        enabled_frontends = ["api", "registration"]
        if (
            mode == "rke2-ha"
            and _get(data, "spec.addons.traefik.enabled", False)
            and not _get(data, "spec.rke2.disablePackagedIngress", True)
        ):
            result.errors.append(
                "Managed Traefik requires spec.rke2.disablePackagedIngress=true; "
                "review ingress ownership and migrate existing packaged controllers first"
            )
        if _get(data, "spec.addons.traefik.enabled", False):
            enabled_frontends.extend(["http", "https"])
        used = [frontend_ports[name] for name in enabled_frontends]
        if len(used) != len(set(used)):
            result.errors.append("Enabled VIP frontend ports must be unique")

        if lb_enabled and lb_colocated:
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
        if manage_firewalld:
            for cidr in [*management_cidrs, *ingress_cidrs]:
                try:
                    if ipaddress.ip_network(cidr, strict=False).version != 4:
                        result.errors.append(
                            "Managed HA firewall rules currently require IPv4 CIDRs"
                        )
                except ValueError:
                    pass  # Invalid syntax has already been reported above.
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
                snapshot_s3 = _get(data, "spec.rke2.etcdSnapshots.s3", {}) or {}
                if not snapshot_s3.get("enabled", False):
                    result.errors.append(
                        "Production RKE2 requires encrypted off-host etcd snapshot replication"
                    )
                elif not snapshot_s3.get("configSecretFile") or not snapshot_s3.get("secretName"):
                    result.errors.append(
                        "Production RKE2 S3 snapshots require configSecretFile and secretName"
                    )
                if not _get(data, "spec.rke2.protectKernelDefaults", False):
                    result.errors.append(
                        "Production RKE2 requires protectKernelDefaults after applying "
                        "the matching CIS/sysctl baseline"
                    )
            if mode == "k3s-ha":
                if not _get(data, "spec.k3s.secretsEncryption", True):
                    result.errors.append("Production K3s requires secrets encryption")
                if not _get(data, "spec.k3s.protectKernelDefaults", False):
                    result.errors.append(
                        "Production K3s requires protectKernelDefaults after applying "
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

    option_problem = False
    for slug, option in _get(data, "spec.adapters.options", {}).items():
        if not isinstance(option, dict):
            result.errors.append(f"spec.adapters.options.{slug} must be a mapping")
            option_problem = True
    for slug, modes in {
        "step-ca": ("standalone", "docker", "kubernetes"),
        "openbao-pki": ("docker", "kubernetes"),
    }.items():
        if (
            slug in enabled
            and _get(data, f"spec.adapters.options.{slug}.installMode", modes[0]) not in modes
        ):
            result.errors.append(f"{slug} installMode must be one of {', '.join(modes)}")
            option_problem = True
    if option_problem:
        return result
    acquisition_issues = (
        _adapter_acquisition_issues(data)
        + _chart_acquisition_issues(data)
        + _managed_cluster_version_issues(data)
    )
    if environment == "production" or for_deployment:
        result.errors.extend(acquisition_issues)
    else:
        result.warnings.extend(acquisition_issues)

    if mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}:
        cert_manager_enabled = _get(data, "spec.addons.certManager.enabled", False)
        for slug, addon in {
            "cert-manager": "certManager",
            "trust-manager": "trustManager",
            "cert-manager-csi-driver": "csiDriver",
            "traefik-acme": "traefik",
        }.items():
            if slug in enabled and not _get(data, f"spec.addons.{addon}.enabled", False):
                result.errors.append(f"Adapter {slug} requires enabled spec.addons.{addon}")
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
        if (
            environment == "production"
            and cert_manager_enabled
            and not _get(data, "spec.addons.certManager.disableAutoApproval", False)
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
        for issuer in ("letsEncryptStaging", "letsEncryptProduction", "internalCa"):
            if _get(data, f"{issuer_base}.{issuer}.enabled", False):
                result.errors.append(
                    f"Managed issuer {issuer} is not implemented; keep its enabled flag false "
                    "and provision a reviewed issuer manifest separately"
                )
    source = Path(data.get("__source_path__", ".")).parent
    secret_fields: tuple[str, ...] = ()
    if mode in {"rke2-ha", "k3s-ha"}:
        secret_fields = ("spec.secrets.rke2TokenFile",)
        if _get(data, "spec.platform.loadBalancer.enabled", True):
            secret_fields += ("spec.secrets.keepalivedAuthFile",)
        if mode == "rke2-ha" and _get(data, "spec.rke2.etcdSnapshots.s3.enabled", False):
            secret_fields += ("spec.rke2.etcdSnapshots.s3.configSecretFile",)
    for dotted in secret_fields:
        value = _get(data, dotted)
        if not value:
            continue
        secret_path = source / value
        if not secret_path.exists():
            result.warnings.append(f"Secret file does not exist yet: {value}")
            continue
        if dotted.endswith("configSecretFile") and environment == "production":
            try:
                validate_snapshot_file(secret_path)
            except SnapshotConfigurationError as exc:
                result.errors.append(str(exc))
            except (OSError, UnicodeError):
                result.errors.append("Unable to read UTF-8 RKE2 S3 configuration")
            continue
        try:
            with secret_path.open(encoding="utf-8", newline="") as stream:
                raw_secret = stream.read()
            secret = raw_secret.strip()
        except (OSError, UnicodeError) as exc:
            result.errors.append(f"Unable to read secret file {value}: {exc}")
            continue
        if dotted.endswith("rke2TokenFile") and len(secret) < 16:
            result.errors.append("RKE2 token file must contain at least 16 characters")
        if dotted.endswith("keepalivedAuthFile") and len(secret) < 8:
            result.errors.append("Keepalived auth file must contain at least 8 characters")
        if dotted.endswith("configSecretFile") and not secret:
            result.errors.append("RKE2 S3 snapshot configuration secret file must not be empty")

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
            if not isinstance(value, str) or value.strip().lower() in (
                "",
                "latest",
                "stable",
                "current",
            ):
                result.errors.append(
                    f"Production deployment must pin spec.versions.{required} to a version string"
                )
        installer_checksum_key = {
            "rke2-ha": "rke2InstallerChecksum",
            "k3s-ha": "k3sInstallerChecksum",
        }.get(mode)
        if installer_checksum_key and not _is_sha256(versions.get(installer_checksum_key)):
            result.errors.append(
                f"Production {mode} requires spec.versions.{installer_checksum_key} "
                "as a SHA-256 checksum for the privileged installer script"
            )
        if (
            mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}
            and not versions.get("helmChecksum")
            and not versions.get("helmChecksums")
        ):
            result.errors.append(
                "Production Kubernetes deployment must pin a Helm archive SHA-256 checksum"
            )
        if versions.get("helmChecksum") and not _is_sha256(versions["helmChecksum"]):
            result.errors.append("spec.versions.helmChecksum must be a SHA-256 checksum")

    return result
