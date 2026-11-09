"""Installation contracts shared by CLI preflight and Ansible rendering."""

from __future__ import annotations

import re
from typing import Any

import yaml

from .errors import ConfigurationError

CLIENTS = {"acme-sh", "certbot", "lego", "cfssl", "dehydrated"}
CONTAINERS = CLIENTS | {
    "step-ca",
    "openbao-pki",
    "ejbca-community",
    "dogtag-pki",
    "spire",
    "caddy-auto-https",
    "traefik-acme",
    "lemur",
}
IMAGE = re.compile(
    r"(?:[a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+|localhost|[a-z0-9][a-z0-9.-]*(?=:[0-9]+/))"
    r"(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}"
)


def options_for_host(options: dict, hostname: str) -> dict:
    """Apply a named host override without changing another host's settings."""
    if not isinstance(options, dict) or not isinstance(options.get("hosts", {}), dict):
        raise ConfigurationError("Adapter options and hosts must be mappings")
    override = options.get("hosts", {}).get(hostname, {})
    if not isinstance(override, dict):
        raise ConfigurationError("Adapter host override must be a mapping")
    return {**{k: v for k, v in options.items() if k != "hosts"}, **override}


def backend(slug: str, mode: str, options: dict) -> str:
    """Resolve application placement independently of cluster installation."""
    if mode == "windows":
        return "windows"
    if mode == "docker":
        return "boulder-lab" if slug == "boulder" else "docker"
    if mode in {"rke2-ha", "k3s-ha", "existing-kubernetes"}:
        if slug in {"step-ca", "openbao-pki"}:
            return (
                "kubernetes" if options.get("installMode", "kubernetes") == "kubernetes" else "host"
            )
        if slug in {
            "cert-manager",
            "trust-manager",
            "cert-manager-csi-driver",
            "spire",
            "traefik-acme",
            "ejbca-community",
        }:
            return "kubernetes"
    return "host"


def topology_issues(
    mode: str,
    nodes: list[dict],
    enabled: list[str],
    options: dict,
    start_services: bool = False,
    environment: str = "staging",
) -> list[str]:
    """Reject empty placements and configuration-only native SPIRE installs."""
    issues = []
    names = [node["name"] for node in nodes]
    for slug in enabled:
        original = options.get(slug, {})
        if not isinstance(original.get("hosts", {}), dict):
            issues.append(f"{slug}: hosts must be a mapping")
            continue
        if set(original.get("hosts", {})) - set(names):
            issues.append(f"{slug}: host override refers to an unknown deployment node")
        for name in names:
            try:
                resolved = options_for_host(original, name)
            except ConfigurationError as exc:
                issues.append(f"{slug}: {exc}")
                continue
            selected = resolved.get("nodes", names)
            if (
                not _strings(selected)
                or not selected
                or len(selected) != len(set(selected))
                or set(selected) - set(names)
            ):
                issues.append(f"{slug}: nodes must select known, unique deployment hosts")
                continue
            if name not in selected:
                continue
            if (
                slug == "ejbca-community"
                and environment == "production"
                and resolved.get("externalDatabase") is not True
            ):
                issues.append(
                    "ejbca-community: production requires an explicitly reviewed external database"
                )
            files = resolved.get("files", [])
            if not isinstance(files, list):
                issues.append(f"{slug}: files must be a list")
            else:
                for entry in files:
                    if (
                        not isinstance(entry, dict)
                        or not isinstance(entry.get("source"), str)
                        or not re.fullmatch(r"/[^\n]+", entry["source"])
                        or not isinstance(entry.get("name"), str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", entry["name"])
                        or entry["name"]
                        in {"config", "config.py", "config.yaml", "config.hcl", "activated.json"}
                        or not isinstance(entry.get("mode", "0640"), str)
                        or entry.get("mode", "0640") not in {"0400", "0600", "0640"}
                    ):
                        issues.append(
                            f"{slug}: files need absolute sources and private confined targets"
                        )
            if mode == "docker" and resolved.get("installMode", "docker") != "docker":
                issues.append(f"{slug}: Docker mode cannot silently select a different installMode")
            if backend(slug, mode, resolved) == "kubernetes" and names[0] not in selected:
                issues.append(f"{slug}: cluster installation must include the bootstrap controller")
            if slug == "spire" and mode in {"standalone", "raw"}:
                components = resolved.get("components", [])
                if (
                    not _strings(components)
                    or not components
                    or set(components) - {"server", "agent"}
                ):
                    issues.append(
                        "spire: select server and/or agent components for every target host"
                    )
                    continue
                for component in components:
                    config = resolved.get(component + "ConfigFile", "")
                    if not isinstance(config, str) or not config.startswith("/") or "\n" in config:
                        issues.append(
                            f"spire: {component} requires an absolute reviewed configuration file"
                        )
            if slug == "lemur" and mode in {"standalone", "raw"}:
                for field in ("requirementsFile", "configFile"):
                    value = resolved.get(field, "")
                    if not isinstance(value, str) or not value.startswith("/") or "\n" in value:
                        issues.append(
                            f"lemur: {field} requires an absolute reviewed controller file"
                        )
                if (
                    resolved.get("runMigrations", False)
                    and resolved.get("migrationHost") not in names
                ):
                    issues.append("lemur: nominate a deployment host for database migrations")
            native_server = (
                slug == "caddy-auto-https"
                and mode != "docker"
                or slug == "traefik-acme"
                and mode in {"standalone", "raw"}
                or slug == "openbao-pki"
                and backend(slug, mode, resolved) == "host"
                and resolved.get("installMode", "standalone") == "standalone"
                or slug == "step-ca"
                and backend(slug, mode, resolved) == "host"
                and resolved.get("installMode", "standalone") == "standalone"
            )
            if start_services and native_server:
                value = resolved.get("serviceConfigFile", "")
                if not isinstance(value, str) or not value.startswith("/") or "\n" in value:
                    issues.append(f"{slug}: activation requires an absolute serviceConfigFile")
                if slug == "step-ca" and not re.fullmatch(
                    r"/[A-Za-z0-9_./-]+", str(resolved.get("passwordFile", ""))
                ):
                    issues.append("step-ca: activation requires a reviewed target passwordFile")
            if slug == "caddy-auto-https" and resolved.get("configAdapter", "json") not in (
                "json",
                "caddyfile",
            ):
                issues.append("caddy-auto-https: configAdapter must be json or caddyfile")
            if slug == "freeipa-certmonger":
                role = resolved.get("role", "server")
                if not isinstance(role, str) or role not in {"server", "client", "replica"}:
                    issues.append("freeipa-certmonger: role must be server, client or replica")
                server_inputs = all(
                    isinstance(resolved.get(field), str) and resolved[field]
                    for field in (
                        "realm",
                        "domain",
                        "hostname",
                        "directoryManagerPasswordFile",
                        "adminPasswordFile",
                    )
                )
                server_inputs = (
                    server_inputs
                    and all(
                        re.fullmatch(r"/[^\x00-\x1f\x7f]+", resolved[field])
                        for field in ("directoryManagerPasswordFile", "adminPasswordFile")
                    )
                    and all(
                        re.fullmatch(r"[A-Za-z0-9.-]+", resolved[field])
                        for field in ("realm", "domain", "hostname")
                    )
                )
                if (
                    role == "server"
                    and resolved.get("configureServer", False)
                    and not server_inputs
                ):
                    issues.append(
                        "freeipa-certmonger: server creation requires realm, domain, hostname "
                        "and protected password file paths"
                    )
                if role == "client" and not all(
                    isinstance(resolved.get(field), str) and resolved[field]
                    for field in ("realm", "domain", "server", "keytabFile")
                ):
                    issues.append(
                        "freeipa-certmonger: client enrollment requires realm, domain, "
                        "server and keytabFile"
                    )
    return list(dict.fromkeys(issues))


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(v, str) and v and "\x00" not in v for v in value
    )


def verified_manifest_images(rendered: str, expected: str) -> bool:
    """Check rendered pod images, including hooks, init containers and sidecars."""
    if len(rendered.encode("utf-8")) > 16 * 1024 * 1024:
        raise ConfigurationError("Rendered application manifests exceed the inspection limit")
    images = []
    active = set()
    entries = 0

    def inspect(value, depth=0):
        nonlocal entries
        entries += 1
        if depth > 100 or entries > 200000 or id(value) in active:
            raise ConfigurationError(
                "Rendered application manifests contain excessive or cyclic data"
            )
        if isinstance(value, (dict, list)):
            active.add(id(value))
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"containers", "initContainers", "ephemeralContainers"}:
                    if not isinstance(child, list):
                        raise ConfigurationError("Rendered pod containers must be a list")
                    for container in child:
                        image = container.get("image") if isinstance(container, dict) else None
                        if not isinstance(image, str) or not IMAGE.fullmatch(image):
                            raise ConfigurationError(
                                "Rendered pod image lacks a fully qualified digest"
                            )
                        images.append(image)
                inspect(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, depth + 1)
        active.discard(id(value))

    try:
        for document in yaml.safe_load_all(rendered):
            inspect(document)
    except (yaml.YAMLError, RecursionError):
        raise ConfigurationError("Cannot parse rendered application manifests") from None
    if expected not in images:
        raise ConfigurationError("Rendered application does not contain the approved primary image")
    return True


def container_model(options: dict, slug: str) -> dict:
    """Render a digest-bound Compose application, never execute a container.

    Images and application-specific settings are supplied by the reviewed
    deployment profile. There is no mutable image fallback or generated CA key.
    """
    if slug not in CONTAINERS or not isinstance(options, dict):
        raise ConfigurationError("Adapter has no managed Compose installation contract")
    if slug == "spire" and "containers" in options:
        components = options["containers"]
        if (
            "container" in options
            or not isinstance(components, dict)
            or not components
            or set(components) - {"server", "agent"}
        ):
            raise ConfigurationError("spire: containers must select server and/or agent runtimes")
        return {
            "name": "certweaver-spire",
            "services": {
                name: container_model({"container": runtime}, slug)["services"]["app"]
                for name, runtime in components.items()
            },
        }
    runtime = options.get("container", {})
    if not isinstance(runtime, dict):
        raise ConfigurationError(f"{slug}: container must be a mapping")
    allowed = {
        "image",
        "command",
        "entrypoint",
        "ports",
        "mounts",
        "envFiles",
        "healthcheck",
        "user",
        "hostPID",
    }
    if set(runtime) - allowed:
        raise ConfigurationError(f"{slug}: unknown container option")
    image = runtime.get("image")
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise ConfigurationError(
            f"{slug}: container.image requires registry/repository@sha256 digest"
        )
    service: dict[str, Any] = {
        "image": image,
        "restart": "no" if slug in CLIENTS else "unless-stopped",
    }
    for field in ("command", "entrypoint", "ports", "envFiles"):
        value = runtime.get(field, [])
        if not _strings(value):
            raise ConfigurationError(
                f"{slug}: container.{field} must be a list of nonempty strings"
            )
        if value:
            service["env_file" if field == "envFiles" else field] = value
    if any(not p.startswith("/") or "\n" in p for p in runtime.get("envFiles", [])):
        raise ConfigurationError(f"{slug}: envFiles must be absolute target paths")
    mounts = runtime.get("mounts", [])
    if not isinstance(mounts, list):
        raise ConfigurationError(f"{slug}: container.mounts must be a list")
    volumes = []
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or set(mount) - {"source", "target", "readOnly"}
            or not all(
                isinstance(mount.get(k), str) and mount[k].startswith("/") and "\n" not in mount[k]
                for k in ("source", "target")
            )
            or type(mount.get("readOnly", True)) is not bool
        ):
            raise ConfigurationError(
                f"{slug}: mounts require absolute source/target and boolean readOnly"
            )
        volumes.append(
            {
                "type": "bind",
                "source": mount["source"],
                "target": mount["target"],
                "read_only": mount.get("readOnly", True),
                "bind": {"create_host_path": False},
            }
        )
    if volumes:
        service["volumes"] = volumes
    if "user" in runtime:
        if not isinstance(runtime["user"], str) or not re.fullmatch(
            r"[0-9]+(?::[0-9]+)?", runtime["user"]
        ):
            raise ConfigurationError(f"{slug}: container.user must be a numeric UID or UID:GID")
        service["user"] = runtime["user"]
    if "hostPID" in runtime:
        if not isinstance(runtime["hostPID"], bool) or slug != "spire":
            raise ConfigurationError("hostPID is an explicit boolean SPIRE agent option")
        if runtime["hostPID"]:
            service["pid"] = "host"
    if slug not in CLIENTS and not (service.get("command") or service.get("entrypoint")):
        raise ConfigurationError(
            f"{slug}: server containers require an explicit application command"
        )
    if slug == "openbao-pki":
        if any(
            arg in {"-dev", "--dev"} or arg.startswith(("-dev=", "--dev="))
            for arg in service.get("command", []) + service.get("entrypoint", [])
        ):
            raise ConfigurationError(
                "openbao-pki: development server mode is not a managed installation"
            )
        service["cap_add"] = ["IPC_LOCK"]
    if "healthcheck" in runtime:
        health = runtime["healthcheck"]
        if (
            not isinstance(health, dict)
            or set(health) != {"test", "interval", "timeout", "retries"}
            or not _strings(health.get("test"))
            or not health["test"]
            or health["test"][0] != "CMD"
            or not all(
                isinstance(health.get(k), str) and re.fullmatch(r"[1-9][0-9]*s", health[k])
                for k in ("interval", "timeout")
            )
            or (
                not isinstance(health.get("retries"), int)
                or isinstance(health.get("retries"), bool)
            )
            or not 1 <= health["retries"] <= 100
        ):
            raise ConfigurationError(
                f"{slug}: healthcheck requires CMD test, second durations and bounded retries"
            )
        service["healthcheck"] = health

    # Compose interprets dollar signs even in YAML-quoted values. Preserve the
    # literal argv/path supplied by the profile, without reading controller env.
    def literal(value):
        if isinstance(value, str):
            return value.replace("$", "$$")
        if isinstance(value, list):
            return [literal(v) for v in value]
        if isinstance(value, dict):
            return {k: literal(v) for k, v in value.items()}
        return value

    return {"name": "certweaver-" + slug, "services": {"app": literal(service)}}
