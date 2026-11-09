"""Inventory source dependency declarations and guard checksum-before-extraction paths.

Static declarations are not a resolved deployment inventory or license approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml


def tasks(nodes):
    for task in nodes or []:
        if not isinstance(task, dict):
            raise ValueError("Dependency task declarations must be mappings")
        yield task
        for section in ("block", "rescue", "always"):
            yield from tasks(task.get(section))


def inspect(root: Path) -> dict:
    entries, errors, sources = [], [], {}
    modules = {
        "ansible.builtin.get_url": ("download", ("url", "checksum")),
        "ansible.windows.win_get_url": ("download", ("url", "checksum", "checksum_algorithm")),
        "ansible.builtin.git": (
            "git-source",
            ("repo", "version", "update", "force", "recursive", "track_submodules"),
        ),
        "ansible.builtin.dnf": ("host-packages", ("name",)),
        "ansible.windows.win_psmodule": (
            "powershell-module",
            ("name", "required_version", "repository"),
        ),
        "community.windows.win_psmodule": (
            "powershell-module",
            ("name", "required_version", "repository"),
        ),
    }
    for path in sorted((root / "roles").rglob("*.yml")):
        if "tasks" not in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix()
        sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        previous = {}
        for task in tasks(yaml.safe_load(path.read_text(encoding="utf-8"))):
            for module, (kind, keys) in modules.items():
                if module not in task:
                    continue
                arguments = task[module]
                if not isinstance(arguments, dict):
                    raise ValueError("Dependency modules require explicit argument mappings")
                entries.append(
                    {
                        "kind": kind,
                        "source": relative,
                        "task": task.get("name"),
                        "declaration": {key: arguments[key] for key in keys if key in arguments},
                        "resolvedCandidateIdentity": None,
                        "owner": None,
                        "acquisitionReview": "NOT_REVIEWED",
                        "licenseReview": "NOT_REVIEWED",
                    }
                )
                if kind == "download":
                    checksum = arguments.get("checksum")
                    if not isinstance(checksum, str) or not checksum or "omit" in checksum:
                        errors.append(f"{relative}: download checksum cannot be optional")
                    if arguments.get("validate_certs") is False:
                        errors.append(
                            f"{relative}: artifact download cannot disable TLS validation"
                        )
                if kind == "git-source" and (
                    relative != "roles/pki_adapter/tasks/_checkout_verified_git.yml"
                    or arguments.get("version") != "{{ certweaver_git_commit }}"
                    or arguments.get("update") is not True
                    or arguments.get("force") is not False
                    or arguments.get("recursive") is not False
                    or arguments.get("track_submodules") is not False
                    or arguments.get("executable")
                    != "{{ certweaver_adapter_source_parent }}/.certweaver-verified-git"
                ):
                    errors.append(f"{relative}: Git acquisition must use the exact-commit verifier")
            archive = task.get("ansible.builtin.unarchive", {})
            if isinstance(archive, dict) and "://" in str(archive.get("src", "")):
                errors.append(
                    f"{relative}: remote archive must be checksum-verified before extraction"
                )
            variables = task.get("vars", {})
            if "certweaver_git_repository" in variables:
                entries.append(
                    {
                        "kind": "git-checkout",
                        "source": relative,
                        "task": task.get("name"),
                        "declaration": {
                            "name": variables.get("certweaver_git_name"),
                            "repository": variables["certweaver_git_repository"],
                            "commit": variables.get("certweaver_git_commit"),
                        },
                        "resolvedCandidateIdentity": None,
                        "owner": None,
                        "acquisitionReview": "NOT_REVIEWED",
                        "licenseReview": "NOT_REVIEWED",
                    }
                )
            if "certweaver_download_url" in variables:
                entries.append(
                    {
                        "kind": "adapter-payload",
                        "source": relative,
                        "task": task.get("name"),
                        "declaration": {
                            "name": variables.get("certweaver_download_name"),
                            "url": variables["certweaver_download_url"],
                            "loop": task.get("loop"),
                        },
                        "resolvedCandidateIdentity": None,
                        "owner": None,
                        "acquisitionReview": "NOT_REVIEWED",
                        "licenseReview": "NOT_REVIEWED",
                    }
                )
            command = task.get("ansible.builtin.command", {})
            arguments = command.get("argv", []) if isinstance(command, dict) else []
            if (
                isinstance(arguments, list)
                and arguments
                and "upgrade" in arguments
                and "--install" in arguments
            ):
                conditions = task.get("when", [])
                if (
                    len(arguments) < 5
                    or arguments[0]
                    != "{{ certweaver_chart_helm_executable | default('/usr/local/bin/helm') }}"
                    or arguments[4] != "{{ certweaver_chart_archive_path }}"
                    or previous.get("ansible.builtin.include_role", {}).get("name")
                    != "verified_chart"
                    or not isinstance(conditions, list)
                    or "not ansible_check_mode" not in conditions
                    or "certweaver_chart_verified | default(false) | bool" not in conditions
                    or any(
                        flag in arguments for flag in ("--dependency-update", "--repo", "--version")
                    )
                ):
                    errors.append(
                        f"{relative}: Helm installation must use "
                        "the immediately verified local archive"
                    )
            if task.get("ansible.builtin.include_role", {}).get("name") == "verified_chart":
                entries.append(
                    {
                        "kind": "helm-chart",
                        "source": relative,
                        "task": task.get("name"),
                        "declaration": {
                            key: variables.get("certweaver_chart_" + key)
                            for key in (
                                "key",
                                "name",
                                "reference",
                                "repository",
                                "version",
                                "checksum",
                            )
                        },
                        "resolvedCandidateIdentity": None,
                        "owner": None,
                        "acquisitionReview": "NOT_REVIEWED",
                        "licenseReview": "NOT_REVIEWED",
                    }
                )
            previous = task
    for path in sorted((root / "roles").rglob("*.j2")):
        sources[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("Image="):
                if not re.fullmatch(
                    r"(?:localhost|[a-z0-9-]+(?:[.][a-z0-9-]+)+)(?::[0-9]+)?/"
                    r"[a-z0-9_./-]+@\{\{ "
                    r"certweaver_adapter_versions\.[a-z0-9_]+_image \| lower \}\}",
                    line[6:],
                ):
                    errors.append(
                        f"{path.relative_to(root).as_posix()}: "
                        "Quadlet images require a qualified repository and image-digest variable"
                    )
                entries.append(
                    {
                        "kind": "container-image",
                        "source": path.relative_to(root).as_posix(),
                        "declaration": {"image": line[6:]},
                        "resolvedCandidateIdentity": None,
                        "owner": None,
                        "acquisitionReview": "NOT_REVIEWED",
                        "licenseReview": "NOT_REVIEWED",
                    }
                )
    compose = root / "docker/compose.pki.yml"
    if compose.is_file():
        sources["docker/compose.pki.yml"] = hashlib.sha256(compose.read_bytes()).hexdigest()
        for name, service in yaml.safe_load(compose.read_text())["services"].items():
            if not re.fullmatch(
                r"(?:localhost|[a-z0-9-]+(?:[.][a-z0-9-]+)+)(?::[0-9]+)?/"
                r"[a-z0-9_./-]+@\$\{"
                r"[A-Z][A-Z0-9_]*_IMAGE_DIGEST:\?[^}]+\}",
                service["image"],
            ):
                errors.append(
                    f"docker/compose.pki.yml: {name} requires a qualified repository "
                    "and mandatory image-digest input"
                )
            entries.append(
                {
                    "kind": "container-image",
                    "source": "docker/compose.pki.yml",
                    "declaration": {"service": name, "image": service["image"]},
                    "resolvedCandidateIdentity": None,
                    "owner": None,
                    "acquisitionReview": "NOT_REVIEWED",
                    "licenseReview": "NOT_REVIEWED",
                }
            )
    registry_path = root / "config/pki-registry.yml"
    if registry_path.is_file():
        sources["config/pki-registry.yml"] = hashlib.sha256(registry_path.read_bytes()).hexdigest()
        for adapter in yaml.safe_load(registry_path.read_text())["adapters"]:
            entries.append(
                {
                    "kind": "adapter-registry",
                    "source": "config/pki-registry.yml",
                    "declaration": {
                        key: adapter[key]
                        for key in ("slug", "name", "license", "upstream", "maturity")
                    },
                    "resolvedCandidateIdentity": None,
                    "owner": None,
                    "acquisitionReview": "NOT_REVIEWED",
                    "licenseReview": "DECLARED_NOT_VERIFIED",
                }
            )
    return {
        "schemaVersion": 1,
        "status": "SOURCE_DECLARATIONS_NOT_COMPLETE_DEPLOYMENT_INVENTORY",
        "entries": entries,
        "sourceSha256": sources,
        "guardErrors": errors,
        "limitations": [
            "Expressions and mutable refs are not resolved upstream identities",
            "Transitive chart/container/OS dependencies require candidate reconciliation",
            "License, lifecycle, ownership and trust decisions remain unreviewed",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(Path(__file__).resolve().parents[1])
        if args.json:
            print(json.dumps(result, indent=2))
        elif result["guardErrors"]:
            for error in result["guardErrors"]:
                print("ERROR: " + error)
        else:
            print(
                "Adapter source acquisition guards passed; "
                "resolved dependency/owner/license review remains open"
            )
        raise SystemExit(1 if result["guardErrors"] else 0)
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        print(f"ERROR: Dependency source inspection failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
