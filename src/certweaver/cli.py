from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import _get, load_config, validate_config
from .enterprise import evaluate_enterprise, initialize_enterprise
from .errors import CertWeaverError, ConfigurationError
from .readiness import (
    assess_evidence,
    assessment_markdown,
    repo_score,
    score_markdown,
    write_evidence_bundle,
)
from .registry import load_registry, project_root
from .render import execution_plan, write_inventory


def _config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-c", "--config", default="certweaver.yml", help="Configuration YAML")


def _print_validation(config_path: str, fail: bool = True) -> int:
    config = load_config(config_path)
    result = validate_config(config)
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    for error in result.errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if result.ok:
        print("Configuration is valid")
        return 0
    return 2 if fail else 0


def command_validate(args: argparse.Namespace) -> int:
    return _print_validation(args.config)


def command_matrix(_: argparse.Namespace) -> int:
    registry = load_registry()
    headers = ("#", "slug", "name", "maturity", "targets", "modes")
    rows = []
    for idx, adapter in enumerate(registry.values(), start=1):
        rows.append(
            (
                str(idx),
                adapter.slug,
                adapter.name,
                adapter.maturity,
                ",".join(adapter.targets),
                ",".join(adapter.modes),
            )
        )
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))]
    print("  ".join(value.ljust(widths[i]) for i, value in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_config(config)
    result.require_ok()
    for idx, item in enumerate(execution_plan(config), start=1):
        print(f"{idx:02d}. {item}")
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    return 0


def command_render(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    validate_config(config).require_ok()
    destination = write_inventory(config, args.output)
    print(destination)
    return 0


def command_score(args: argparse.Namespace) -> int:
    if args.evidence:
        config = load_config(args.config or "certweaver.yml")
        assessment = assess_evidence(config, args.evidence)
        print(assessment_markdown(assessment), end="")
        return 0 if assessment.complete else 2
    if args.config:
        raise ConfigurationError("score --config requires --evidence DIRECTORY")
    print(score_markdown(), end="")
    return 0


def command_evidence(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_config(config)
    result.require_ok()
    files = write_evidence_bundle(config, args.output)
    score, maximum = repo_score()
    print(f"Evidence bundle written to {Path(args.output).resolve()}")
    print(f"Repo-local production maturity score: {score}/{maximum}")
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    for path in files:
        print(path)
    return 0


def command_enterprise_score(args: argparse.Namespace) -> int:
    assessment = evaluate_enterprise(args.assessment)
    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2))
    else:
        print(f"Enterprise verified credit: {assessment.verified_points:g}/100")
        print(f"Assessed controls: {assessment.assessed_controls}/100")
        print(f"Production decision: {assessment.production_decision}")
        print("Authentication backend: unavailable in this CLI; assured credit is denied")
        print("Zero verified credit means no accepted proof, not measured operational failure.")
        for category, points in assessment.category_scores.items():
            print(f"  {category}: {points:g}")
        for gate, status in assessment.gates.items():
            print(f"  {gate}: {status}")
        for error in assessment.errors:
            print(f"ERROR: {error}")
        for control in assessment.controls:
            if control.limitations:
                print(f"{control.control_id}: {'; '.join(control.limitations)}")
    return 0 if assessment.complete else 2


def command_enterprise_init(args: argparse.Namespace) -> int:
    print(initialize_enterprise(args.output))
    return 0


def _playbook_for_mode(mode: str) -> str:
    return {
        "rke2-ha": "rke2-ha.yml",
        "k3s-ha": "k3s-ha.yml",
        "existing-kubernetes": "addons.yml",
        "standalone": "standalone.yml",
        "docker": "docker.yml",
        "raw": "standalone.yml",
        "windows": "windows.yml",
    }[mode]


def _required_secret_files(config: dict) -> dict[str, Path | None]:
    if _get(config, "spec.mode") not in {"rke2-ha", "k3s-ha"}:
        return {}
    source = Path(config.get("__source_path__", ".")).parent
    values = {
        "RKE2/K3s token": _get(config, "spec.secrets.rke2TokenFile"),
    }
    if _get(config, "spec.platform.loadBalancer.enabled", True):
        values["Keepalived authentication"] = _get(config, "spec.secrets.keepalivedAuthFile")
    if _get(config, "spec.mode") == "rke2-ha" and _get(
        config, "spec.rke2.etcdSnapshots.s3.enabled", False
    ):
        values["etcd S3 configuration"] = _get(
            config, "spec.rke2.etcdSnapshots.s3.configSecretFile"
        )
    return {name: source / value if value else None for name, value in values.items()}


def command_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_config(config, for_deployment=True)
    checks = {
        "python": sys.executable,
        "ansible-playbook": shutil.which("ansible-playbook"),
    }
    mode = _get(config, "spec.mode")
    if mode != "windows":
        checks["ssh"] = shutil.which("ssh")
    checks.update(
        {
            f"{name} file": str(path) if path and path.is_file() else None
            for name, path in _required_secret_files(config).items()
        }
        if result.ok
        else {}
    )
    if mode == "windows":
        print(
            "NOTE: Install the ansible.windows and community.windows collections before deployment"
        )
    failed = False
    for name, value in checks.items():
        state = "OK" if value else "MISSING"
        print(f"{state:7} {name}: {value or '-'}")
        failed |= not bool(value)
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    for error in result.errors:
        print(f"ERROR: {error}")
        failed = True
    return 2 if failed else 0


def command_deploy(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_config(config, for_deployment=True)
    result.require_ok()
    if not shutil.which("ansible-playbook"):
        raise ConfigurationError("ansible-playbook is required; install the Ansible prerequisites")
    for name, path in _required_secret_files(config).items():
        if path is None or not path.is_file():
            raise ConfigurationError(f"Required {name} file is missing; run certweaver doctor")
    root = project_root()
    inventory = Path(args.inventory).resolve()
    write_inventory(config, inventory)
    mode = config["spec"]["mode"]
    cmd = [
        "ansible-playbook",
        "-i",
        str(inventory),
        str(root / "playbooks" / _playbook_for_mode(mode)),
    ]
    if args.check:
        cmd.append("--check")
    if args.limit:
        cmd.extend(["--limit", args.limit])
    if args.tags:
        cmd.extend(["--tags", args.tags])
    environment = os.environ.copy()
    environment.setdefault("ANSIBLE_CONFIG", str(root / "ansible.cfg"))
    roles_path = str(root / "roles")
    if environment.get("ANSIBLE_ROLES_PATH"):
        roles_path += os.pathsep + environment["ANSIBLE_ROLES_PATH"]
    environment["ANSIBLE_ROLES_PATH"] = roles_path
    print("Executing:", " ".join(cmd))
    return subprocess.run(cmd, check=False, env=environment).returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="certweaver")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="Validate a deployment configuration")
    _config_argument(validate)
    validate.set_defaults(func=command_validate)

    matrix = sub.add_parser("matrix", help="Show the twenty adapter integrations")
    matrix.set_defaults(func=command_matrix)

    plan = sub.add_parser("plan", help="Print the ordered deployment plan")
    _config_argument(plan)
    plan.set_defaults(func=command_plan)

    render = sub.add_parser("render-inventory", help="Render Ansible inventory")
    _config_argument(render)
    render.add_argument("-o", "--output", default=".certweaver/inventory.yml")
    render.set_defaults(func=command_render)

    score = sub.add_parser("score", help="Show the repo-local production maturity score")
    score.add_argument("-c", "--config", help="Deployment configuration for evidence assessment")
    score.add_argument("--evidence", help="Assess a reviewed evidence bundle; exit 2 if incomplete")
    score.set_defaults(func=command_score)

    evidence = sub.add_parser("evidence", help="Write a sanitized production evidence bundle")
    _config_argument(evidence)
    evidence.add_argument("-o", "--output", default=".certweaver/evidence")
    evidence.set_defaults(func=command_evidence)

    enterprise_init = sub.add_parser(
        "enterprise-init", help="Create an unassessed enterprise v1 record without overwriting"
    )
    enterprise_init.add_argument("-o", "--output", required=True)
    enterprise_init.set_defaults(func=command_enterprise_init)

    enterprise_score = sub.add_parser(
        "enterprise-score", help="Recompute enterprise v1 evidence credit and gates"
    )
    enterprise_score.add_argument(
        "assessment", help="Assessment JSON; evidence paths relative to it"
    )
    enterprise_score.add_argument(
        "--json", action="store_true", help="Export all control decisions"
    )
    enterprise_score.set_defaults(func=command_enterprise_score)

    doctor = sub.add_parser("doctor", help="Check local prerequisites")
    _config_argument(doctor)
    doctor.set_defaults(func=command_doctor)

    deploy = sub.add_parser("deploy", help="Run the selected Ansible deployment")
    _config_argument(deploy)
    deploy.add_argument("-i", "--inventory", default=".certweaver/inventory.yml")
    deploy.add_argument("--check", action="store_true")
    deploy.add_argument("--limit")
    deploy.add_argument("--tags")
    deploy.set_defaults(func=command_deploy)
    return parser


def main() -> None:
    try:
        args = build_parser().parse_args()
        raise SystemExit(args.func(args))
    except (CertWeaverError, OSError) as exc:
        print(f"certweaver: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
