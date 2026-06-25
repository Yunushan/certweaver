from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import load_config, validate_config
from .errors import CertWeaverError
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


def command_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_config(config)
    checks = {
        "python": sys.executable,
        "ansible-playbook": shutil.which("ansible-playbook"),
        "ssh": shutil.which("ssh"),
    }
    mode = config.get("spec", {}).get("mode")
    if mode == "windows":
        checks["ansible Windows collections"] = "checked during deployment"
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
    result = validate_config(config)
    result.require_ok()
    root = project_root()
    inventory = Path(args.inventory)
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
    print("Executing:", " ".join(cmd))
    return subprocess.run(cmd, check=False).returncode


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
    except CertWeaverError as exc:
        print(f"certweaver: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
