"""Prove WinRM fail-fast against real separate controller environments, without host contact."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import io
import json
import runpy
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from unittest.mock import patch

import yaml
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from certweaver import cli, controller
from certweaver.errors import ConfigurationError


def ansible_only_lock(root: Path) -> tuple[str, list[str]]:
    installer = runpy.run_path(str(root / "scripts/install-python-deps.py"))
    source = installer["lock_file"](root, "dev")
    environment = {**default_environment(), "extra": ""}
    entries = {}
    for line in source.read_text().replace("\\\n", " ").splitlines():
        if not line.strip():
            continue
        requirement = Requirement(line.split("--hash=", 1)[0].strip())
        if not requirement.marker or requirement.marker.evaluate(environment):
            name = canonicalize_name(requirement.name)
            if name in entries:
                raise ValueError("Ambiguous active dependency lock entry")
            entries[name] = (requirement, line)
    pending, selected = ["ansible-core"], set()
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        distribution = importlib.metadata.distribution(name)
        requirement, _ = entries[name]
        if not requirement.specifier.contains(distribution.version):
            raise ValueError("Controller fixture requires the installed source-bound dev profile")
        selected.add(name)
        for raw in distribution.requires or []:
            dependency = Requirement(raw)
            if not dependency.marker or dependency.marker.evaluate(environment):
                pending.append(canonicalize_name(dependency.name))
    if "pywinrm" in selected or "requests-ntlm" in selected:
        raise ValueError("Negative fixture unexpectedly includes WinRM dependencies")
    return "\n".join(entries[name][1] for name in sorted(selected)) + "\n", sorted(selected)


def verify(root: Path, output: Path) -> dict:
    if sys.platform != "linux":
        raise ValueError("This integration fixture qualifies Linux Ansible controllers")
    if output.exists() or output.is_symlink():
        raise ValueError("Controller preflight verification requires fresh output storage")
    output.mkdir(parents=True, mode=0o700)
    config = cli.load_config(root / "examples/configs/windows.yml")
    config.pop("__source_path__")
    config["spec"]["adapters"]["enabled"] = ["posh-acme"]
    config["spec"]["adapters"]["versions"]["posh_acme"] = "4.2.1"
    config_path = output / "fixture-config.yml"
    config_path.write_text(yaml.safe_dump(config))
    config_path.chmod(0o600)
    executable = shutil.which("ansible-playbook")
    if not executable:
        raise ValueError("The fixture needs a working locked Ansible controller")
    environment = cli._ansible_environment(root)
    positive = controller.probe_windows_controller(config, executable, environment)
    if not positive:
        raise ValueError("The positive WinRM controller was not inspected")
    lock, packages = ansible_only_lock(root)
    requirements = output / "ansible-only.lock"
    requirements.write_text(lock)
    target = output / "controller-without-winrm"
    venv.EnvBuilder(with_pip=False).create(target)
    python, negative_executable = target / "bin/python", target / "bin/ansible-playbook"
    installer = runpy.run_path(str(root / "scripts/install-python-deps.py"))
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--python",
            str(python),
            "install",
            "--no-input",
            "--disable-pip-version-check",
            "--index-url",
            "https://pypi.org/simple",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "-r",
            str(requirements),
        ],
        env=installer["pip_environment"](),
        capture_output=True,
        timeout=600,
    )
    (output / "ansible-only-install.log").write_bytes(result.stdout + b"\n" + result.stderr)
    if result.returncode:
        raise ValueError("Cannot prepare the hash-locked negative controller")
    probe = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import importlib.util; assert importlib.util.find_spec('winrm') is None",
        ],
        capture_output=True,
        timeout=20,
    )
    if probe.returncode:
        raise ValueError("The negative controller must genuinely lack pywinrm")
    observations, original_run = [], subprocess.run

    def local_probe_only(command, **kwargs):
        if command != [str(negative_executable), "--version"] and command != [
            str(python),
            "-I",
            "-c",
            controller._PROBE,
        ]:
            raise AssertionError("A target command was attempted during controller preflight")
        observations.append(command[:2])
        return original_run(command, **kwargs)

    inventory = output / "must-not-be-created.yml"
    doctor_output = io.StringIO()
    with (
        patch.object(cli.shutil, "which", return_value=str(negative_executable)),
        patch.object(subprocess, "run", side_effect=local_probe_only),
    ):
        with contextlib.redirect_stdout(doctor_output):
            status = cli.command_doctor(
                cli.build_parser().parse_args(["doctor", "-c", str(config_path)])
            )
        if status != 2 or "missing pywinrm" not in doctor_output.getvalue():
            raise ValueError("Doctor did not reject the actual missing controller dependency")
        for existing in [False, True]:
            if existing:
                inventory.write_text("protected-existing-inventory\n")
            args = cli.build_parser().parse_args(
                ["deploy", "-c", str(config_path), "-i", str(inventory), "--check"]
            )
            try:
                cli.command_deploy(args)
            except ConfigurationError as error:
                if "missing pywinrm" not in str(error):
                    raise ValueError("Unexpected deployment preflight failure") from None
            else:
                raise ValueError("Deployment accepted a controller without WinRM")
            if (
                inventory.exists()
                if not existing
                else inventory.read_text() != "protected-existing-inventory\n"
            ):
                raise ValueError("Rejected preflight created or replaced inventory")
    (output / "doctor.log").write_text(doctor_output.getvalue())
    if len(observations) != 6:
        raise ValueError("The fixture did not exercise every read-only controller probe")
    return {
        "scope": (
            "Real positive controller and separate hash-locked Ansible-only runtime; "
            "no Windows authentication, managed-host contact or deployment"
        ),
        "positiveController": positive,
        "negativeControllerPython": str(python),
        "negativeControllerPackages": packages,
        "negativeRuntimeLacksPywinrm": True,
        "doctorExitCode": status,
        "missingAndExistingInventoryPreserved": True,
        "targetCommandsAttempted": 0,
        "localProbeCommands": observations,
        "ansibleOnlyLockSha256": hashlib.sha256(requirements.read_bytes()).hexdigest(),
        "sourceSha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in [
                "src/certweaver/controller.py",
                "src/certweaver/cli.py",
                "ci/python-dev.lock",
                "ci/python-locks.json",
                "pyproject.toml",
                "scripts/check-controller-preflight.py",
            ]
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = verify(Path(__file__).resolve().parents[1], args.output_dir.absolute())
        (args.output_dir / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        print("Selected-controller prerequisite verification passed without target execution")
    except (OSError, ValueError, KeyError, ConfigurationError, subprocess.SubprocessError) as error:
        print(f"Controller preflight verification failed ({type(error).__name__})")
        raise SystemExit(1) from error
