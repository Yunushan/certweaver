"""Smoke-test a built wheel from outside the source checkout.

Uses the current environment's runtime dependencies, installs only the wheel
into a temporary directory, and runs each command in an isolated interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import marshal
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def verified_asset_files(assets: Path, names: set[str]) -> dict[str, Path]:
    """Allow only listed resources and bytecode demonstrably compiled from them.

    pip normally compiles Python Ansible filters/helpers when installing a wheel.
    Do not ignore arbitrary cache files: compare every derived code object to
    a fresh compilation of its listed source, including the installed filename.
    """
    expected = {name: assets / name for name in names}
    compiled = {
        Path(importlib.util.cache_from_source(str(path))).relative_to(assets).as_posix(): path
        for name, path in expected.items()
        if name.endswith(".py")
    }
    observed = set()
    for path in assets.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(assets).as_posix()
        if name in names:
            observed.add(name)
            continue
        source = compiled.get(name)
        if source is None or path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError("Unexpected installed deployment resource: " + name)
        data = path.read_bytes()
        if (
            len(data) < 16
            or data[:4] != importlib.util.MAGIC_NUMBER
            or int.from_bytes(data[4:8], "little") not in {0, 1, 3}
            or marshal.loads(data[16:])
            != compile(source.read_bytes(), str(source), "exec", dont_inherit=True, optimize=0)
        ):
            raise RuntimeError("Installed deployment bytecode differs from approved source")
    if observed != names:
        raise RuntimeError("Installed deployment resources are missing")
    return expected


def resource_hashes(root: Path) -> dict[str, str]:
    names = [
        line.strip()
        for line in (root / "certweaver-resources.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def check_wheel(wheel: Path) -> None:
    wheel = wheel.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="certweaver-wheel-") as temporary:
        workspace = Path(temporary)
        installed = workspace / "installed"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--disable-pip-version-check",
                "--target",
                str(installed),
                str(wheel),
            ],
            check=True,
        )
        assets = installed / "certweaver" / "_assets"
        expected = resource_hashes(Path(__file__).resolve().parents[1])
        actual = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in verified_asset_files(assets, set(expected)).items()
        }
        if expected != actual:
            raise RuntimeError("Installed deployment resources differ from the source tree")
        source_package = Path(__file__).resolve().parents[1] / "src" / "certweaver"
        expected_code = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_package.glob("*.py")
        }
        actual_code = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (installed / "certweaver").glob("*.py")
        }
        if expected_code != actual_code:
            raise RuntimeError("Installed Python modules differ from the source tree")
        bootstrap = (
            "import runpy,sys; "
            f"sys.path.insert(0, {str(installed)!r}); "
            "from certweaver.registry import project_root; "
            "root = project_root(); "
            "assert root.name == '_assets', root; "
            "assert (root / 'ansible.cfg').is_file(); "
            "assert (root / 'playbooks/rke2-ha.yml').is_file(); "
            "assert (root / 'roles/rke2_server/templates/config.yaml.j2').is_file(); "
            "assert (root / 'kubernetes/cert-manager/values.yaml').is_file(); "
            "sys.argv = ['certweaver', *sys.argv[1:]]; "
            "runpy.run_module('certweaver.cli', run_name='__main__')"
        )
        config = installed / "certweaver" / "_assets" / "examples" / "configs" / "standalone.yml"
        commands = [
            ["--version"],
            ["matrix"],
            ["score"],
            ["validate", "-c", str(config)],
            ["plan", "-c", str(config)],
            ["render-inventory", "-c", str(config), "-o", str(workspace / "inventory.yml")],
            ["evidence", "-c", str(config), "-o", str(workspace / "evidence")],
            ["enterprise-init", "-o", str(workspace / "enterprise-assessment.json")],
            ["staging-init", "-o", str(workspace / "staging-inputs")],
        ]
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH", "ANSIBLE_CONFIG", "ANSIBLE_ROLES_PATH"}
        }
        for command in commands:
            print(f"Checking installed wheel: {' '.join(command)}", flush=True)
            subprocess.run(
                [sys.executable, "-I", "-c", bootstrap, *command],
                cwd=workspace,
                env=environment,
                check=True,
            )
        enterprise_result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                bootstrap,
                "enterprise-score",
                str(workspace / "enterprise-assessment.json"),
                "--json",
            ],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if enterprise_result.returncode != 2:
            raise RuntimeError("Installed enterprise evaluator did not reject an unassessed record")
        report = json.loads(enterprise_result.stdout)
        if report["verified_points"] != 0 or len(report["controls"]) != 100 or report["complete"]:
            raise RuntimeError("Installed enterprise evaluator returned an incorrect draft result")
        staging_result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                bootstrap,
                "staging-check",
                str(workspace / "staging-inputs"),
                "--json",
            ],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if staging_result.returncode != 2:
            raise RuntimeError("Installed staging checker did not reject blank inputs")
        staging_report = json.loads(staging_result.stdout)
        if (
            staging_report["executionAuthorized"]
            or staging_report["enterprisePointsAwarded"] != 0
            or staging_report["controlCount"] != 100
            or staging_report["inputsComplete"]
        ):
            raise RuntimeError("Installed staging checker granted unsupported authority")
        deploy_check = f"""
import os
import sys
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

sys.path.insert(0, {str(installed)!r})
from certweaver import cli
from certweaver.registry import project_root

root = project_root()
inventory = Path({str(workspace / "deploy-inventory.yml")!r})
config = cli.load_config({str(config)!r})
config['spec']['adapters']['enabled'] = []
import yaml
smoke_config = Path({str(workspace / "deploy-smoke.yml")!r})
smoke_config.write_text(yaml.safe_dump(
    {{k: v for k, v in config.items() if not k.startswith('__')}}
))
args = cli.build_parser().parse_args([
    'deploy', '-c', str(smoke_config), '-i', str(inventory), '--check',
])

def fake_run(command, *, check, env):
    assert check is False
    assert command == [
        'ansible-playbook', '-i', str(inventory),
        str(root / 'playbooks/standalone.yml'), '--check',
    ], command
    assert inventory.is_file()
    assert Path(env['ANSIBLE_CONFIG']) == root / 'ansible.cfg'
    assert env['ANSIBLE_ROLES_PATH'].split(os.pathsep)[0] == str(root / 'roles')
    return CompletedProcess(command, 0)

with patch.object(cli.shutil, 'which', return_value='/fake/ansible-playbook'):
    with patch.object(cli.subprocess, 'run', side_effect=fake_run) as execution:
        assert cli.command_deploy(args) == 0
        execution.assert_called_once()
"""
        print("Checking installed wheel: deployment command and bundled Ansible paths", flush=True)
        subprocess.run(
            [sys.executable, "-I", "-c", deploy_check],
            cwd=workspace,
            env=environment,
            check=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    check_wheel(parser.parse_args().wheel)
