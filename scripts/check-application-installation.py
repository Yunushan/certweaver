"""Exercise native Lemur installation with a synthetic application and no service deployment."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import yaml


def verify(root: Path, output: Path, build_python: Path) -> dict:
    if os.geteuid() != 0:
        raise ValueError("The fixture requires root for isolated build/runtime identity checks")
    if not shutil.which("sudo") or not shutil.which("git"):
        raise ValueError("The fixture requires Git and sudo")
    work = Path(tempfile.mkdtemp(prefix="certweaver-application-fixture-", dir="/var/tmp"))
    work.chmod(0o755)
    suffix = uuid.uuid4().hex[:8]
    identities = {"lemur-build": "cw-lmrb-" + suffix, "lemur": "cw-lmrr-" + suffix}
    for name in identities.values():
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise ValueError("Fixture identity already exists")
    for directory in ["homes", "tools", "systemd", "source/src/lemur/migrations", "templates"]:
        (work / directory).mkdir(parents=True, exist_ok=True)
    build_python = build_python.resolve()
    runtime_root = build_python.parent.parent
    if runtime_root == Path("/usr"):
        raise ValueError("Provide a relocatable build Python for the fixture")
    shutil.copytree(
        runtime_root, work / "python", ignore=shutil.ignore_patterns("site-packages", "__pycache__")
    )
    build_python = work / "python/bin" / build_python.name
    source = work / "source"
    (source / "setup.py").write_text(
        "from setuptools import setup,find_packages\n"
        "setup(name='lemur',version='0.0.0',packages=find_packages('src'),"
        "package_dir={'':'src'},entry_points={'console_scripts':['lemur=lemur:main']})\n"
    )
    (source / "src/lemur/__init__.py").write_text(
        "def main():\n"
        "    import pathlib,sys\n"
        "    if 'upgrade' in sys.argv:\n"
        "        assert pathlib.Path(sys.argv[-1]).is_dir()\n"
        "    print('Synthetic application invocation completed')\n"
    )
    (source / "src/lemur/migrations/__init__.py").write_text("")
    (source / "package-lock.json").write_text(
        '{"name":"synthetic-application","lockfileVersion":3,"packages":{}}'
    )
    environment = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("ANSIBLE_", "PYTHON", "PIP_", "GIT_"))
    }
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    for args in [
        ["init", "--quiet"],
        ["add", "--all"],
        [
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Synthetic installation fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Synthetic installation fixture; not a release",
        ],
    ]:
        subprocess.run(["git", *args], cwd=source, env=environment, check=True, capture_output=True)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, env=environment, text=True
    ).strip()
    selected = []
    for line in (root / "ci/python-build.lock").read_text().replace("\\\n", " ").splitlines():
        if any(
            line.startswith(name + "==") for name in ["pip", "setuptools", "wheel", "packaging"]
        ):
            selected.append(line)
    if len(selected) != 4:
        raise ValueError("Fixture build lock must bind all four build tools")
    lock = work / "requirements.lock"
    lock.write_text("\n".join(selected) + "\n")
    config = work / "application-config.py"
    canary = "synthetic-private-" + uuid.uuid4().hex
    config.write_text("PRIVATE_FIXTURE_VALUE = " + repr(canary) + "\n")
    config.chmod(0o600)
    npm = work / "tools/npm"
    npm.write_text(
        "#!" + str(build_python) + "\n"
        "import pathlib,sys\n"
        "assert sys.argv[1:]==['ci','--ignore-scripts','--strict-ssl=true',"
        "'--audit=false','--fund=false']\n"
        "path=pathlib.Path('node_modules/.bin/gulp');path.parent.mkdir(parents=True,exist_ok=True)\n"
        'path.write_text(\'#!/bin/sh\\nset -eu\\ntest "$1" = build -o "$1" = package\\n\')\n'
        "path.chmod(0o750)\n"
    )
    npm.chmod(0o755)
    tasks = yaml.safe_load((root / "roles/pki_adapter/tasks/_lemur_native.yml").read_text())
    effects = []

    def confined(value, key=""):
        if isinstance(value, str):
            if (
                key in {"owner", "group", "become_user", "certweaver_file_group"}
                and value in identities
            ):
                return identities[value]
            return (
                value.replace("/opt/certweaver", str(work / "opt"))
                .replace("/etc/certweaver", str(work / "etc"))
                .replace("/etc/systemd/system", str(work / "systemd"))
            )
        if isinstance(value, list):
            return [confined(item, key) for item in value]
        if isinstance(value, dict):
            result = {field: confined(item, field) for field, item in value.items()}
            if "ansible.builtin.user" in result:
                result["ansible.builtin.user"]["home"] = str(work / "homes") + "/{{ lemur_user }}"
                result["loop"] = list(identities.values())
            if "ansible.builtin.command" in result:
                args = result["ansible.builtin.command"].get("argv", [])
                if args and args[0] == "/usr/bin/python3.12":
                    args[0] = str(build_python)
                if args and args[0] == "npm":
                    args[0] = str(npm)
                if args and args[-1] == "lemur" and "freeze-application.py" in str(args):
                    args[-1] = identities["lemur"]
            for module in ["ansible.builtin.copy", "ansible.builtin.template"]:
                if module not in result:
                    continue
                original = result[module].get("src")
                if original in {"validate-build-lock.py", "freeze-application.py"}:
                    result[module]["src"] = str(root / "roles/pki_adapter/files" / original)
                if original == "lemur.service.j2":
                    result[module]["src"] = str(work / "templates/lemur.service.j2")
            if result.get("ansible.builtin.include_tasks") == "_stage_files.yml":
                result["ansible.builtin.include_tasks"] = str(work / "stage-files.yml")
            if result.get("ansible.builtin.include_tasks") == "_activate_service.yml":
                result["ansible.builtin.include_tasks"] = str(work / "activate-service.yml")
            if "ansible.builtin.systemd" in result:
                decision = result.pop("ansible.builtin.systemd")
                effects.append(decision)
                result["vars"] = {**result.get("vars", {}), "fixture_systemd_state": decision}
                result["ansible.builtin.copy"] = {
                    "content": "{{ fixture_systemd_state | to_json }}",
                    "dest": str(work / "activation-decision.json"),
                    "mode": "0600",
                }
            return result
        return value

    template = (root / "roles/pki_adapter/templates/lemur.service.j2").read_text()
    template = template.replace("User=lemur", "User=" + identities["lemur"]).replace(
        "Group=lemur", "Group=" + identities["lemur"]
    )
    (work / "templates/lemur.service.j2").write_text(template)
    stage = confined(
        yaml.safe_load((root / "roles/pki_adapter/tasks/_stage_files.yml").read_text())
    )
    (work / "stage-files.yml").write_text(yaml.safe_dump(stage))
    activation = confined(
        yaml.safe_load((root / "roles/pki_adapter/tasks/_activate_service.yml").read_text())
    )
    (work / "activate-service.yml").write_text(yaml.safe_dump(activation))
    tasks = confined(tasks)
    options = {
        "requirementsFile": str(lock),
        "configFile": str(config),
        "runMigrations": False,
        "migrationHost": "localhost",
    }
    inventory = work / "inventory.yml"
    inventory.write_text(
        yaml.safe_dump(
            {
                "all": {
                    "hosts": {
                        "localhost": {
                            "ansible_connection": "local",
                            "ansible_python_interpreter": str(build_python),
                        }
                    }
                }
            }
        )
    )
    configuration = work / "ansible.cfg"
    configuration.write_text("[defaults]\n[privilege_escalation]\nbecome=False\n")
    environment.update(
        ANSIBLE_CONFIG=str(configuration),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_LOCAL_TEMP=str(work / "ansible"),
    )
    observations = []
    try:
        for phase in [
            "install",
            "repeat",
            "activate",
            "active-repeat",
            "prepare-update",
            "reactivate",
        ]:
            options["runMigrations"] = phase == "activate"
            start = phase in {"activate", "active-repeat", "reactivate"}
            decision_file = work / "activation-decision.json"
            before = decision_file.read_bytes() if decision_file.exists() else None
            if phase == "prepare-update":
                config.write_text(config.read_text() + "# reviewed configuration update\n")
            book = work / "playbook.yml"
            book.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Exercise synthetic native application installation",
                            "hosts": "localhost",
                            "gather_facts": False,
                            "become": False,
                            "vars": {
                                "certweaver_adapter_options": {"lemur": options},
                                "certweaver_adapter_source_path": str(source),
                                "certweaver_adapter_source_commit": commit,
                                "certweaver_adapter_start_services": start,
                            },
                            "tasks": tasks,
                        }
                    ]
                )
            )
            result = subprocess.run(
                [
                    str(Path(sys.executable).with_name("ansible-playbook")),
                    "-i",
                    str(inventory),
                    str(book),
                    "--diff",
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                timeout=600,
            )
            log = result.stdout + b"\n" + result.stderr
            (output / ("native-application-" + phase + ".log")).write_bytes(log)
            if result.returncode or canary.encode() in log:
                raise ValueError("Application installation fixture failed: " + phase)
            after = decision_file.read_bytes() if decision_file.exists() else None
            if not start and after != before:
                raise ValueError("Unrequested application activation")
            if start:
                expected = "started" if phase == "active-repeat" else "restarted"
                if json.loads(after)["state"] != expected:
                    raise ValueError(
                        "Application activation did not reconcile prepared input changes"
                    )
            if phase == "repeat" and b"changed=0" not in log:
                raise ValueError("Application installation was not idempotent")
            observations.append(
                {"phase": phase, "returnCode": result.returncode, "realServiceStarted": False}
            )
        release = next((work / "opt/lemur").glob(commit + "-*"))
        runtime_uid = pwd.getpwnam(identities["lemur"]).pw_uid
        runtime_gid = grp.getgrnam(identities["lemur"]).gr_gid
        probe = subprocess.run(
            ["sudo", "-u", identities["lemur"], "test", "-w", str(release)], capture_output=True
        )
        if release.stat().st_uid != 0 or probe.returncode == 0:
            raise ValueError("Runtime identity can modify application code")
        for name, readable in [(identities["lemur"], True), (identities["lemur-build"], False)]:
            probe = subprocess.run(
                ["sudo", "-u", name, "test", "-r", str(work / "etc/lemur/config.py")],
                capture_output=True,
            )
            if (probe.returncode == 0) != readable:
                raise ValueError("Application configuration identity isolation failed")
        return {
            "scope": (
                "Real Ansible/Git/venv/pip with synthetic application and npm; "
                "no Lemur, database or systemd deployment"
            ),
            "syntheticSourceCommit": commit,
            "requirementsSha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "observations": observations,
            "applicationOwnedByRoot": True,
            "runtimeCodeWriteDenied": True,
            "buildIdentitySecretReadDenied": True,
            "runtimeIdentity": {"uid": runtime_uid, "gid": runtime_gid},
            "workDirectory": str(work),
            "sourceSha256": {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in [
                    "roles/pki_adapter/tasks/_lemur_native.yml",
                    "roles/pki_adapter/files/freeze-application.py",
                    "roles/pki_adapter/files/validate-build-lock.py",
                    "roles/pki_adapter/templates/lemur.service.j2",
                    "roles/pki_adapter/tasks/_activate_service.yml",
                ]
            },
        }
    finally:
        # Only identities generated by this invocation are eligible for cleanup.
        # Their home paths were confined to the owned fixture directory; no
        # recursive home removal or shared user modification is performed.
        for name in identities.values():
            try:
                record = pwd.getpwnam(name)
            except KeyError:
                continue
            if Path(record.pw_dir).parent != work / "homes":
                raise ValueError("Refusing cleanup of an identity outside this fixture")
            subprocess.run(["userdel", name], check=True, capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--build-python", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Output must be a fresh directory")
    args.output_dir.mkdir(parents=True, mode=0o700)
    result = verify(Path(__file__).resolve().parents[1], args.output_dir, args.build_python)
    (args.output_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
