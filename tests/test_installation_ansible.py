"""Run real installation tasks against an isolated synthetic Docker executable.

No image is pulled and no application is deployed. This qualifies Ansible
rendering/reconciliation and fail-closed inputs, not Docker or CA runtime health.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from certweaver.registry import project_root

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not shutil.which("ansible-playbook"),
    reason="Real Ansible installation fixtures require a POSIX control environment",
)
IMAGE = "registry.example.invalid/pki/application@sha256:" + "a" * 64


def exercise(tmp_path: Path, slug: str, runtime: dict, *, start: bool):
    root = project_root()
    executable = tmp_path / "docker"
    executable.write_text(
        "#!"
        + sys.executable
        + "\n"
        + r"""
import hashlib,json,pathlib,sys,yaml
root=pathlib.Path(__file__).parent
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\n')
if args==['compose','version','--short']:
    print('2.40.0'); raise SystemExit(0)
assert args[:2]==['compose','-f']
path=pathlib.Path(args[2]); model=yaml.safe_load(path.read_text())
assert model['services']
action=args[3:]
assert action in [['config','--quiet'],['pull'],['up','-d','--wait','--wait-timeout','300']]
if action[0]=='up':
    identity=hashlib.sha256(path.read_bytes()).hexdigest()
    state=root/'running-identity'
    status='Running' if state.exists() and state.read_text()==identity else 'Created'
    print(status,file=sys.stderr)
    state.write_text(identity)
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    tasks = yaml.safe_load((root / "roles/pki_adapter/tasks/_container.yml").read_text())

    def local(value):
        if isinstance(value, str):
            return (
                value.replace("/etc/certweaver/containers", str(tmp_path / "managed"))
                .replace("/usr/local/bin", str(tmp_path / "bin"))
                .replace("docker compose", str(executable) + " compose")
            )
        if isinstance(value, list):
            return [local(v) for v in value]
        if isinstance(value, dict):
            result = {k: local(v) for k, v in value.items() if k not in {"owner", "group"}}
            command = result.get("ansible.builtin.command")
            if isinstance(command, dict) and command.get("argv", [None])[0] == "docker":
                command["argv"][0] = str(executable)
            if result.get("ansible.builtin.include_tasks") == "_stage_files.yml":
                result["ansible.builtin.include_tasks"] = str(tmp_path / "stage-files.yml")
            return result
        return value

    (tmp_path / "bin").mkdir(exist_ok=True)
    staged = yaml.safe_load((root / "roles/pki_adapter/tasks/_stage_files.yml").read_text())
    staged = local(staged)
    staged = json.loads(
        json.dumps(staged).replace("/etc/certweaver/", str(tmp_path / "inputs") + "/")
    )
    (tmp_path / "stage-files.yml").write_text(yaml.safe_dump(staged), encoding="utf-8")
    book = tmp_path / "playbook.yml"
    book.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Qualify actual Compose installation tasks without a runtime",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "become": False,
                    "vars": {
                        "item": slug,
                        "certweaver_adapter_options": {slug: runtime},
                        "certweaver_adapter_start_services": start,
                        "ansible_python_interpreter": sys.executable,
                    },
                    "tasks": local(tasks),
                }
            ]
        ),
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "PYTHON"))}
    configuration = tmp_path / "ansible.cfg"
    configuration.write_text("[defaults]\n[privilege_escalation]\nbecome=False\n", encoding="utf-8")
    env.update(
        PYTHONPATH=str(root / "src"),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_FILTER_PLUGINS=str(root / "roles/pki_adapter/filter_plugins"),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible"),
        ANSIBLE_CONFIG=str(configuration),
    )
    return subprocess.run(
        [shutil.which("ansible-playbook"), "-i", "localhost,", str(book), "--diff"],
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )


@pytest.mark.parametrize("slug,start", [("certbot", True), ("step-ca", False), ("step-ca", True)])
def test_actual_compose_tasks_prepare_and_reconcile_without_unrequested_activation(
    tmp_path, slug, start
):
    runtime = {
        "container": {
            "image": IMAGE,
            "command": ["run", "fixture-private-canary"],
            "healthcheck": {
                "test": ["CMD", "healthcheck"],
                "interval": "10s",
                "timeout": "5s",
                "retries": 3,
            },
        }
    }
    for attempt in range(2):
        result = exercise(tmp_path, slug, runtime, start=start)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "fixture-private-canary" not in result.stdout + result.stderr
        if attempt:
            assert "changed=0" in result.stdout
    model = yaml.safe_load((tmp_path / "managed" / slug / "compose.yml").read_text())
    assert model["services"]["app"]["image"] == IMAGE
    assert (tmp_path / "managed" / slug / "compose.yml").stat().st_mode & 0o777 == 0o600
    calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
    up = [args for args in calls if "up" in args]
    assert len(up) == (2 if start and slug != "certbot" else 0)
    assert (tmp_path / "bin" / ("certweaver-" + slug)).is_file()


@pytest.mark.parametrize(
    "runtime",
    [
        {"container": {"image": "registry.example.invalid/tool:latest", "command": ["run"]}},
        {"container": {"image": IMAGE, "command": ["run"]}},
    ],
)
def test_actual_compose_tasks_reject_unreviewed_image_or_missing_readiness_before_commands(
    tmp_path, runtime
):
    result = exercise(tmp_path, "step-ca", runtime, start=True)
    assert result.returncode != 0
    assert not (tmp_path / "calls.jsonl").exists()


@pytest.mark.parametrize(
    "slug,executable,adapter",
    [
        ("step-ca", "step-ca", None),
        ("openbao-pki", "bao", None),
        ("traefik-acme", "traefik", None),
        ("caddy-auto-https", "caddy", "json"),
        ("caddy-auto-https", "caddy", "caddyfile"),
    ],
)
def test_actual_native_service_tasks_bind_configuration_and_restart_to_installed_bytes(
    tmp_path, slug, executable, adapter
):
    root = project_root()
    (tmp_path / "bin").mkdir()
    (tmp_path / "systemd").mkdir()
    binary = tmp_path / "bin" / executable
    binary.write_text("synthetic installed binary identity\n")
    configuration = tmp_path / "reviewed-config"
    configuration.write_text("synthetic-private-configuration\n")
    configuration.chmod(0o600)
    options = {"serviceConfigFile": str(configuration), "passwordFile": "/private/password"}
    if adapter:
        options["configAdapter"] = adapter

    def confined(value):
        if isinstance(value, str):
            return (
                value.replace("/etc/certweaver", str(tmp_path / "etc"))
                .replace("/etc/systemd/system", str(tmp_path / "systemd"))
                .replace("/usr/local/bin", str(tmp_path / "bin"))
            )
        if isinstance(value, list):
            return [confined(item) for item in value]
        if isinstance(value, dict):
            result = {k: confined(v) for k, v in value.items() if k not in {"owner", "group"}}
            if "ansible.builtin.user" in result:
                result.pop("ansible.builtin.user")
                result["ansible.builtin.assert"] = {"that": [True]}
            if result.get("ansible.builtin.include_tasks") == "_stage_files.yml":
                result["ansible.builtin.include_tasks"] = str(tmp_path / "staging.yml")
            if "ansible.builtin.template" in result:
                result["ansible.builtin.template"]["src"] = str(
                    root / "roles/pki_adapter/templates/native.service.j2"
                )
            if "ansible.builtin.systemd" in result:
                decision = result.pop("ansible.builtin.systemd")
                result["vars"] = {"fixture_state": decision["state"]}
                result["ansible.builtin.copy"] = {
                    "content": "{{ fixture_state }}",
                    "dest": str(tmp_path / "decision"),
                    "mode": "0600",
                }
            return result
        return value

    tasks = confined(
        yaml.safe_load((root / "roles/pki_adapter/tasks/_native_service.yml").read_text())
    )
    stage = confined(
        yaml.safe_load((root / "roles/pki_adapter/tasks/_stage_files.yml").read_text())
    )
    (tmp_path / "staging.yml").write_text(yaml.safe_dump(stage))
    cfg = tmp_path / "ansible.cfg"
    cfg.write_text("[defaults]\n[privilege_escalation]\nbecome=False\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "PYTHON"))}
    env.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible"))
    for phase, start, expected in [
        ("prepare", False, None),
        ("activate", True, "restarted"),
        ("repeat", True, "started"),
        ("binary-change", True, "restarted"),
        ("repeat-after-change", True, "started"),
    ]:
        if phase == "binary-change":
            binary.write_text("changed approved binary identity\n")
        book = tmp_path / "native.yml"
        book.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Exercise native service decisions without systemd",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "become": False,
                        "vars": {
                            "item": slug,
                            "ansible_python_interpreter": sys.executable,
                            "certweaver_adapter_options": {slug: options},
                            "certweaver_adapter_start_services": start,
                        },
                        "tasks": tasks,
                    }
                ]
            )
        )
        result = subprocess.run(
            [shutil.which("ansible-playbook"), "-i", "localhost,", str(book), "--diff"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "synthetic-private-configuration" not in result.stdout + result.stderr
        decision = tmp_path / "decision"
        assert (decision.read_text() if decision.exists() else None) == expected
    unit = (tmp_path / "systemd" / ("certweaver-" + slug + ".service")).read_text()
    if slug == "traefik-acme":
        assert "/config.yaml" in unit
    if slug == "openbao-pki":
        assert "/config.hcl" in unit and "MemorySwapMax=0" in unit
    if adapter == "caddyfile":
        assert "--adapter caddyfile" in unit


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_actual_freeipa_primary_input_tasks_protect_passwords_without_joining_a_domain(
    tmp_path, mode
):
    root = project_root()
    secret = "  synthetic-private-password  "
    password = tmp_path / "password"
    password.write_text(secret + "\n")
    password.chmod(mode)
    role = yaml.safe_load(
        (root / "roles/pki_adapter/tasks/adapters/freeipa-certmonger.yml").read_text()
    )
    primary = next(task for task in role if "block" in task)
    expectation = primary["block"][-1].pop("ansible.builtin.expect")
    assert "password" not in expectation["command"].lower()
    primary["block"][-1]["vars"] = {"fixture_responses": expectation["responses"]}
    primary["block"][-1]["ansible.builtin.assert"] = {
        "that": [
            "fixture_responses['(?i)Directory Manager password:'] == fixture_expected",
            "fixture_responses['(?i)IPA admin password:'] == fixture_expected",
            "fixture_responses['(?i)Password \\(confirm\\):'] == "
            "[fixture_expected, fixture_expected]",
        ]
    }
    # Only the synthetic file's current owner changes; production still requires root.
    for task in primary["block"]:
        assertions = task.get("ansible.builtin.assert", {}).get("that", [])
        task.get("ansible.builtin.assert", {})["that"] = [
            expression.replace("stat.uid == 0", "stat.uid == " + str(os.getuid()))
            for expression in assertions
        ]
    cfg = tmp_path / "ansible.cfg"
    cfg.write_text("[defaults]\n[privilege_escalation]\nbecome=False\n")
    book = tmp_path / "primary.yml"
    book.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Validate private FreeIPA inputs without domain installation",
                    "hosts": "localhost",
                    "connection": "local",
                    "become": False,
                    "gather_facts": False,
                    "vars": {
                        "ansible_python_interpreter": sys.executable,
                        "fixture_expected": secret,
                        "certweaver_freeipa_role": "server",
                        "certweaver_adapter_start_services": True,
                        "certweaver_freeipa_options": {
                            "configureServer": True,
                            "realm": "EXAMPLE.TEST",
                            "domain": "example.test",
                            "hostname": "ipa.example.test",
                            "directoryManagerPasswordFile": str(password),
                            "adminPasswordFile": str(password),
                        },
                    },
                    "tasks": [primary],
                }
            ]
        )
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "PYTHON"))}
    env.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible"))
    result = subprocess.run(
        [shutil.which("ansible-playbook"), "-i", "localhost,", str(book), "--diff"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert (result.returncode == 0) is (mode == 0o600), result.stdout + result.stderr
    assert secret not in result.stdout + result.stderr
