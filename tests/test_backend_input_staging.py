"""Exercise actual adapter input routing without installing an adapter or contacting a cluster."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest
import yaml

from certweaver.registry import project_root

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not shutil.which("ansible-playbook"),
    reason="Adapter input routing requires the Linux Ansible controller",
)


@pytest.mark.parametrize(
    "mode,kind",
    [
        ("rke2-ha", "cluster"),
        ("k3s-ha", "cluster"),
        ("existing-kubernetes", "cluster"),
        ("standalone", "host-container"),
        ("raw", "native"),
        ("docker", "docker"),
    ],
)
def test_actual_role_stages_chart_inputs_before_adapter_and_preserves_native_container_ownership(
    tmp_path, mode, kind
):
    root = project_root()
    enabled = ["step-ca", "openbao-pki", "ejbca-community", "spire", "traefik-acme"]
    if kind == "host-container":
        enabled = enabled[:3]
    elif kind == "native":
        enabled = ["step-ca", "openbao-pki", "spire", "traefik-acme", "caddy-auto-https", "lemur"]
    early = kind in {"cluster", "host-container"}
    source = tmp_path / "reviewed-values"
    source.write_text("synthetic-private-input-canary\n")
    source.chmod(0o600)
    options = {
        slug: {"files": [{"source": str(source), "name": "values.yaml", "mode": "0600"}]}
        for slug in enabled
    }
    if kind == "host-container":
        for slug in enabled[:2]:
            options[slug]["installMode"] = "docker"

    def confined(value):
        if isinstance(value, str):
            return value.replace("/etc/certweaver", str(tmp_path / "inputs"))
        if isinstance(value, list):
            return [confined(item) for item in value]
        if isinstance(value, dict):
            result = {
                key: confined(item) for key, item in value.items() if key not in {"owner", "group"}
            }
            include = result.get("ansible.builtin.include_tasks")
            if include in {"_stage_files.yml", "_stage_backend_files.yml"}:
                result["ansible.builtin.include_tasks"] = str(tmp_path / include)
            elif include == "adapters/{{ item }}.yml":
                result["ansible.builtin.include_tasks"] = str(tmp_path / "observe-input.yml")
            elif include in {"_container.yml", "_native_service.yml"}:
                result.pop("ansible.builtin.include_tasks")
                result["ansible.builtin.assert"] = {"that": [True]}
            return result
        return value

    for name in ["_stage_files.yml", "_stage_backend_files.yml"]:
        tasks = confined(yaml.safe_load((root / "roles/pki_adapter/tasks" / name).read_text()))
        (tmp_path / name).write_text(yaml.safe_dump(tasks))
    observe = [
        {
            "name": "Observe input before adapter execution",
            "ansible.builtin.stat": {"path": str(tmp_path / "inputs") + "/{{ item }}/values.yaml"},
            "register": "fixture_input",
        },
        {
            "name": "Require the selected backend input delivery contract",
            "ansible.builtin.assert": {
                "that": [
                    "fixture_input.stat.exists == fixture_early_stage",
                    "not fixture_early_stage or fixture_input.stat.mode == '0600'",
                ]
            },
        },
    ]
    (tmp_path / "observe-input.yml").write_text(yaml.safe_dump(observe))
    tasks = confined(yaml.safe_load((root / "roles/pki_adapter/tasks/main.yml").read_text()))
    book = tmp_path / "routing.yml"
    book.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Verify backend inputs with all installation and activation stubbed",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "become": False,
                    "vars": {
                        "ansible_python_interpreter": sys.executable,
                        "ansible_architecture": "x86_64",
                        "certweaver_adapter_arch_map": {"x86_64": "amd64"},
                        "certweaver_adapter_root": str(tmp_path / "root"),
                        "certweaver_mode": mode,
                        "certweaver_environment": "staging",
                        "certweaver_allow_risky_adapters": ["lemur"],
                        "certweaver_enabled_adapters": enabled,
                        "certweaver_adapter_options": options,
                        "certweaver_adapter_start_services": False,
                        "fixture_early_stage": early,
                    },
                    "tasks": tasks,
                }
            ]
        )
    )
    cfg = tmp_path / "ansible.cfg"
    cfg.write_text("[defaults]\n[privilege_escalation]\nbecome=False\n")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("ANSIBLE_", "PYTHON"))
    }
    environment.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible"))
    for attempt in range(2):
        result = subprocess.run(
            [shutil.which("ansible-playbook"), "-i", "localhost,", str(book), "--diff"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "synthetic-private-input-canary" not in result.stdout + result.stderr
        if attempt:
            assert "changed=0" in result.stdout
    for slug in enabled:
        target = tmp_path / "inputs" / slug / "values.yaml"
        assert target.exists() is early
        if early:
            assert target.read_bytes() == source.read_bytes()
