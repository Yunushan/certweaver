"""Exercise actual adapter image gates, templates and service decisions without containers."""

from __future__ import annotations

import argparse
import copy
import json
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(root: Path, output: Path, temporary: Path) -> dict:
    walk = runpy.run_path(str(root / "scripts/check-adapter-acquisition.py"))["tasks"]
    definitions = []
    for slug, key, template, repository in [
        ("step-ca", "step_ca_image", "step-ca.container.j2", "docker.io/smallstep/step-ca"),
        ("openbao-pki", "openbao_image", "openbao.container.j2", "docker.io/openbao/openbao"),
        ("ejbca-community", "ejbca_image", "ejbca.container.j2", "docker.io/keyfactor/ejbca-ce"),
    ]:
        source = root / "roles/pki_adapter/tasks/adapters" / (slug + ".yml")
        document = yaml.safe_load(source.read_text())
        entries = list(walk(document))
        gate = copy.deepcopy(
            next(t for t in entries if t.get("vars", {}).get("certweaver_require_image_digest"))
        )
        gate["ansible.builtin.include_tasks"] = str(
            root / "roles/pki_adapter/tasks/_require_version.yml"
        )
        render = copy.deepcopy(
            next(t for t in entries if t.get("ansible.builtin.template", {}).get("src") == template)
        )
        render.pop("notify", None)
        render["ansible.builtin.template"].update(
            src=str(root / "roles/pki_adapter/templates" / template),
            dest=str(temporary / template),
        )
        activate = next(t for t in document if t["name"].startswith("Activate "))
        require(
            "certweaver_adapter_start_services | bool"
            in (activate["when"] if isinstance(activate["when"], list) else [activate["when"]]),
            f"{slug}: service activation lost its explicit operator opt-in",
        )
        service = next(
            t for t in walk(activate["block"]) if "name" in t.get("ansible.builtin.systemd", {})
        )
        decision = {
            "name": "Observe source service state without executing systemd",
            "ansible.builtin.set_fact": {
                "fixture_service_state": service["ansible.builtin.systemd"]["state"]
            },
            "when": activate["when"],
        }
        definitions.append((slug, key, repository, gate, render, decision))

    configuration = copy.deepcopy(
        next(
            t
            for t in entries_for(root, walk, "openbao-pki")
            if t.get("ansible.builtin.template", {}).get("src") == "openbao.hcl.j2"
        )
    )
    configuration["ansible.builtin.template"].update(
        src=str(root / "roles/pki_adapter/templates/openbao.hcl.j2"),
        dest=str(temporary / "openbao.hcl"),
    )
    tasks = []
    observations = []
    for case in [
        "initial",
        "repeat",
        "image-change",
        "repeat-updated",
        "configuration-change",
        "disabled",
    ]:
        digest = "sha256:" + ("A" if case in {"initial", "repeat"} else "B") * 64
        tasks.append(
            {
                "name": f"Select synthetic {case} inputs",
                "ansible.builtin.set_fact": {
                    "certweaver_adapter_versions": {key: digest for _, key, *_ in definitions},
                    "certweaver_adapter_start_services": case != "disabled",
                    "certweaver_adapter_options": {
                        "openbao-pki": {"apiAddress": "https://changed.example.invalid:8200"}
                    }
                    if case in {"configuration-change", "disabled"}
                    else {},
                },
            }
        )
        tasks.append(configuration)
        for slug, _key, repository, gate, render, decision in definitions:
            expected = (
                None
                if case == "disabled"
                else (
                    "restarted"
                    if case in {"initial", "image-change"}
                    or (case == "configuration-change" and slug == "openbao-pki")
                    else "started"
                )
            )
            tasks.extend(
                [
                    gate,
                    render,
                    {
                        "name": "Reset observed state",
                        "ansible.builtin.set_fact": {"fixture_service_state": None},
                    },
                    decision,
                    {
                        "name": "Read rendered synthetic unit",
                        "ansible.builtin.slurp": {
                            "src": render["ansible.builtin.template"]["dest"]
                        },
                        "register": "fixture_unit",
                    },
                    {
                        "name": f"Verify {slug} {case} image and source service decision",
                        "ansible.builtin.assert": {
                            "that": [
                                "fixture_service_state == fixture_expected_state",
                                "fixture_image_line in "
                                + "(fixture_unit.content | b64decode).splitlines()",
                            ]
                        },
                        "vars": {
                            "fixture_expected_state": expected,
                            "fixture_image_line": "Image=" + repository + "@" + digest.lower(),
                        },
                    },
                ]
            )
            observations.append(
                {"adapter": slug, "case": case, "expectedServiceDecision": expected}
            )

    def execute(label: str, selected: list[dict], variables: dict) -> subprocess.CompletedProcess:
        path = temporary / (label + ".yml")
        path.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Synthetic image configuration probe; no service execution",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "become": False,
                        "vars": {
                            "ansible_python_interpreter": sys.executable,
                            "ansible_host": "127.0.0.1",
                            "certweaver_step_ca_mode": "docker",
                            "certweaver_openbao_mode": "docker",
                            **variables,
                        },
                        "tasks": selected,
                    }
                ]
            )
        )
        result = subprocess.run(
            [str(Path(sys.executable).parent / "ansible-playbook"), "-i", "localhost,", str(path)],
            cwd=root,
            capture_output=True,
            timeout=120,
            check=False,
        )
        (output / (label + ".log")).write_bytes(result.stdout + b"\n" + result.stderr)
        return result

    result = execute("render-and-reconcile", tasks, {})
    require(
        result.returncode == 0, "Container render/decision verification failed; inspect local log"
    )
    negative = []
    for slug, key, _, gate, *_ in definitions:
        for name, value in [
            ("missing", ""),
            ("mutable-tag", "v1.2.3"),
            ("bad-digest", "sha256:123"),
        ]:
            label = slug + "-" + name
            result = execute(label, [gate], {"certweaver_adapter_versions": {key: value}})
            require(result.returncode != 0, label + ": invalid image input passed the actual gate")
            require(
                b"reviewed sha256 digest" in result.stdout, label + ": unexpected failure reason"
            )
            negative.append({"adapter": slug, "case": name, "exitCode": result.returncode})
    record = {
        "scope": (
            "Synthetic local Ansible input gates, actual template output and source service-state "
            "decisions only; no image resolution/pull, container, systemd operation "
            "or production approval"
        ),
        "observations": observations,
        "rejectedInputs": negative,
        "systemdExecuted": False,
        "containersStarted": False,
    }
    (output / "container-configuration-result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def entries_for(root, walk, slug):
    return walk(
        yaml.safe_load((root / "roles/pki_adapter/tasks/adapters" / (slug + ".yml")).read_text())
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error(
            "Use isolated Linux with root permissions for the source template ownership checks"
        )
    if not output.resolve().is_relative_to(root) or output.exists() or output.is_symlink():
        parser.error("The output directory must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-container-config-") as temporary:
        verify(root, output, Path(temporary))
    print(
        "Container image gates, rendered digests and service decisions verified; "
        "no containers started"
    )
