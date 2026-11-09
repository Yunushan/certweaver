"""Qualify opt-in administrative credential export with private synthetic files."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

endpoint_tools = runpy.run_path(str(Path(__file__).with_name("check-operator-endpoint.py")))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard(root):
    endpoint_tools["guard"](root)
    role = root / "roles/cluster_addons"
    main = yaml.safe_load((role / "tasks/main.yml").read_text())
    pre = main[0]
    exports = [
        t for t in main if t.get("ansible.builtin.include_tasks") == "_export_kubeconfig.yml"
    ]
    require(
        pre.get("ansible.builtin.include_tasks") == "_kubeconfig_preflight.yml"
        and pre.get("when") == "certweaver_fetch_kubeconfig | bool"
        and len(exports) == 1
        and exports[0].get("when") == pre["when"]
        and not any("ansible.builtin.fetch" in t for t in main),
        "Optional credential export requires early preflight and no raw fetch path",
    )
    private = yaml.safe_load((role / "tasks/_kubeconfig_preflight.yml").read_text())
    export = yaml.safe_load((role / "tasks/_export_kubeconfig.yml").read_text())
    require(
        len(export) == 1
        and export[0].get("no_log") is True
        and export[0].get("diff") is False
        and export[0].get("when") == "not ansible_check_mode",
        "Credential content must stay private and absent from check-mode transfer",
    )
    tasks = export[0]["block"]
    require(len(tasks) == 7, "Credential source/transfer/verification stages are mandatory")
    require(
        all(
            t.get("no_log", True) is True and t.get("diff", False) is False
            for t in [*tasks, *export[0]["always"]]
        ),
        "Child tasks must not override credential logging protection",
    )
    for task in [private[1], tasks[0], tasks[5], tasks[6]]:
        require(
            task.get("delegate_to") == "localhost"
            and task.get("become") is False
            and task.get("vars")
            == {
                "ansible_connection": "local",
                "ansible_python_interpreter": "{{ ansible_playbook_python }}",
            },
            "Controller operations must use local connection without inherited escalation",
        )
    require(
        "not (lookup('ansible.builtin.config', 'DEFAULT_DEBUG') | bool)"
        in private[0]["ansible.builtin.assert"]["that"]
        and private[1].get("no_log") is True
        and private[1].get("check_mode") is False,
        "Preflight must reject debug logging and validate paths without check-mode writes",
    )
    source = tasks[1]["ansible.builtin.stat"]
    require(
        source.get("follow") is False
        and source.get("get_checksum") is True
        and source.get("checksum_algorithm") == "sha256"
        and tasks[2]["ansible.builtin.assert"]["that"]
        == [
            "certweaver_kubeconfig_export_source.stat.isreg | default(false)",
            "not (certweaver_kubeconfig_export_source.stat.islnk | default(false))",
            "certweaver_kubeconfig_export_source.stat.uid == 0",
            "certweaver_kubeconfig_export_source.stat.nlink == 1",
            "certweaver_kubeconfig_export_source.stat.mode == '0600'",
            "certweaver_kubeconfig_export_source.stat.size > 0",
            "certweaver_kubeconfig_export_source.stat.size <= 1048576",
            "certweaver_kubeconfig_export_source.stat.checksum is match('^[a-f0-9]{64}$')",
        ],
        "Source must be a bounded protected file with an inspected SHA-256",
    )
    require(
        tasks[4]["ansible.builtin.assert"]["that"][-1]
        == "(certweaver_kubeconfig_export_blob.content | b64decode | hash('sha256')) == "
        "certweaver_kubeconfig_export_source.stat.checksum",
        "Transferred bytes must match the inspected source",
    )
    publish = tasks[5]["ansible.builtin.copy"]
    require(
        publish.get("mode") == "0600"
        and publish.get("content") == "{{ certweaver_kubeconfig_export_blob.content | b64decode }}"
        and publish.get("dest")
        == "{{ (certweaver_kubeconfig_export_destination.stdout | from_json).destination }}"
        and publish.get("follow") is False
        and publish.get("unsafe_writes") is False
        and publish.get("backup") is False
        and publish.get("force") is True
        and tasks[6]["ansible.builtin.command"]["argv"][-2:]
        == ["--sha256", "{{ certweaver_kubeconfig_export_source.stat.checksum }}"]
        and export[0]["always"][0]["ansible.builtin.set_fact"]
        == {"certweaver_kubeconfig_export_blob": {}, "cacheable": False},
        "Publication must be private/atomic, verified and followed by credential-value cleanup",
    )


def verify(root, output, native):
    guard(root)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "KUBE", "PYTHON"))}
    env.update(
        ANSIBLE_ROLES_PATH=str(root / "roles"),
        ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
        ANSIBLE_NOCOLOR="1",
        TMPDIR=str(native),
        PYTHONDONTWRITEBYTECODE="1",
    )
    role = root / "roles/cluster_addons"
    main = yaml.safe_load((role / "tasks/main.yml").read_text())
    source_calls = [
        main[0],
        next(t for t in main if t.get("ansible.builtin.include_tasks") == "_export_kubeconfig.yml"),
    ]
    observations = []
    cases = [
        "rke2",
        "default-destination",
        "k3s",
        "existing",
        "repeat",
        "rotation",
        "disabled",
        "check-mode",
        "parent-link",
        "file-link",
        "hardlink",
        "public-parent",
        "writable-ancestor",
        "public-file",
        "foreign-file",
        "source-link",
        "source-public",
        "source-empty",
        "source-oversize",
        "debug",
        "localhost-alias",
    ]
    for case in cases:
        directory = native / case
        directory.mkdir(mode=0o700)
        home = directory / "home"
        home.mkdir(mode=0o700)
        env["HOME"] = str(home)
        source = directory / "source-kubeconfig"
        # Runtime fixture data only; never a credential for any service.
        canary = "synthetic-private-export-" + os.urandom(12).hex()
        payload = (
            "apiVersion: v1\nkind: Config\nusers:\n- name: fixture\n  user:\n"
            "    token: " + canary + "\nliteral: '{{ 7*7 }}'\n"
        ).encode()
        source.write_bytes(payload)
        source.chmod(0o600)
        private = directory / "private"
        private.mkdir(mode=0o700)
        target = private / "kubeconfig"
        if case == "default-destination":
            target = home / ".config/certweaver/fixture-export/kubeconfig"
        sentinel = directory / "sentinel"
        sentinel.write_bytes(b"original unrelated content")
        sentinel.chmod(0o600)
        if case == "parent-link":
            private.rmdir()
            private.symlink_to(home, target_is_directory=True)
        elif case == "file-link":
            target.symlink_to(sentinel)
        elif case == "hardlink":
            os.link(sentinel, target)
        elif case == "public-parent":
            private.chmod(0o755)
        elif case == "writable-ancestor":
            directory.chmod(0o777)
        elif case in {"public-file", "foreign-file"}:
            target.write_bytes(b"prior controlled content")
            target.chmod(0o644 if case == "public-file" else 0o600)
            if case == "foreign-file":
                os.chown(target, 65534, 65534)
        elif case == "source-link":
            source.unlink()
            source.symlink_to(sentinel)
        elif case == "source-public":
            source.chmod(0o644)
        elif case == "source-empty":
            source.write_bytes(b"")
        elif case == "source-oversize":
            source.write_bytes(b"x" * (1048576 + 1))
        elif case in {"check-mode", "disabled"}:
            source.unlink()  # Success must not depend on reading a credential.
        values = {
            "ansible_python_interpreter": sys.executable,
            "ansible_remote_tmp": str(native / "remote"),
            "certweaver_mode": "k3s-ha"
            if case == "k3s"
            else ("existing-kubernetes" if case == "existing" else "rke2-ha"),
            "certweaver_deployment_name": "fixture-export",
            "certweaver_fetch_kubeconfig": case != "disabled",
            "certweaver_local_kubeconfig_path": str(target),
            "certweaver_kubeconfig_path": str(source),
        }
        if case == "default-destination":
            values.pop("certweaver_local_kubeconfig_path")
        calls = []
        for i, original in enumerate(source_calls):
            task = copy.deepcopy(original)
            task["ansible.builtin.include_role"] = {
                "name": "cluster_addons",
                "tasks_from": task.pop("ansible.builtin.include_tasks"),
            }
            calls.append(task)
            if i == 0:
                calls.append(
                    {
                        "name": "Observe advancement after export preflight",
                        "ansible.builtin.debug": {"msg": "EXPORT_PREFLIGHT_ADVANCED"},
                    }
                )
        inventory = directory / "inventory.yml"
        inventory.write_text(
            yaml.safe_dump(
                {
                    "all": {
                        "hosts": {
                            "fixture-remote": {"ansible_connection": "local"},
                            "localhost": {"ansible_connection": "ssh", "ansible_host": "192.0.2.1"}
                            if case == "localhost-alias"
                            else {"ansible_connection": "local"},
                        }
                    }
                }
            )
        )
        playbook = directory / "fixture.yml"
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Synthetic private credential export",
                        "hosts": "fixture-remote",
                        "gather_facts": False,
                        "become": False,
                        "vars": values,
                        "tasks": calls,
                    }
                ]
            )
        )
        count = 2 if case in {"repeat", "rotation"} else 1
        for iteration in range(count):
            if iteration and case == "rotation":
                payload += b"# synthetic rotation\n"
                source.write_bytes(payload)
            command = [
                str(Path(sys.executable).with_name("ansible-playbook")),
                "-i",
                str(inventory),
                str(playbook),
                "--diff",
                "-vvv",
            ]
            if case == "check-mode":
                command.append("--check")
            local_env = {**env, **({"ANSIBLE_DEBUG": "true"} if case == "debug" else {})}
            r = subprocess.run(command, cwd=root, env=local_env, capture_output=True, timeout=120)
            log = r.stdout + b"\n" + r.stderr
            label = case + "-" + str(iteration)
            (output / (label + ".log")).write_bytes(log)
            success = case in {
                "rke2",
                "default-destination",
                "k3s",
                "existing",
                "repeat",
                "rotation",
                "disabled",
                "check-mode",
                "localhost-alias",
            }
            require((r.returncode == 0) == success, "Unexpected export case result: " + label)
            require(
                canary.encode() not in log, "Private credential entered public output: " + label
            )
            exported = success and case not in {"disabled", "check-mode"}
            if exported:
                require(
                    target.read_bytes() == payload
                    and target.stat().st_uid == os.geteuid()
                    and target.stat().st_mode & 0o777 == 0o600
                    and target.parent.stat().st_mode & 0o777 == 0o700,
                    "Exported bytes, ownership or private modes differ",
                )
            elif not target.exists() or case in {
                "source-link",
                "source-public",
                "source-empty",
                "source-oversize",
                "debug",
            }:
                require(not target.exists(), "Rejected or skipped export created a credential file")
            if case == "repeat" and iteration:
                require(re.search(rb"changed=0\s", log), "Unchanged export was not idempotent")
            if case in {
                "parent-link",
                "file-link",
                "hardlink",
                "public-parent",
                "writable-ancestor",
                "public-file",
                "foreign-file",
                "debug",
            }:
                require(
                    b'"msg": "EXPORT_PREFLIGHT_ADVANCED"' not in log,
                    "Unsafe export destination advanced into the add-on phase",
                )
            require(
                sentinel.read_bytes() == b"original unrelated content", "Unrelated file changed"
            )
            if case in {"public-file", "foreign-file"}:
                require(
                    target.read_bytes() == b"prior controlled content"
                    and target.stat().st_mode & 0o777 == (0o644 if case == "public-file" else 0o600)
                    and target.stat().st_uid == (0 if case == "public-file" else 65534),
                    "Rejected existing credential file was modified",
                )
            observations.append(
                {
                    "case": label,
                    "exitCode": r.returncode,
                    "expectedResultVerified": True,
                    "privateCanaryAbsentFromPublicOutput": True,
                    "exported": exported,
                    "sourceSha256": hashlib.sha256(payload).hexdigest() if exported else None,
                }
            )
        directory.chmod(0o700)
    result = {
        "scope": "Actual Ansible export tasks/helper and synthetic local root-owned files; "
        "root-controller fixture only, no real credentials, remote SSH/become boundary, "
        "Kubernetes access or production acceptance",
        "observations": observations,
    }
    (output / "kubeconfig-export-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux root for temporary credential ownership fixtures")
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-private-export-") as temporary:
        result = verify(root, output, Path(temporary))
        endpoint = endpoint_tools["verify"](
            root, output, Path(temporary) / "endpoint", args.kubectl
        )
    print("Verified " + str(len(result["observations"])) + " private credential export cases")
    print("Verified " + str(len(endpoint["observations"])) + " operator endpoint/TLS cases")
