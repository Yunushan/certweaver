"""Qualify production snapshot preflight and private transfer in owned fixtures."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import yaml

PRODUCTION = "certweaver_environment | default('production') == 'production'"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def caller(task):
    return {k: v for k, v in task.items() if k != "name"} == {
        "ansible.builtin.include_role": {"name": "snapshot_config"},
        "tags": ["always"],
    }


def snapshot_block(root):
    return next(
        t
        for t in load(root / "roles/cluster_addons/tasks/main.yml")
        if t["name"] == "Reconcile RKE2 S3 snapshot secret"
    )


def guard(root):
    role = load(root / "roles/snapshot_config/tasks/main.yml")
    require(len(role) == 1, "Snapshot validation must have one unconditional policy block")
    policy = role[0]
    require(
        set(policy) == {"name", "tags", "when", "block"}
        and policy["tags"] == ["always"]
        and policy["when"] == ["certweaver_mode == 'rke2-ha'", PRODUCTION],
        "Production RKE2 validation must not be bypassed by disabled backups or tags",
    )
    assertion, command, receipt = policy["block"]
    require(
        assertion["ansible.builtin.assert"]["that"]
        == [
            "not (lookup('ansible.builtin.config', 'DEFAULT_DEBUG') | bool)",
            "certweaver_rke2_etcd_snapshot_enabled | default(true) | bool",
            "certweaver_rke2_etcd_s3_enabled | default(false) | bool",
            "certweaver_rke2_etcd_s3_config_file is defined",
            "certweaver_rke2_etcd_s3_config_file is string",
            "certweaver_rke2_etcd_s3_config_file | length > 0",
        ],
        "Production requires scheduled off-host snapshots, explicit input and disabled debug",
    )
    require(
        command["ansible.builtin.command"]
        == {
            "argv": [
                "{{ ansible_playbook_python }}",
                "-m",
                "certweaver.snapshot",
                "{{ certweaver_rke2_etcd_s3_config_file }}",
            ]
        }
        and command.get("delegate_to") == "localhost"
        and command.get("become") is False
        and command.get("vars")
        == {
            "ansible_connection": "local",
            "ansible_python_interpreter": "{{ ansible_playbook_python }}",
        }
        and command.get("changed_when") is False
        and command.get("check_mode") is False
        and command.get("diff") is False
        and command.get("register") == "certweaver_snapshot_validation",
        "Snapshot input must be read-only, local, unprivileged and validated even in check mode",
    )
    require(
        receipt.get("ansible.builtin.set_fact")
        == {
            "certweaver_snapshot_policy": "{{ certweaver_snapshot_validation.stdout | from_json }}"
        },
        "Retain only the validator's exact input identity",
    )
    for task in policy["block"]:
        require(
            task.get("no_log") is True
            and not set(task).intersection(
                {"when", "ignore_errors", "ignore_unreachable", "failed_when", "environment"}
            ),
            "Validation and private diagnostics must not be skipped or weakened",
        )
    for name in ["rke2-ha", "upgrade"]:
        first = load(root / f"playbooks/{name}.yml")[0]
        require(
            len(first.get("pre_tasks", [])) == 1
            and caller(first["pre_tasks"][0])
            and first.get("hosts") == "cluster_servers"
            and first.get("any_errors_fatal") is True,
            "Snapshot validation must precede all managed fleet observation/mutation",
        )
    require(
        caller(load(root / "roles/rke2_server/tasks/main.yml")[2]),
        "Standalone RKE2 role requires snapshot preflight before host changes",
    )
    require(
        caller(load(root / "roles/cluster_addons/tasks/main.yml")[1]),
        "Standalone add-ons require snapshot preflight before Helm/secret changes",
    )
    block = snapshot_block(root)
    require(
        block.get("no_log") is True
        and block.get("diff") is False
        and block["when"]
        == [
            "certweaver_mode == 'rke2-ha'",
            "certweaver_rke2_etcd_s3_enabled | bool",
            "not ansible_check_mode",
        ],
        "Secret transfer/render/apply must remain private and skipped in check mode",
    )
    tasks = block["block"]
    require(
        tasks[0].get("ansible.builtin.set_fact") == {"certweaver_snapshot_stage": {}}
        and "when" not in tasks[0]
        and caller(tasks[1]),
        "Clear stale staging identity and revalidate exact source before transfer",
    )
    allocation = next(t for t in tasks if t["name"].startswith("Allocate invocation"))
    protection = next(t for t in tasks if t["name"].startswith("Protect invocation"))
    require(
        allocation.get("ansible.builtin.tempfile")
        == {"state": "directory", "path": "/run", "prefix": "certweaver-etcd-s3-"}
        and allocation.get("register") == "certweaver_snapshot_stage"
        and allocation.get("changed_when") is False,
        "Every invocation requires its own temporary directory",
    )
    require(
        protection.get("ansible.builtin.file")
        == {
            "path": "{{ certweaver_snapshot_stage.path }}",
            "state": "directory",
            "owner": "root",
            "group": "root",
            "mode": "0700",
        }
        and protection.get("changed_when") is False,
        "Protect invocation staging before copying private input",
    )
    transfer = next(t for t in tasks if t["name"].startswith("Stage RKE2"))
    identity = next(t for t in tasks if t["name"].startswith("Inspect transferred"))
    binding = next(t for t in tasks if t["name"].startswith("Require exactly"))
    render = next(t for t in tasks if t["name"].startswith("Render RKE2"))
    require(
        transfer["ansible.builtin.copy"]["src"] == "{{ certweaver_rke2_etcd_s3_config_file }}"
        and transfer["ansible.builtin.copy"]["dest"]
        == "{{ certweaver_snapshot_stage.path }}/snapshot.env"
        and transfer["ansible.builtin.copy"]["mode"] == "0600"
        and " ".join(transfer["ansible.builtin.copy"].get("checksum", "").split())
        == "{{ certweaver_snapshot_policy.sha1 if " + PRODUCTION + " else omit }}",
        "Private transfer requires the exact validated controller checksum",
    )
    require(
        identity.get("ansible.builtin.stat")
        == {
            "path": "{{ certweaver_snapshot_stage.path }}/snapshot.env",
            "get_checksum": True,
            "checksum_algorithm": "sha256",
            "get_mime": False,
            "get_attributes": False,
        }
        and identity.get("when") == PRODUCTION
        and identity.get("register") == "certweaver_snapshot_staged",
        "Inspect actual staged bytes with SHA-256",
    )
    require(
        binding.get("ansible.builtin.assert", {}).get("that")
        == [
            "certweaver_snapshot_staged.stat.checksum == certweaver_snapshot_policy.sha256",
            "certweaver_snapshot_staged.stat.size == certweaver_snapshot_policy.bytes",
        ]
        and binding.get("when") == PRODUCTION,
        "Staged SHA-256 and size must match before rendering",
    )
    require(
        tasks.index(allocation)
        < tasks.index(protection)
        < tasks.index(transfer)
        < tasks.index(identity)
        < tasks.index(binding)
        < tasks.index(render),
        "Do not render or apply an unvalidated transfer",
    )
    manifest = next(t for t in tasks if t["name"].startswith("Write rendered"))
    comparison = next(t for t in tasks if t["name"].startswith("Compare RKE2"))
    publication = next(t for t in tasks if t["name"].startswith("Apply RKE2"))
    common = [
        "kubectl",
        "--kubeconfig",
        "{{ certweaver_kubeconfig_path }}",
        "--cache-dir={{ certweaver_snapshot_stage.path }}/cache",
        "--request-timeout=30s",
    ]
    require(
        comparison.get("ansible.builtin.command", {}).get("argv")
        == [
            *common,
            "diff",
            "--server-side",
            "--field-manager=certweaver",
            "--show-secrets=false",
            "-f",
            "{{ certweaver_snapshot_stage.path }}/secret.yaml",
        ]
        and comparison.get("environment")
        == {"KUBECTL_EXTERNAL_DIFF": "", "TMPDIR": "{{ certweaver_snapshot_stage.path }}"}
        and comparison.get("register") == "certweaver_rke2_etcd_s3_diff"
        and comparison.get("failed_when") == "certweaver_rke2_etcd_s3_diff.rc not in [0, 1]"
        and comparison.get("changed_when") is False,
        "Comparison must use bounded private server-side diff with explicit error semantics",
    )
    require(
        publication.get("ansible.builtin.command", {}).get("argv")
        == [
            *common,
            "apply",
            "--server-side",
            "--field-manager=certweaver",
            "-f",
            "{{ certweaver_snapshot_stage.path }}/secret.yaml",
        ]
        and publication.get("when") == "certweaver_rke2_etcd_s3_diff.rc == 1"
        and publication.get("changed_when") is True
        and tasks.index(manifest) < tasks.index(comparison) < tasks.index(publication),
        "Publish only an observed difference and report persistent change",
    )
    require(
        manifest["ansible.builtin.copy"]
        == {
            "content": "{{ certweaver_rke2_etcd_s3_secret.stdout }}",
            "dest": "{{ certweaver_snapshot_stage.path }}/secret.yaml",
            "owner": "root",
            "group": "root",
            "mode": "0600",
        }
        and "--from-env-file={{ certweaver_snapshot_stage.path }}/snapshot.env"
        in render["ansible.builtin.command"]["argv"]
        and all(t.get("changed_when") is False for t in [transfer, render, manifest]),
        "Private temporary work must stay inside invocation staging "
        "without persistent change credit",
    )
    require(
        "diffutils" in load(root / "roles/common/defaults/main.yml")["certweaver_common_packages"],
        "Managed hosts require the standard comparison utility",
    )
    for task in tasks:
        require(
            not set(task).intersection({"ignore_errors", "ignore_unreachable"})
            and (task is comparison or "failed_when" not in task)
            and (task in [identity, binding, publication] or "when" not in task)
            and task.get("no_log", True) is True
            and task.get("diff", False) is False,
            "Do not bypass or disclose snapshot publication",
        )
    require(
        len(block["always"]) == 1
        and block["always"][0].get("ansible.builtin.file")
        == {"path": "{{ certweaver_snapshot_stage.path }}", "state": "absent"}
        and block["always"][0].get("when") == "certweaver_snapshot_stage.path is defined"
        and block["always"][0].get("changed_when") is False,
        "Always remove only this invocation's allocated staging directory",
    )


def fixture_kubectl(state_path, client, args):
    """Client rendering is real; publication is an isolated observation marker."""
    state = json.loads(Path(state_path).read_text())
    if "create" in args:
        if state["case"] == "render-failure":
            return 42
        return subprocess.run([client, *args], check=False).returncode
    require("apply" in args or "diff" in args, "Unexpected fixture command")
    if "diff" in args:
        return 1
    manifest = Path(args[args.index("-f") + 1])
    document = yaml.safe_load(manifest.read_text())
    require(document["type"] == "etcd.k3s.cattle.io/s3-config-secret", "Wrong Secret type")
    credential = base64.b64decode(document["data"]["etcd-s3-secret-key"])
    require(credential == state["canary"].encode(), "Credential bytes changed")
    parent = manifest.parent.stat()
    require(
        stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == 0,
        "Staging directory must be private and root-owned",
    )
    for path in [manifest.parent / "snapshot.env", manifest]:
        info = path.stat()
        require(
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 0,
            "Staging must be private and root-owned",
        )
    Path(state["marker"]).write_text(json.dumps({"private": True, "credentialPreserved": True}))
    if state["case"] == "apply-failure":
        return 43
    print("secret/synthetic-backup-config created")
    return 0


def verify(root, output, native, supplied=None):
    guard(root)
    client = native / "kubectl-real"
    health = runpy.run_path(str(root / "scripts/check-cluster-health.py"))
    health["acquire_client"](root, client, supplied)
    block_source = snapshot_block(root)
    role_call = {
        "name": "Run actual snapshot input policy",
        "ansible.builtin.include_role": {"name": "snapshot_config"},
        "tags": ["always"],
    }
    cases = [
        "defaults",
        *["false-" + x for x in ["false", "False", "FALSE", "0", "f", "F"]],
        "insecure",
        "skip-verify",
        "bare-key",
        "quoted",
        "trailing-space",
        "duplicate",
        "missing",
        "empty",
        "oversize",
        "line-limit",
        "line-too-long",
        "line-utf8",
        "invalid-utf8",
        "scheduled-disabled",
        "s3-disabled",
        "debug",
        "check-positive",
        "check-negative",
        "controller-race",
        "staged-race",
        "render-failure",
        "apply-failure",
        "deploy-preflight",
        "upgrade-preflight",
        "server-preflight",
        "addons-preflight",
        "development",
        "other-mode",
    ]
    observations = []
    for case in cases:
        directory = native / case
        directory.mkdir(mode=0o700)
        source, marker = [directory / n for n in ["source.env", "applied.json"]]
        canary = "synthetic-snapshot-private-" + uuid.uuid4().hex
        if case in {"line-limit", "line-too-long"}:
            size = 65535 if case == "line-limit" else 65536
            canary += "x" * (size - len("etcd-s3-secret-key=") - len(canary))
        elif case == "line-utf8":
            canary += "é" * 33000
        payload = (
            f"etcd-s3-secret-key={canary}\netcd-s3-insecure=false\netcd-s3-skip-ssl-verify=false\n"
        )
        if case == "defaults":
            payload = f"etcd-s3-secret-key={canary}\n"
        elif case.startswith("false-"):
            payload = "\ufeff# Synthetic input\r\n\r\n  " + payload.replace(
                "false", case[6:]
            ).replace("\n", "\r\n")
        elif case in {
            "insecure",
            "check-negative",
            "deploy-preflight",
            "upgrade-preflight",
            "server-preflight",
            "addons-preflight",
            "development",
        }:
            payload = payload.replace("insecure=false", "insecure=true")
        elif case == "skip-verify":
            payload = payload.replace("verify=false", "verify=true")
        elif case == "bare-key":
            payload += "etcd-s3-bucket\n"
        elif case == "quoted":
            payload = payload.replace("insecure=false", 'insecure="false"')
        elif case == "trailing-space":
            payload = payload.replace("insecure=false", "insecure=false ")
        elif case == "duplicate":
            payload += "etcd-s3-insecure=false\n"
        elif case == "empty":
            payload = ""
        elif case == "oversize":
            payload = "#" + "x" * (1024 * 1024)
        source.write_bytes(b"\xff" if case == "invalid-utf8" else payload.encode())
        source.chmod(0o600)
        if case == "missing":
            source.unlink()
        state = directory / "state.json"
        state.write_text(json.dumps({"case": case, "canary": canary, "marker": str(marker)}))
        kubeconfig = directory / "kubeconfig"
        kubeconfig.write_text(
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"
        )
        executable = directory / "kubectl"
        executable.write_text(
            f"#!{sys.executable}\nimport runpy,sys\n"
            f"m=runpy.run_path({str(Path(__file__).resolve())!r})\n"
            f"sys.exit(m['fixture_kubectl']({str(state)!r},"
            f"{str(client)!r},sys.argv[1:]))\n"
        )
        executable.chmod(0o700)
        block = copy.deepcopy(block_source)

        def replace(value, directory=directory):
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                return [replace(v) for v in value]
            if isinstance(value, dict):
                return {
                    k: str(directory) if k == "path" and v == "/run" else replace(v)
                    for k, v in value.items()
                }
            return value

        block = replace(block)
        if case in {"controller-race", "staged-race"}:
            altered = payload.replace("insecure=false", "insecure=true ")
            require(len(altered.encode()) == len(payload.encode()), "Race probe must preserve size")
            injection = {
                "name": "Inject same-size synthetic input race",
                "ansible.builtin.copy": {
                    "content": altered,
                    "dest": str(source)
                    if case == "controller-race"
                    else "{{ certweaver_snapshot_stage.path }}/snapshot.env",
                    "mode": "0600",
                },
                "no_log": True,
                "diff": False,
            }
            index = next(
                i
                for i, t in enumerate(block["block"])
                if t["name"].startswith(
                    "Stage RKE2" if case == "controller-race" else "Inspect transferred"
                )
            )
            block["block"].insert(index, injection)
        tasks = [
            copy.deepcopy(role_call),
            block,
            {
                "name": "Observe policy progression",
                "ansible.builtin.debug": {"msg": "SNAPSHOT_PREFLIGHT_ADVANCED"},
            },
        ]
        if case in {"deploy-preflight", "upgrade-preflight"}:
            tasks = (
                copy.deepcopy(
                    load(
                        root
                        / (
                            "playbooks/rke2-ha.yml"
                            if case == "deploy-preflight"
                            else "playbooks/upgrade.yml"
                        )
                    )[0]["pre_tasks"]
                )
                + tasks[-1:]
            )
        elif case in {"server-preflight", "addons-preflight"}:
            path, index = (
                ("roles/rke2_server/tasks/main.yml", 2)
                if case == "server-preflight"
                else ("roles/cluster_addons/tasks/main.yml", 1)
            )
            tasks = [copy.deepcopy(load(root / path)[index]), *tasks[-1:]]
        variables = {
            "ansible_python_interpreter": sys.executable,
            "certweaver_mode": "k3s-ha" if case == "other-mode" else "rke2-ha",
            "certweaver_environment": "development" if case == "development" else "production",
            "certweaver_rke2_etcd_snapshot_enabled": case != "scheduled-disabled",
            "certweaver_rke2_etcd_s3_enabled": case != "s3-disabled",
            "certweaver_rke2_etcd_s3_config_file": str(source),
            "certweaver_kubeconfig_path": str(kubeconfig),
            "certweaver_rke2_etcd_s3_secret_name": "synthetic-backup-config",
        }
        play = directory / "play.yml"
        play.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Isolated snapshot policy fixture",
                        "hosts": "fixture",
                        "gather_facts": False,
                        "become": True,
                        "vars": variables,
                        "tasks": tasks,
                    }
                ]
            )
        )
        inventory = directory / "inventory.yml"
        inventory.write_text(
            yaml.safe_dump(
                {
                    "all": {
                        "hosts": {
                            "fixture": {"ansible_connection": "local"},
                            "localhost": {"ansible_connection": "ssh", "ansible_host": "192.0.2.1"},
                        }
                    }
                }
            )
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "KUBE"))}
        env.update(
            ANSIBLE_ROLES_PATH=str(root / "roles"),
            ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
            ANSIBLE_NOCOLOR="1",
            PATH=str(directory) + os.pathsep + os.environ["PATH"],
        )
        if case == "debug":
            env["ANSIBLE_DEBUG"] = "1"
        args = [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(play),
            "-vvv",
            "--diff",
        ]
        if case.startswith("check-"):
            args.append("--check")
        result = subprocess.run(args, env=env, capture_output=True, timeout=90)
        log = result.stdout + b"\n" + result.stderr
        (output / (case + ".log")).write_bytes(log)
        require(
            canary.encode() not in log and base64.b64encode(canary.encode()) not in log,
            "Private canary appeared in public Ansible diagnostics",
        )
        success = case in {
            "defaults",
            "line-limit",
            "check-positive",
            "development",
            "other-mode",
        } or case.startswith("false-")
        require((result.returncode == 0) == success, "Unexpected snapshot fixture result: " + case)
        applied = success and case not in {"check-positive", "other-mode"}
        require(
            marker.exists() == (applied or case == "apply-failure"),
            "Unexpected publication progression: " + case,
        )
        require(not list(directory.glob("certweaver-etcd-s3-*")), "Private staging was not cleaned")
        if not success:
            headers = re.findall(rb"TASK \[([^\n]+)\] \*+", log.split(b"fatal:", 1)[0])
            expected = "Read and validate the exact private snapshot configuration"
            if case in {"scheduled-disabled", "s3-disabled", "debug"}:
                expected = "Require explicit snapshot input and disabled Ansible debug"
            elif case == "controller-race":
                expected = "Stage RKE2 S3 snapshot secret configuration"
            elif case == "staged-race":
                expected = "Require exactly the validated snapshot bytes before secret rendering"
            elif case == "render-failure":
                expected = "Render RKE2 S3 snapshot Kubernetes Secret"
            elif case == "apply-failure":
                expected = "Apply RKE2 S3 snapshot Kubernetes Secret"
            require(headers and expected.encode() in headers[-1], "Wrong failure task: " + case)
        observations.append(
            {
                "case": case,
                "exitCode": result.returncode,
                "expectedResultVerified": True,
                "privateCanaryAbsentFromOutput": True,
                "stagingRemoved": True,
                "publicationObserved": marker.exists(),
            }
        )
    record = {
        "scope": "Actual Ansible policy and private transfer/cleanup; real kubectl client "
        "rendering, marker-only publication. Owned root-controller fixture, no remote "
        "SSH/become, API/object store/snapshot/restore or production acceptance.",
        "observations": observations,
    }
    (output / "snapshot-config-result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux root for owned temporary credential fixtures")
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-snapshot-config-") as temporary:
        result = verify(root, output, Path(temporary), args.kubectl)
    print("Verified " + str(len(result["observations"])) + " snapshot configuration cases")
