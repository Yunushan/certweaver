"""Qualify managed fleet failure propagation under controller strategy overrides."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import yaml

from certweaver import snapshot

MANAGED_PLAYBOOKS = ("rke2-ha", "k3s-ha", "upgrade")
REQUIRED_STRATEGY = "ansible.builtin.linear"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def guard(root):
    for name in MANAGED_PLAYBOOKS:
        plays = load(root / f"playbooks/{name}.yml")
        require(isinstance(plays, list) and plays, "Managed playbook must contain plays")
        for index, play in enumerate(plays):
            require(
                play.get("strategy") == REQUIRED_STRATEGY
                and play.get("any_errors_fatal") is True
                and not set(play).intersection(
                    {"ignore_errors", "ignore_unreachable", "force_handlers"}
                ),
                f"{name} play {index} must pin the built-in linear strategy and fatal fleet policy",
            )


def verify(root, output, native):
    guard(root)
    native.mkdir(mode=0o700)
    module_hash = hashlib.sha256(
        Path(snapshot.__file__).read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    require(
        module_hash
        == hashlib.sha256(
            (root / "src/certweaver/snapshot.py").read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest(),
        "Controller must use the qualified snapshot validator",
    )
    observations = []
    for filename in MANAGED_PLAYBOOKS:
        source = root / f"playbooks/{filename}.yml"
        for override in ("linear", "free", "host_pinned"):
            for failure in ("none", "preflight", "health"):
                case = f"{filename}-{override}-{failure}"
                directory = native / case
                directory.mkdir(mode=0o700)
                canary = "synthetic-strategy-private-" + uuid.uuid4().hex
                good, wrong = directory / "good.env", directory / "bad.env"
                for path, flag in [(good, "false"), (wrong, "true")]:
                    path.write_text(
                        f"etcd-s3-secret-key={canary}\netcd-s3-insecure={flag}\n", encoding="utf-8"
                    )
                    path.chmod(0o600)
                plays = copy.deepcopy(load(source))
                for index, play in enumerate(plays):
                    play.pop("roles")
                    play.update(gather_facts=False, become=False)
                    if index == 0:
                        play["tasks"] = (
                            [
                                {
                                    "name": "Inject synthetic K3s version gate failure",
                                    "ansible.builtin.assert": {
                                        "that": ["not fixture_preflight_failure"]
                                    },
                                }
                            ]
                            if filename == "k3s-ha"
                            else [
                                {
                                    "name": "Observe separately qualified version logic",
                                    "ansible.builtin.debug": {"msg": "VERSION_GATE_STUB"},
                                }
                            ]
                        )
                    else:
                        play.pop("pre_tasks", None)
                        play["tasks"] = []
                        if index == 1:
                            play["tasks"].append(
                                {
                                    "name": "Inject synthetic fleet health gate failure",
                                    "ansible.builtin.assert": {
                                        "that": ["not fixture_health_failure"]
                                    },
                                }
                            )
                        play["tasks"].append(
                            {
                                "name": "Observe later phase without service mutation",
                                "ansible.builtin.file": {
                                    "path": str(
                                        directory / f"phase-{index}-{{{{ inventory_hostname }}}}"
                                    ),
                                    "state": "touch",
                                    "mode": "0600",
                                },
                            }
                        )
                book = directory / "play.yml"
                book.write_text(yaml.safe_dump(plays), encoding="utf-8")
                variables = {
                    "ansible_connection": "local",
                    "ansible_python_interpreter": sys.executable,
                    "certweaver_mode": "k3s-ha" if filename == "k3s-ha" else "rke2-ha",
                    "certweaver_environment": "production",
                    "certweaver_rke2_etcd_snapshot_enabled": True,
                    "certweaver_rke2_etcd_s3_enabled": True,
                    "certweaver_rke2_etcd_s3_config_file": str(good),
                    "fixture_preflight_failure": False,
                    "fixture_health_failure": False,
                }
                inventory = directory / "inventory.yml"
                inventory.write_text(
                    yaml.safe_dump(
                        {
                            "all": {
                                "vars": variables,
                                "children": {
                                    "cluster_servers": {
                                        "hosts": {
                                            "fixture-first": {},
                                            "fixture-peer": {
                                                "certweaver_rke2_etcd_s3_config_file": str(
                                                    wrong if failure == "preflight" else good
                                                ),
                                                "fixture_preflight_failure": failure == "preflight",
                                                "fixture_health_failure": failure == "health",
                                            },
                                        }
                                    },
                                    "cluster_bootstrap": {"hosts": {"fixture-first": {}}},
                                    "cluster_joiners": {"hosts": {"fixture-peer": {}}},
                                },
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                env = {
                    k: v
                    for k, v in os.environ.items()
                    if not k.startswith(("ANSIBLE_", "PYTHON", "KUBE"))
                }
                env.update(
                    ANSIBLE_ROLES_PATH=str(root / "roles"),
                    ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
                    ANSIBLE_NOCOLOR="1",
                    ANSIBLE_STRATEGY=override,
                )
                result = subprocess.run(
                    [
                        str(Path(sys.executable).with_name("ansible-playbook")),
                        "-i",
                        str(inventory),
                        str(book),
                        "-vvv",
                        "--diff",
                    ],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    timeout=90,
                )
                log = result.stdout + b"\n" + result.stderr
                (output / (case + ".log")).write_bytes(log)
                markers = sorted(p.name for p in directory.glob("phase-*"))
                require(
                    canary.encode() not in log, "Private canary appeared in strategy diagnostics"
                )
                require(
                    result.returncode == (0 if failure == "none" else 2),
                    "Unexpected strategy result: " + case,
                )
                require(
                    len(markers)
                    == (
                        (6 if filename in {"rke2-ha", "k3s-ha"} else 5) if failure == "none" else 0
                    ),
                    "Failed fleet advanced into a later phase: " + case,
                )
                require(
                    not (b"any_errors_fatal" in log and b"not supported" in log),
                    "Fatal propagation policy was not effective",
                )
                if failure != "none":
                    headers = re.findall(rb"TASK \[([^\n]+)\] \*+", log.split(b"fatal:", 1)[0])
                    expected = (
                        "Inject synthetic fleet health gate failure"
                        if failure == "health"
                        else (
                            "Inject synthetic K3s version gate failure"
                            if filename == "k3s-ha"
                            else "Read and validate the exact private snapshot configuration"
                        )
                    )
                    require(
                        headers and expected.encode() in headers[-1], "Wrong failure gate: " + case
                    )
                observations.append(
                    {
                        "case": case,
                        "requestedEnvironmentStrategy": override,
                        "sourcePlayStrategy": REQUIRED_STRATEGY,
                        "failure": failure,
                        "exitCode": result.returncode,
                        "laterPhaseCount": len(markers),
                        "expectedResultVerified": True,
                        "privateCanaryAbsentFromOutput": True,
                        "sourcePlaybookSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    }
                )
    record = {
        "scope": "Actual source play targets/serial/failure policy and real RKE2 snapshot "
        "preflight; synthetic K3s version and fleet health failures, with marker replacements "
        "for mutating work. No service mutation, remote SSH/become, cluster or approval.",
        "snapshotModuleSha256": module_hash,
        "observations": observations,
    }
    (output / "managed-strategy-result.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-managed-strategy-") as temporary:
        result = verify(root, output, Path(temporary) / "cases")
    print("Verified " + str(len(result["observations"])) + " managed strategy/failure cases")
