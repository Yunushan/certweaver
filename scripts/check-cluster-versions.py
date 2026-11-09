"""Exercise actual read-only version gates and source installer decisions in temporary fixtures."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard(root):
    for product in ["rke2", "k3s"]:
        tasks = yaml.safe_load((root / f"roles/{product}_server/tasks/main.yml").read_text())
        require(
            tasks[0].get("ansible.builtin.include_role") == {"name": "cluster_version"}
            and not set(tasks[0]).intersection({"when", "vars", "ignore_errors", "failed_when"}),
            "Server changes must begin with the unconditional observed-version gate",
        )
        install = next(
            t
            for t in tasks
            if t["name"]
            == f"Install or upgrade pinned {product.upper() if product == 'rke2' else 'K3s'} server"
        )
        require(
            install.get("when") == "certweaver_cluster_version_install_needed | bool",
            "Installer must use the qualified exact-version decision",
        )
    for name in ["rke2-ha", "k3s-ha", "upgrade"]:
        plays = yaml.safe_load((root / f"playbooks/{name}.yml").read_text())
        expected = {"role": "cluster_version"}
        if name == "upgrade":
            expected["vars"] = {"certweaver_cluster_version_require_installed": True}
        require(
            plays[0].get("hosts") == "cluster_servers"
            and plays[0].get("any_errors_fatal") is True
            and plays[0].get("roles") == [expected],
            "Every managed server must pass read-only version preflight before mutation",
        )


def write_binary(path, product, version, marker, *, output=None, code=0):
    text = (
        output
        if output is not None
        else f"{product} version {version} (aabbcc)\ngo version go1.fixture\n"
    )
    path.write_text(
        f"#!{sys.executable}\nimport pathlib,sys\nassert sys.argv[1:]==['--version']\n"
        f"pathlib.Path({str(marker)!r}).write_text('version command executed')\n"
        f"sys.stdout.write({text!r})\nsys.exit({code!r})\n"
    )
    path.chmod(0o755)


def verify(root, output, native):
    guard(root)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANSIBLE_")}
    env.update(
        ANSIBLE_ROLES_PATH=str(root / "roles"),
        ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
        ANSIBLE_NOCOLOR="1",
    )
    observations = []
    snapshot_file = native / "synthetic-snapshot.env"
    snapshot_file.write_text("etcd-s3-bucket=synthetic-version-fixture\n", encoding="utf-8")
    snapshot_file.chmod(0o600)
    snapshot_vars = {
        "certweaver_environment": "production",
        "certweaver_rke2_etcd_snapshot_enabled": True,
        "certweaver_rke2_etcd_s3_enabled": True,
        "certweaver_rke2_etcd_s3_config_file": str(snapshot_file),
    }

    def execute(label, plays, inventory="localhost,", check=False):
        playbook = native / (label + ".yml")
        playbook.write_text(yaml.safe_dump(plays))
        args = [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(playbook),
        ]
        if check:
            args.append("--check")
        completed = subprocess.run(args, cwd=root, env=env, capture_output=True, timeout=90)
        log = completed.stdout + b"\n" + completed.stderr
        (output / (label + ".log")).write_bytes(log)
        return completed.returncode, log

    for product, mode, suffix in [("rke2", "rke2-ha", "rke2r"), ("k3s", "k3s-ha", "k3s")]:
        base = f"v1.33.12+{suffix}2"
        cases = {
            "fresh": {"absent": True, "needed": True},
            "equal": {"needed": False},
            "patch-up": {"target": f"v1.33.13+{suffix}1", "needed": True},
            "revision-up": {"target": f"v1.33.12+{suffix}3", "needed": True},
            "numeric-revision": {
                "current": f"v1.33.12+{suffix}9",
                "target": f"v1.33.12+{suffix}10",
                "needed": True,
            },
            "minor-up": {"target": f"v1.34.0+{suffix}1", "needed": True},
            "numeric-minor": {
                "current": f"v1.9.12+{suffix}2",
                "target": f"v1.10.0+{suffix}1",
                "needed": True,
            },
            "patch-downgrade": {"target": f"v1.33.11+{suffix}9", "reason": "Refusing a downgrade"},
            "revision-downgrade": {
                "target": f"v1.33.12+{suffix}1",
                "reason": "Refusing a downgrade",
            },
            "minor-downgrade": {"target": f"v1.32.20+{suffix}9", "reason": "Refusing a downgrade"},
            "minor-skip": {"target": f"v1.35.0+{suffix}1", "reason": "Refusing a downgrade"},
            "invalid-target": {
                "target": "stable",
                "reason": "Select a literal stable",
                "executed": False,
            },
            "prerelease-target": {
                "target": f"v1.34.0-rc1+{suffix}1",
                "reason": "Select a literal stable",
                "executed": False,
            },
            "cross-product-target": {
                "target": "v1.33.12+" + ("k3s1" if product == "rke2" else "rke2r1"),
                "reason": "Select a literal stable",
                "executed": False,
            },
            "leading-zero-target": {
                "target": f"v1.033.12+{suffix}2",
                "reason": "Select a literal stable",
                "executed": False,
            },
            "newline-target": {
                "target": base + "\n",
                "reason": "Select a literal stable",
                "executed": False,
            },
            "major-target": {
                "target": f"v2.0.0+{suffix}1",
                "reason": "Select a literal stable",
                "executed": False,
            },
            "unknown-installed": {
                "stdout": f"{product} version unknown\n",
                "reason": "version is unknown or ambiguous",
            },
            "conflicting-identities": {
                "stdout": f"{product} version {base}\n{product} version unknown\n",
                "reason": "version is unknown or ambiguous",
            },
            "wrong-product-installed": {
                "stdout": f"other version {base}\n",
                "reason": "version is unknown or ambiguous",
            },
            "failed-version-command": {"exit": 7, "reason": '"rc": 7'},
            "symlink-binary": {
                "kind": "symlink",
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "directory-binary": {
                "kind": "directory",
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "not-executable": {
                "permission": 0o600,
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "world-writable": {
                "permission": 0o757,
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "group-writable": {
                "permission": 0o775,
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "wrong-owner": {
                "owner": 65534,
                "reason": "protected root-owned regular executable",
                "executed": False,
            },
            "ambiguous-locations": {
                "duplicate": True,
                "reason": "missing or multiple managed binary locations",
                "executed": False,
            },
            "missing-upgrade": {
                "absent": True,
                "installed": True,
                "reason": "missing or multiple managed binary locations",
                "executed": False,
            },
            "check-mode": {"check": True, "needed": False},
            "check-mode-downgrade": {
                "check": True,
                "target": f"v1.32.20+{suffix}9",
                "reason": "Refusing a downgrade",
            },
        }
        for name, case in cases.items():
            label = product + "-" + name
            directory = native / label
            directory.mkdir()
            binary, marker = directory / product, directory / "version-executed"
            selected, current = case.get("target", base), case.get("current", base)
            paths = [str(binary)]
            if not case.get("absent"):
                write_binary(
                    binary,
                    product,
                    current,
                    marker,
                    output=case.get("stdout"),
                    code=case.get("exit", 0),
                )
                if case.get("kind") == "symlink":
                    real = directory / "real"
                    binary.rename(real)
                    binary.symlink_to(real)
                if case.get("kind") == "directory":
                    binary.unlink()
                    binary.mkdir()
                if "permission" in case:
                    binary.chmod(case["permission"])
                if "owner" in case:
                    os.chown(binary, case["owner"], case["owner"])
                if case.get("duplicate"):
                    duplicate = directory / "duplicate"
                    write_binary(duplicate, product, current, marker)
                    paths.append(str(duplicate))
            variables = {
                **snapshot_vars,
                "ansible_python_interpreter": sys.executable,
                "certweaver_mode": mode,
                "certweaver_rke2_version": selected,
                "certweaver_k3s_version": selected,
                "certweaver_cluster_version_paths": {mode: paths},
                "certweaver_cluster_version_require_installed": case.get("installed", False),
            }
            post = []
            if "reason" not in case:
                post.append(
                    {
                        "name": "Check the actual installer decision",
                        "ansible.builtin.assert": {
                            "that": [
                                "certweaver_cluster_version_install_needed == fixture_needed",
                                "certweaver_cluster_version_current == fixture_current",
                            ]
                        },
                        "vars": {
                            "fixture_needed": case["needed"],
                            "fixture_current": "" if case.get("absent") else current,
                        },
                    }
                )
            post.append(
                {
                    "name": "Observe gate advancement",
                    "ansible.builtin.debug": {"msg": "VERSION_GATE_ADVANCED"},
                }
            )
            code, log = execute(
                label,
                [
                    {
                        "name": "Synthetic observed version; no installer execution",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "become": False,
                        "vars": variables,
                        "roles": ["cluster_version"],
                        "post_tasks": post,
                    }
                ],
                check=case.get("check", False),
            )
            advanced = b'"msg": "VERSION_GATE_ADVANCED"' in log
            expected = "reason" not in case
            reason = case.get("reason")
            executed = case.get("executed", not case.get("absent", False))
            observed = {
                "case": label,
                "exitCode": code,
                "advanced": advanced,
                "versionCommandExecuted": marker.exists(),
                "expectedSuccess": expected,
            }
            (output / (label + "-observation.json")).write_text(
                json.dumps(observed, indent=2) + "\n"
            )
            require(
                (code == 0) == expected and advanced == expected,
                "Unexpected version gate result: " + label,
            )
            require(marker.exists() == executed, "Unexpected binary execution: " + label)
            if reason:
                require(
                    reason.encode() in log,
                    "Failure was not the expected version rejection: " + label,
                )
            observations.append(
                {**observed, "expectedReasonVerified": True, "expectedResultVerified": True}
            )

        # Execute the actual all-server preflight and source installer condition.
        # Health/common/add-on roles are stubs here; the separate real-client
        # health fixture exercises health and progression boundaries.
        tasks = yaml.safe_load((root / f"roles/{product}_server/tasks/main.yml").read_text())
        installer = copy.deepcopy(
            next(t for t in tasks if t["name"].startswith("Install or upgrade pinned"))
        )
        installer.pop("notify")
        runner = native / (product + "-installer-marker")
        runner.write_text(
            f"#!{sys.executable}\nimport json,os,pathlib,sys\n"
            f"assert os.environ['INSTALL_{product.upper()}_VERSION']==sys.argv[2]\n"
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({'target':sys.argv[2]}))\n"
        )
        runner.chmod(0o755)
        for name in ["upgrade", "equal", "partial", "bad-peer", "missing-peer", "deploy-bad-peer"]:
            label = product + "-fleet-" + name
            selected = f"v1.34.0+{suffix}1"
            hosts, mutations = {}, {}
            for host in ["fixture-first", "fixture-peer"]:
                directory = native / (label + "-" + host)
                directory.mkdir()
                binary, marker = directory / product, directory / "version-executed"
                current = f"v1.33.12+{suffix}2"
                if name == "equal" or (name == "partial" and host == "fixture-first"):
                    current = selected
                if "bad-peer" in name and host == "fixture-peer":
                    current = f"v1.31.12+{suffix}2"
                if name != "missing-peer" or host != "fixture-peer":
                    write_binary(binary, product, current, marker)
                mutations[host] = directory / "installer-executed"
                hosts[host] = {
                    "ansible_connection": "local",
                    "certweaver_cluster_version_paths": {mode: [str(binary)]},
                    "fixture_installer_marker": str(mutations[host]),
                }
            inventory = native / (label + "-inventory.yml")
            inventory.write_text(
                yaml.safe_dump(
                    {
                        "all": {
                            "children": {
                                "cluster_servers": {"hosts": hosts},
                                "cluster_bootstrap": {"hosts": {"fixture-first": {}}},
                                "cluster_joiners": {"hosts": {"fixture-peer": {}}},
                            }
                        }
                    }
                )
            )
            filename = mode if name == "deploy-bad-peer" else "upgrade"
            plays = yaml.safe_load((root / f"playbooks/{filename}.yml").read_text())
            for play in plays:
                play.update(
                    become=False,
                    gather_facts=False,
                    vars={
                        **snapshot_vars,
                        "ansible_python_interpreter": sys.executable,
                        "certweaver_mode": mode,
                        "certweaver_rke2_version": selected,
                        "certweaver_k3s_version": selected,
                    },
                )
            for play in plays[1:]:
                roles = play.pop("roles", [])
                if any(r.get("role") in {"rke2_server", "k3s_server"} for r in roles):
                    selected_installer = copy.deepcopy(installer)
                    selected_installer["ansible.builtin.command"] = {
                        "argv": [str(runner), "{{ fixture_installer_marker }}", selected]
                    }
                    play["tasks"] = [copy.deepcopy(tasks[0]), selected_installer]
                else:
                    play["tasks"] = [
                        {
                            "name": "Observe later phase without mutation",
                            "ansible.builtin.debug": {"msg": "LATER_PHASE_ADVANCED"},
                        }
                    ]
            code, log = execute(label, plays, inventory)
            markers = {h: p.exists() for h, p in mutations.items()}
            expected_success = name in {"upgrade", "equal", "partial"}
            expected_markers = {
                "fixture-first": name == "upgrade",
                "fixture-peer": name in {"upgrade", "partial"},
            }
            require(
                (code == 0) == expected_success and markers == expected_markers,
                "Fleet transition ordering failed: " + label,
            )
            if not expected_success:
                require(
                    b"LATER_PHASE_ADVANCED" not in log
                    and (
                        b"Refusing a downgrade" in log
                        or b"missing or multiple managed binary locations" in log
                    ),
                    "Fleet failed for an unrelated reason or advanced after rejection: " + label,
                )
            observations.append(
                {
                    "case": label,
                    "exitCode": code,
                    "installerMarkers": markers,
                    "expectedResultVerified": True,
                    "expectedReasonVerified": True,
                }
            )
    result = {
        "scope": (
            "Actual Ansible version role, source all-server preflight and installer condition "
            "with synthetic root-owned executables and marker-only installers; no real product, "
            "package installation, cluster, downgrade, upgrade or recovery qualification"
        ),
        "observations": observations,
    }
    (output / "cluster-versions-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux with root permissions for temporary ownership fixtures")
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be a fresh directory inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-version-fixture-") as temporary:
        result = verify(root, output, Path(temporary))
    print(f"Verified {len(result['observations'])} observed version and fleet-preflight cases")
