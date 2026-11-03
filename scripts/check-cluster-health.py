"""Exercise managed-cluster health gates with real kubectl and a synthetic HTTPS API."""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.server
import json
import os
import runpy
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import yaml

RUNTIME_WHEN = [
    "certweaver_cluster_version_current | length > 0",
    "certweaver_cluster_version_install_needed | bool",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard(root):
    """Reject removal or conditional bypass of the production callers."""
    for distribution in ["rke2", "k3s"]:
        tasks = yaml.safe_load((root / f"roles/{distribution}_server/tasks/main.yml").read_text())
        require(
            tasks[-1].get("ansible.builtin.include_role") == {"name": "cluster_health"}
            and tasks[-1].get("vars") == {"certweaver_cluster_health_phase": "post-reconcile"}
            and not set(tasks[-1]).intersection({"when", "ignore_errors", "failed_when"}),
            "Server reconciliation must end with the unconditional cluster health role",
        )
        require(
            tasks[1].get("ansible.builtin.include_role") == {"name": "cluster_health"}
            and tasks[1].get("vars") == {"certweaver_cluster_health_phase": "pre-upgrade"}
            and tasks[1].get("when") == RUNTIME_WHEN
            and not set(tasks[1]).intersection({"ignore_errors", "failed_when"}),
            "Version-changing server reconciliation requires the observed running identity gate",
        )
        flushes = [
            i for i, t in enumerate(tasks) if t.get("ansible.builtin.meta") == "flush_handlers"
        ]
        require(
            len(flushes) == 1
            and flushes[0] < len(tasks) - 1
            and not any("notify" in t for t in tasks[flushes[0] + 1 :]),
            "Pending platform/server handlers must finish before final readiness",
        )
    for filename in ["rke2-ha", "k3s-ha", "upgrade"]:
        plays = yaml.safe_load((root / f"playbooks/{filename}.yml").read_text())
        require(
            all(
                p.get("any_errors_fatal") is True
                and not set(p).intersection(
                    {"ignore_errors", "ignore_unreachable", "force_handlers"}
                )
                for p in plays
            ),
            "Managed cluster plays must stop on failure",
        )
        if filename == "upgrade":
            # Version preflight owns the first play; health remains the next
            # gate before the serial installer and add-on plays.
            require(
                plays[1].get("hosts") == "cluster_servers"
                and plays[1].get("roles")
                == [
                    {
                        "role": "cluster_health",
                        "vars": {
                            "certweaver_cluster_health_phase": "pre-upgrade",
                        },
                    }
                ]
                and plays[2].get("serial") == 1,
                "Upgrade must check every managed node before a serial mutation",
            )
        else:
            require(
                plays[1].get("hosts") == "cluster_servers"
                and plays[1].get("roles")
                == [
                    {
                        "role": "cluster_health",
                        "vars": {"certweaver_cluster_health_phase": "pre-upgrade"},
                        "when": RUNTIME_WHEN,
                    }
                ],
                "Deployment must check every changing server before platform preparation",
            )
            require(len(plays) == 5, "Managed deployment must not prepare hosts in a separate play")
            product = filename.split("-", 1)[0]
            for play, group in zip(
                plays[2:4], ["cluster_bootstrap", "cluster_joiners"], strict=True
            ):
                require(
                    play.get("hosts") == group
                    and play.get("serial") == 1
                    and play.get("roles")
                    == [
                        {"role": "common", "tags": ["common"]},
                        {
                            "role": "haproxy_keepalived",
                            "when": "certweaver_load_balancer_enabled | bool",
                            "tags": ["load-balancer"],
                        },
                        {"role": product + "_server", "tags": [product]},
                    ],
                    "Host preparation and server readiness must share the same serial play",
                )
                pre = [
                    {k: v for k, v in t.items() if k != "name"} for t in play.get("pre_tasks", [])
                ]
                require(
                    pre
                    == [
                        {"ansible.builtin.include_role": {"name": "cluster_version"}},
                        {
                            "ansible.builtin.include_role": {"name": "cluster_health"},
                            "vars": {"certweaver_cluster_health_phase": "pre-upgrade"},
                            "when": RUNTIME_WHEN,
                        },
                    ],
                    "Each serial host must recheck version/runtime before platform preparation",
                )


def acquire_client(root, target, supplied=None):
    record = json.loads((root / "ci/cluster-health-client.lock.json").read_text())
    version = record["version"]
    require(
        record["platform"] == "linux-amd64"
        and record["url"] == f"https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl"
        and len(record["sha256"]) == 64
        and all(c in "0123456789abcdef" for c in record["sha256"]),
        "Unexpected cluster health fixture client identity",
    )
    if supplied is not None:
        require(not supplied.is_symlink() and supplied.is_file(), "Client must be a regular file")
        data = supplied.read_bytes()
        require(len(data) <= 128 * 1024 * 1024, "Fixture client exceeded size limit")
    else:
        redirect = runpy.run_path(str(root / "scripts/install-ci-tool.py"))["HTTPSRedirects"]
        opener = urllib.request.build_opener(redirect())
        data, started = bytearray(), time.monotonic()
        with opener.open(record["url"], timeout=45) as source:
            while block := source.read(1024 * 1024):
                data.extend(block)
                require(
                    len(data) <= 128 * 1024 * 1024 and time.monotonic() - started <= 180,
                    "Fixture client download exceeded size/time limits",
                )
    require(hashlib.sha256(data).hexdigest() == record["sha256"], "Fixture client digest mismatch")
    target.write_bytes(data)
    target.chmod(0o700)
    return record


def make_certificates(native):
    extensions = native / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    for command in [
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Synthetic health fixture CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(native / "ca.key"),
            "-out",
            str(native / "ca.crt"),
        ],
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Synthetic API",
            "-keyout",
            str(native / "server.key"),
            "-out",
            str(native / "server.csr"),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(native / "server.csr"),
            "-CA",
            str(native / "ca.crt"),
            "-CAkey",
            str(native / "ca.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(extensions),
            "-out",
            str(native / "server.crt"),
        ],
    ]:
        subprocess.run(command, check=True, capture_output=True, timeout=30)


def verify(root, output, native, supplied):
    guard(root)
    client = native / "kubectl"
    record = acquire_client(root, client, supplied)
    make_certificates(native)
    k3s = native / "k3s-client-wrapper"
    k3s.write_text(
        f"#!{sys.executable}\nimport os,sys\nassert sys.argv[1]=='kubectl'\n"
        f"os.execv({str(client)!r},[{str(client)!r}]+sys.argv[2:])\n"
    )
    k3s.chmod(0o700)
    state = {
        "case": "",
        "requests": [],
        "events": [],
        "apiCalls": 0,
        "nodeCalls": 0,
        "versionCalls": 0,
        "version": "",
        "mutated": set(),
        "fleet": False,
    }

    def running_version(node):
        if state["fleet"] and node not in state["mutated"]:
            return state.get("observedVersion", "v1.32.13+rke2r2")
        return state["version"]

    class API(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if (
                self.path not in {"/fixture/mutate", "/fixture/prepare", "/fixture/handler"}
                or self.headers.get("Authorization") != "Bearer synthetic-health-fixture-control"
            ):
                self.reply(401, b"Unauthorized")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024:
                self.reply(400, b"Invalid fixture control")
                return
            node = json.loads(self.rfile.read(length))["node"]
            require(
                node in {"fixture-node", "fixture-peer", "fixture-third"}, "Unexpected fixture node"
            )
            action = self.path.rsplit("/", 1)[-1]
            state["events"].append(action.upper() + ":" + node)
            if action == "prepare":
                state["prepared"].add(node)
                failure_node = (
                    "fixture-peer" if "peer-preparation" in state["case"] else "fixture-node"
                )
                if "preparation-failure" in state["case"] and node == failure_node:
                    self.reply(500, b"Synthetic preparation failure")
                    return
            elif action == "handler":
                if "handler-failure" in state["case"]:
                    self.reply(500, b"Synthetic handler failure")
                    return
            else:
                state["mutated"].add(node)
            self.reply(200, b"{}")

        def do_GET(self):
            state["requests"].append(self.path)
            path = urlsplit(self.path).path
            case = state["case"]
            token = self.headers.get("Authorization", "")
            allowed = {"Bearer synthetic-health-fixture-token"} | {
                "Bearer synthetic-health-fixture-token:" + n
                for n in ["fixture-node", "fixture-peer", "fixture-third", "localhost"]
            }
            local_node = token.split(":", 1)[1] if ":" in token else "fixture-node"
            state["events"].append("GET:" + local_node + ":" + path)
            status, body = 200, b"ok"
            if token not in allowed or case == "unauthorized":
                status, body = 401, b"Unauthorized"
            elif path == "/readyz":
                state["apiCalls"] += 1
                if (
                    case == "api-not-ready"
                    or ("same-version-repair" in case and local_node not in state["mutated"])
                    or (case == "transient-api" and state["apiCalls"] == 1)
                    or (case == "upgrade-peer-api-unready" and local_node == "fixture-peer")
                ):
                    status, body = 503, b"etcd check failed"
                elif case == "api-wrong-body":
                    body = b"ready-but-not-the-required-response"
            elif path == "/version":
                state["versionCalls"] += 1
                state.setdefault("perNodeVersionCalls", {}).setdefault(local_node, 0)
                state["perNodeVersionCalls"][local_node] += 1
                version = running_version(local_node)
                if (
                    case in {"api-version-mismatch", "preflight-api-drift"}
                    or (
                        "recheck-drift" in case
                        and local_node == "fixture-node"
                        and state["perNodeVersionCalls"][local_node] > 1
                    )
                    or ("final-health-failure" in case and local_node in state["mutated"])
                    or (
                        case in {"upgrade-preflight-version-drift", "deploy-runtime-drift"}
                        and local_node == "fixture-peer"
                    )
                    or (case == "upgrade-api-version-failure" and local_node in state["mutated"])
                    or (case == "transient-server-version" and state["versionCalls"] == 1)
                ):
                    version = "v1.31.13+rke2r2"
                payload = {"major": "1", "minor": "33", "gitVersion": version}
                if case == "missing-api-version":
                    payload.pop("gitVersion")
                if case in {"api-revision-mismatch", "api-revision-mismatch-k3s"}:
                    payload["gitVersion"] = (
                        "v1.33.12+k3s2" if case.endswith("k3s") else "v1.33.12+rke2r3"
                    )
                body = json.dumps(payload).encode()
                if case == "malformed-api-version":
                    body = b"invalid json"
                if case == "nonobject-api-version":
                    body = b"[]"
            elif path.startswith("/api/v1/nodes/"):
                state["nodeCalls"] += 1
                name = path.rsplit("/", 1)[-1]
                node = {
                    "apiVersion": "v1",
                    "kind": "Node",
                    "metadata": {"name": name},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "nodeInfo": {"kubeletVersion": running_version(name)},
                    },
                }
                if (
                    case == "node-not-ready"
                    or (case == "upgrade-preflight-failure" and name == "fixture-peer")
                    or (case == "transient-node" and state["nodeCalls"] == 1)
                ):
                    node["status"]["conditions"][0]["status"] = "False"
                if case in {"wrong-version", "preflight-node-drift"} or (
                    case == "upgrade-node-failure" and name in state["mutated"]
                ):
                    node["status"]["nodeInfo"]["kubeletVersion"] = "v1.31.13+rke2r2"
                if case == "wrong-node":
                    node["metadata"]["name"] = "some-other-node"
                if case == "wrong-kind":
                    node["kind"] = "Pod"
                if case == "missing-ready-condition":
                    node["status"]["conditions"] = []
                if case == "duplicate-ready":
                    node["status"]["conditions"] *= 2
                if case == "conflicting-ready":
                    node["status"]["conditions"].append({"type": "Ready", "status": "False"})
                if case == "deleting-node":
                    node["metadata"]["deletionTimestamp"] = "2026-11-03T00:00:00Z"
                body = json.dumps(node).encode()
                if case == "missing-node":
                    status, body = 404, b"Not Found"
                if case == "malformed-node":
                    body = b"invalid json"
            else:
                status, body = 404, b"Not Found"
            self.reply(status, body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(native / "server.crt", native / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    observations = []
    snapshot_file = native / "synthetic-snapshot.env"
    snapshot_file.write_text("etcd-s3-bucket=synthetic-health-fixture\n", encoding="utf-8")
    snapshot_file.chmod(0o600)
    snapshot_vars = {
        "certweaver_environment": "production",
        "certweaver_rke2_etcd_snapshot_enabled": True,
        "certweaver_rke2_etcd_s3_enabled": True,
        "certweaver_rke2_etcd_s3_config_file": str(snapshot_file),
    }

    def client_config(name, node="fixture-node", trusted=True):
        path = native / (name + ".kubeconfig")
        cluster = {"server": f"https://127.0.0.1:{server.server_port}"}
        if trusted:
            cluster["certificate-authority"] = str(native / "ca.crt")
        if name == "insecure-kubeconfig":
            cluster.pop("certificate-authority", None)
            cluster["insecure-skip-tls-verify"] = True
        if name == "proxy-kubeconfig":
            cluster["proxy-url"] = "https://127.0.0.1:9"
        path.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "fixture",
                    "clusters": [{"name": "fixture", "cluster": cluster}],
                    "users": [
                        {
                            "name": "fixture",
                            "user": {"token": "synthetic-health-fixture-token:" + node},
                        }
                    ],
                    "contexts": [
                        {"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}
                    ],
                }
            )
        )
        path.chmod(0o600)
        return path

    cases = [
        "ready-rke2",
        "ready-k3s",
        "api-not-ready",
        "api-wrong-body",
        "node-not-ready",
        "wrong-version",
        "wrong-node",
        "wrong-kind",
        "missing-node",
        "missing-ready-condition",
        "duplicate-ready",
        "conflicting-ready",
        "deleting-node",
        "malformed-node",
        "transient-api",
        "transient-node",
        "preflight-older-version",
        "preflight-older-k3s",
        "preflight-node-drift",
        "preflight-api-drift",
        "preflight-missing-observation",
        "preflight-cross-node",
        "invalid-phase",
        "api-version-mismatch",
        "api-revision-mismatch",
        "api-revision-mismatch-k3s",
        "missing-api-version",
        "malformed-api-version",
        "nonobject-api-version",
        "transient-server-version",
        "untrusted-ca",
        "insecure-kubeconfig",
        "proxy-kubeconfig",
        "unauthorized",
        "check-mode",
        "invalid-node",
        "unsupported-mode",
    ]
    successes = {
        "ready-rke2",
        "ready-k3s",
        "transient-api",
        "transient-node",
        "transient-server-version",
        "preflight-older-version",
        "preflight-older-k3s",
        "check-mode",
    }
    try:
        for case in cases:
            mode = "k3s-ha" if case.endswith("k3s") else "rke2-ha"
            version = "v1.33.12+k3s1" if mode == "k3s-ha" else "v1.33.12+rke2r2"
            if case.startswith("preflight-"):
                version = "v1.32.13+k3s1" if mode == "k3s-ha" else "v1.32.13+rke2r2"
            state.update(
                case=case,
                requests=[],
                events=[],
                apiCalls=0,
                nodeCalls=0,
                versionCalls=0,
                version=version,
                mutated=set(),
                fleet=False,
            )
            kubeconfig = client_config(
                case,
                "localhost" if case.startswith("preflight-") else "fixture-node",
                case != "untrusted-ca",
            )
            variables = {
                **snapshot_vars,
                "ansible_python_interpreter": sys.executable,
                "certweaver_mode": mode,
                "certweaver_rke2_version": "v1.33.12+rke2r2",
                "certweaver_k3s_version": "v1.33.12+k3s1",
                "certweaver_cluster_health_profiles": {
                    mode: {
                        "argv": [str(k3s), "kubectl"] if mode == "k3s-ha" else [str(client)],
                        "kubeconfig": str(kubeconfig),
                    }
                },
                "certweaver_cluster_health_nodes": ["fixture-node"],
                "certweaver_cluster_health_api_port": server.server_port,
                "certweaver_cluster_health_retries": 2,
                "certweaver_cluster_health_delay": 0,
                "certweaver_cluster_health_request_timeout": "2s",
            }
            if case.startswith("preflight-"):
                variables.update(
                    certweaver_cluster_health_phase="pre-upgrade",
                    certweaver_cluster_version_current=version,
                    certweaver_cluster_health_nodes=["localhost"],
                )
            if case == "preflight-missing-observation":
                variables.pop("certweaver_cluster_version_current")
            if case == "preflight-cross-node":
                variables["certweaver_cluster_health_nodes"] = ["fixture-node"]
            if case == "invalid-phase":
                variables["certweaver_cluster_health_phase"] = "unknown"
            if case == "invalid-node":
                variables["certweaver_cluster_health_nodes"] = ["../../secrets"]
            if case == "unsupported-mode":
                variables["certweaver_mode"] = "existing-kubernetes"
            playbook = native / (case + ".yml")
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Synthetic health gate; no cluster or service mutation",
                            "hosts": "localhost",
                            "connection": "local",
                            "gather_facts": False,
                            "become": False,
                            "vars": variables,
                            "roles": ["cluster_health"],
                            "post_tasks": [
                                {
                                    "name": "Record successful advancement",
                                    "ansible.builtin.debug": {"msg": "HEALTH_GATE_ADVANCED"},
                                }
                            ],
                        }
                    ]
                )
            )
            env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "KUBE"))}
            env.update(
                ANSIBLE_ROLES_PATH=str(root / "roles"),
                ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
                ANSIBLE_NOCOLOR="1",
                NO_PROXY="127.0.0.1,localhost",
                no_proxy="127.0.0.1,localhost",
            )
            command = [
                str(Path(sys.executable).with_name("ansible-playbook")),
                "-i",
                "localhost,",
                str(playbook),
            ]
            if case == "check-mode":
                command.append("--check")
            completed = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=60)
            log = completed.stdout + b"\n" + completed.stderr
            (output / (case + ".log")).write_bytes(log)
            success = case in successes
            advanced = b'"msg": "HEALTH_GATE_ADVANCED"' in log
            (output / (case + "-observation.json")).write_text(
                json.dumps(
                    {
                        "case": case,
                        "exitCode": completed.returncode,
                        "httpRequests": state["requests"],
                        "advanced": advanced,
                        "expectedSuccess": success,
                    },
                    indent=2,
                )
                + "\n"
            )
            require(
                (completed.returncode == 0) == success and advanced == success,
                f"Unexpected health gate result: {case}",
            )
            if case in {
                "check-mode",
                "invalid-node",
                "unsupported-mode",
                "untrusted-ca",
                "preflight-missing-observation",
                "preflight-cross-node",
                "invalid-phase",
                "insecure-kubeconfig",
                "proxy-kubeconfig",
            }:
                require(not state["requests"], f"Unexpected API HTTP request: {case}")
            if case in {"insecure-kubeconfig", "proxy-kubeconfig"}:
                require(
                    b"Require TLS verification and direct local routing in kubeconfig" in log
                    and (
                        b"TASK [cluster_health : Wait for the authenticated "
                        b"local API readiness endpoint]"
                    )
                    not in log,
                    "Unsafe client context reached the network "
                    "instead of failing configuration validation",
                )
            if case in {"api-not-ready", "api-wrong-body", "unauthorized"}:
                require(not state["nodeCalls"], "Node check ran after API readiness failure")
            if case == "transient-api":
                require(state["apiCalls"] == 2, "API retry not exercised")
            if case == "transient-server-version":
                require(state["versionCalls"] == 2, "Server version retry not exercised")
            if case in {
                "api-version-mismatch",
                "api-revision-mismatch",
                "api-revision-mismatch-k3s",
                "missing-api-version",
                "malformed-api-version",
                "nonobject-api-version",
                "preflight-api-drift",
            }:
                require(not state["nodeCalls"], "Node query ran after server version rejection")
            if case == "transient-node":
                require(state["nodeCalls"] == 2, "Node retry not exercised")
            observations.append(
                {
                    "case": case,
                    "exitCode": completed.returncode,
                    "advanced": advanced,
                    "apiCalls": state["apiCalls"],
                    "nodeCalls": state["nodeCalls"],
                    "serverVersionCalls": state["versionCalls"],
                    "httpRequests": copy.deepcopy(state["requests"]),
                    "expectedResultVerified": True,
                }
            )
        # Version observations are supplied by a stub here; the separate version
        # fixture executes the actual binary observation role. Retain source play
        # boundaries and early/final health gates; only installers and preparation
        # are replaced with private fixture-control requests and markers.
        inventory = native / "upgrade-inventory.yml"
        hosts = {}
        for host in ["fixture-node", "fixture-peer", "fixture-third"]:
            hosts[host] = {
                "ansible_connection": "local",
                "certweaver_cluster_health_profiles": {
                    "rke2-ha": {
                        "argv": [str(client)],
                        "kubeconfig": str(client_config(host, host)),
                    },
                    "k3s-ha": {
                        "argv": [str(k3s), "kubectl"],
                        "kubeconfig": str(client_config(host, host)),
                    },
                },
            }
        inventory.write_text(
            yaml.safe_dump(
                {
                    "all": {
                        "children": {
                            "cluster_servers": {"hosts": hosts},
                            "cluster_bootstrap": {"hosts": {"fixture-node": {}}},
                            "cluster_joiners": {"hosts": {"fixture-peer": {}, "fixture-third": {}}},
                        }
                    }
                }
            )
        )
        variables.update(certweaver_mode="rke2-ha")
        variables.pop("certweaver_cluster_health_nodes")
        variables.pop("certweaver_cluster_health_profiles")
        server_tasks = yaml.safe_load((root / "roles/rke2_server/tasks/main.yml").read_text())
        early_gate, final_gate = copy.deepcopy(server_tasks[1]), copy.deepcopy(server_tasks[-1])
        fleet_cases = [
            "upgrade-healthy",
            "upgrade-preflight-failure",
            "upgrade-node-failure",
            "upgrade-api-version-failure",
            "upgrade-preflight-version-drift",
            "upgrade-peer-api-unready",
            "deploy-runtime-drift",
            "deploy-fresh",
            "deploy-fresh-k3s",
        ] + [
            name + suffix
            for suffix in ["", "-k3s"]
            for name in [
                "deploy-rolling-healthy",
                "deploy-same-version-repair",
                "deploy-preparation-failure",
                "deploy-peer-preparation-failure",
                "deploy-handler-failure",
                "deploy-final-health-failure",
                "deploy-recheck-drift",
            ]
        ]
        for case in fleet_cases:
            mode = "k3s-ha" if case.endswith("-k3s") else "rke2-ha"
            server_tasks = yaml.safe_load(
                (root / ("roles/" + mode.split("-", 1)[0] + "_server/tasks/main.yml")).read_text()
            )
            early_gate, final_gate = copy.deepcopy(server_tasks[1]), copy.deepcopy(server_tasks[-1])
            selected = "v1.33.12+k3s1" if mode == "k3s-ha" else "v1.33.12+rke2r2"
            observed_version = (
                selected
                if "same-version-repair" in case
                else ("v1.32.13+k3s1" if mode == "k3s-ha" else "v1.32.13+rke2r2")
            )
            state.update(
                case=case,
                requests=[],
                events=[],
                apiCalls=0,
                nodeCalls=0,
                versionCalls=0,
                version=selected,
                observedVersion=observed_version,
                perNodeVersionCalls={},
                mutated=set(),
                prepared=set(),
                fleet=True,
            )
            plays = yaml.safe_load(
                (
                    root
                    / (
                        "playbooks/" + mode + ".yml"
                        if case.startswith("deploy-")
                        else "playbooks/upgrade.yml"
                    )
                ).read_text()
            )
            for play in plays:
                play["gather_facts"] = False
                play["become"] = False
                play["vars"] = {**copy.deepcopy(variables), "certweaver_mode": mode}
            observation_task = {
                "name": "Supply separately qualified installed version observation",
                "ansible.builtin.set_fact": {
                    "certweaver_cluster_version_current": ""
                    if "deploy-fresh" in case
                    else observed_version,
                    "certweaver_cluster_version_install_needed": "same-version-repair" not in case,
                },
            }
            plays[0].pop("roles")
            plays[0]["tasks"] = [copy.deepcopy(observation_task)]
            for play in plays[2:]:
                roles = play.pop("roles")
                if "pre_tasks" in play:
                    play["pre_tasks"][0] = copy.deepcopy(observation_task)
                if any(r.get("role") in {"rke2_server", "k3s_server"} for r in roles):
                    preparation = []
                    if any(r.get("role") == "common" for r in roles):
                        preparation = [
                            {
                                "name": "Observe preparation at the source role boundary",
                                "ansible.builtin.uri": {
                                    "url": f"https://127.0.0.1:{server.server_port}/fixture/prepare",
                                    "method": "POST",
                                    "headers": {
                                        "Authorization": "Bearer synthetic-health-fixture-control"
                                    },
                                    "body_format": "json",
                                    "body": {"node": "{{ inventory_hostname }}"},
                                    "validate_certs": True,
                                    "ca_path": str(native / "ca.crt"),
                                },
                                "changed_when": True,
                                "notify": "Synthetic preparation handler",
                            }
                        ]
                        play["handlers"] = [
                            {
                                "name": "Synthetic preparation handler",
                                "ansible.builtin.uri": {
                                    "url": f"https://127.0.0.1:{server.server_port}/fixture/handler",
                                    "method": "POST",
                                    "headers": {
                                        "Authorization": "Bearer synthetic-health-fixture-control"
                                    },
                                    "body_format": "json",
                                    "body": {"node": "{{ inventory_hostname }}"},
                                    "validate_certs": True,
                                    "ca_path": str(native / "ca.crt"),
                                },
                            }
                        ]
                    play["tasks"] = preparation + [
                        early_gate,
                        {
                            "name": "Advance only the synthetic API after the installer boundary",
                            "ansible.builtin.uri": {
                                "url": f"https://127.0.0.1:{server.server_port}/fixture/mutate",
                                "method": "POST",
                                "headers": {
                                    "Authorization": "Bearer synthetic-health-fixture-control"
                                },
                                "body_format": "json",
                                "body": {"node": "{{ inventory_hostname }}"},
                                "validate_certs": True,
                                "ca_path": str(native / "ca.crt"),
                            },
                        },
                        {
                            "name": "Observe synthetic server mutation only",
                            "ansible.builtin.debug": {
                                "msg": "SYNTHETIC_SERVER_MUTATION_{{ inventory_hostname }}"
                            },
                        },
                        copy.deepcopy(
                            next(
                                t
                                for t in server_tasks
                                if t.get("ansible.builtin.meta") == "flush_handlers"
                            )
                        ),
                        final_gate,
                    ]
                elif any(r.get("role") == "cluster_addons" for r in roles):
                    play["tasks"] = [
                        {
                            "name": "Observe synthetic add-on mutation only",
                            "ansible.builtin.debug": {"msg": "SYNTHETIC_ADDONS_MUTATION"},
                        }
                    ]
                else:
                    play["tasks"] = [
                        {
                            "name": "Observe preparation without changing the platform",
                            "ansible.builtin.debug": {"msg": "COMMON_PREPARATION_ADVANCED"},
                        }
                    ]
            playbook = native / (case + ".yml")
            playbook.write_text(yaml.safe_dump(plays))
            completed = subprocess.run(
                [
                    str(Path(sys.executable).with_name("ansible-playbook")),
                    "-i",
                    str(inventory),
                    str(playbook),
                ],
                cwd=root,
                env=env,
                capture_output=True,
                timeout=120,
            )
            log = completed.stdout + b"\n" + completed.stderr
            (output / (case + ".log")).write_bytes(log)
            first = b'"msg": "SYNTHETIC_SERVER_MUTATION_fixture-node"' in log
            peer = b'"msg": "SYNTHETIC_SERVER_MUTATION_fixture-peer"' in log
            addons = b'"msg": "SYNTHETIC_ADDONS_MUTATION"' in log
            prepared = bool(state["prepared"])
            success = case in {"upgrade-healthy", "deploy-fresh", "deploy-fresh-k3s"} or any(
                name in case for name in ["rolling-healthy", "same-version-repair"]
            )
            partial = case in {"upgrade-node-failure", "upgrade-api-version-failure"} or any(
                name in case
                for name in ["peer-preparation-failure", "handler-failure", "final-health-failure"]
            )
            expected = (
                (True, True, True)
                if success
                else ((True, False, False) if partial else (False, False, False))
            )
            third = "fixture-third" in state["mutated"]
            observed = {
                "case": case,
                "exitCode": completed.returncode,
                "firstServerMutationMarker": first,
                "peerMutationMarker": peer,
                "thirdServerMutationMarker": third,
                "preparedNodes": sorted(state["prepared"]),
                "addonMutationMarker": addons,
                "preparationAdvanced": prepared,
                "mutatedNodes": sorted(state["mutated"]),
                "events": state["events"],
            }
            (output / (case + "-observation.json")).write_text(
                json.dumps(observed, indent=2) + "\n"
            )
            require(
                (completed.returncode == 0) == success
                and (first, peer, addons) == expected
                and third == success,
                "Runtime identity did not gate progression: " + case,
            )
            expected_prepared = set()
            if case.startswith("deploy-"):
                if success:
                    expected_prepared = {"fixture-node", "fixture-peer", "fixture-third"}
                elif "peer-preparation-failure" in case:
                    expected_prepared = {"fixture-node", "fixture-peer"}
                elif any(
                    n in case
                    for n in ["preparation-failure", "handler-failure", "final-health-failure"]
                ):
                    expected_prepared = {"fixture-node"}
            require(state["prepared"] == expected_prepared, "Unexpected host preparation: " + case)
            if success and case.startswith("deploy-"):
                events = state["events"]
                previous_ready = -1
                for host in ["fixture-node", "fixture-peer", "fixture-third"]:
                    preparation_index = events.index("PREPARE:" + host)
                    mutation_index = events.index("MUTATE:" + host)
                    handler_index = events.index("HANDLER:" + host)
                    ready_index = events.index(
                        "GET:" + host + ":/api/v1/nodes/" + host, handler_index + 1
                    )
                    require(
                        previous_ready
                        < preparation_index
                        < mutation_index
                        < handler_index
                        < ready_index,
                        "Next host prepared before the previous host completed handler/readiness",
                    )
                    previous_ready = ready_index
                if "fresh" in case or "same-version-repair" in case:
                    first_change = events.index("MUTATE:fixture-node")
                    require(
                        not any(e.startswith("GET:") for e in events[:first_change]),
                        "Fresh or same-version repair probed an unavailable API before startup",
                    )
            observations.append({**observed, "expectedResultVerified": True})
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)
    result = {
        "scope": (
            "Actual Ansible role and pinned kubectl against synthetic localhost TLS/API responses; "
            "no real cluster, upgrade, quorum, workload or service availability proof"
        ),
        "client": record,
        "observations": observations,
    }
    (output / "cluster-health-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        parser.error("The fixture client is pinned for Linux/amd64")
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be a fresh directory inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-health-fixture-") as temporary:
        result = verify(
            root, output, Path(temporary), args.kubectl.absolute() if args.kubectl else None
        )
    print(f"Verified {len(result['observations'])} authenticated API/node health cases")
