"""Qualify snapshot Secret convergence and concurrent private staging locally."""

from __future__ import annotations

import argparse
import base64
import copy
import http.server
import json
import os
import re
import runpy
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


class SecretAPI:
    """Minimal discovery/Secret model; this does not emulate Kubernetes SSA ownership."""

    def __init__(self, native):
        self.live = {}
        self.events = []
        self.token = "synthetic-api-token-" + os.urandom(12).hex()
        self.failure = None
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send(self, status, body):
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def error(self, status, reason):
                self.send(
                    status,
                    {
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "reason": reason,
                        "message": "Synthetic fixture failure",
                        "code": status,
                    },
                )

            def authorized(self):
                if self.headers.get("Authorization") != "Bearer " + parent.token:
                    self.error(401, "Unauthorized")
                    return False
                return True

            def do_GET(self):
                if not self.authorized():
                    return
                path = urlsplit(self.path).path
                parent.events.append({"method": "GET", "path": path})
                if path == "/api":
                    return self.send(
                        200,
                        {
                            "kind": "APIVersions",
                            "apiVersion": "v1",
                            "versions": ["v1"],
                            "serverAddressByClientCIDRs": [],
                        },
                    )
                if path == "/apis":
                    return self.send(
                        200, {"kind": "APIGroupList", "apiVersion": "v1", "groups": []}
                    )
                if path == "/api/v1":
                    return self.send(
                        200,
                        {
                            "kind": "APIResourceList",
                            "apiVersion": "v1",
                            "groupVersion": "v1",
                            "resources": [
                                {
                                    "name": "secrets",
                                    "singularName": "",
                                    "namespaced": True,
                                    "kind": "Secret",
                                    "verbs": ["get", "patch", "create"],
                                }
                            ],
                        },
                    )
                if path == "/openapi/v3":
                    return self.send(
                        200,
                        {
                            "paths": {
                                "api/v1": {"serverRelativeURL": "/openapi/v3/api/v1?hash=synthetic"}
                            }
                        },
                    )
                if path == "/openapi/v3/api/v1":
                    operation = {
                        "x-kubernetes-group-version-kind": {
                            "group": "",
                            "version": "v1",
                            "kind": "Secret",
                        },
                        "parameters": [
                            {"name": "fieldValidation", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "Synthetic fixture response"}},
                    }
                    return self.send(
                        200,
                        {
                            "openapi": "3.0.0",
                            "info": {"title": "Synthetic Secret fixture", "version": "v1"},
                            "paths": {
                                "/api/v1/namespaces/{namespace}/secrets/{name}": {
                                    "patch": operation
                                }
                            },
                            "components": {"schemas": {}},
                        },
                    )
                if path.startswith("/api/v1/namespaces/kube-system/secrets/"):
                    if parent.failure == "read":
                        return self.error(403, "Forbidden")
                    name = path.rsplit("/", 1)[1]
                    if name in parent.live:
                        return self.send(200, parent.live[name])
                return self.error(404, "NotFound")

            def do_PATCH(self):
                if not self.authorized():
                    return
                parsed = urlsplit(self.path)
                dry = "dryRun" in parse_qs(parsed.query)
                name = parsed.path.rsplit("/", 1)[1]
                parent.events.append({"method": "PATCH", "path": parsed.path, "dryRun": dry})
                if parent.failure == "diff" and dry:
                    return self.error(409, "Conflict")
                if parent.failure == "apply" and not dry:
                    return self.error(500, "InternalError")
                value = yaml.safe_load(self.rfile.read(int(self.headers["Content-Length"])))
                require(
                    self.headers.get("Content-Type") == "application/apply-patch+yaml",
                    "Client must use server-side apply",
                )
                require(
                    value["apiVersion"] == "v1"
                    and value["kind"] == "Secret"
                    and value["metadata"]["name"] == name
                    and value["type"] == "etcd.k3s.cattle.io/s3-config-secret"
                    and isinstance(value["data"], dict),
                    "Unexpected fixture Secret",
                )
                metadata = copy.deepcopy(parent.live.get(name, {}).get("metadata", {}))
                metadata.update(value["metadata"])
                metadata.update(
                    namespace="kube-system",
                    uid="synthetic-" + name,
                    resourceVersion="1",
                    creationTimestamp="2026-11-03T00:00:00Z",
                )
                value["metadata"] = metadata
                if not dry:
                    parent.live[name] = copy.deepcopy(value)
                self.send(200, value)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(native / "server.crt", native / "server.key")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = "https://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def barrier(arguments):
    """Deterministically interleave two real Ansible processes using owned markers."""
    mode, folder = arguments[0], Path(arguments[1])
    (folder / (mode + "-ready")).touch(mode=0o600)
    other = "b-ready" if mode == "a" else "a-done"
    deadline = time.monotonic() + 40
    while not (folder / other).exists():
        require(time.monotonic() < deadline, "Concurrent fixture barrier timed out")
        time.sleep(0.05)


def rewrite(value, directory):
    if isinstance(value, str):
        return value.replace("/run/certweaver-etcd-s3.env", str(directory / "shared.env")).replace(
            "/run/certweaver-etcd-s3-secret.yaml", str(directory / "shared.yaml")
        )
    if isinstance(value, list):
        return [rewrite(v, directory) for v in value]
    if isinstance(value, dict):
        return {
            k: (str(directory) if k == "path" and v == "/run" else rewrite(v, directory))
            for k, v in value.items()
        }
    return value


def make_play(root, directory, api, ca, source, name, block, interleave=None):
    private = copy.deepcopy(block)
    private = rewrite(private, directory)
    if interleave:
        index = (
            next(
                i for i, t in enumerate(private["block"]) if t["name"].startswith("Require exactly")
            )
            + 1
        )
        private["block"].insert(
            index,
            {
                "name": "Interleave owned synthetic staging operations",
                "ansible.builtin.command": {
                    "argv": [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--barrier",
                        interleave,
                        str(directory),
                    ]
                },
                "changed_when": False,
            },
        )
    variables = {
        "ansible_python_interpreter": sys.executable,
        "certweaver_mode": "rke2-ha",
        "certweaver_environment": "production",
        "certweaver_rke2_etcd_snapshot_enabled": True,
        "certweaver_rke2_etcd_s3_enabled": True,
        "certweaver_rke2_etcd_s3_config_file": str(source),
        "certweaver_kubeconfig_path": str(ca),
        "certweaver_rke2_etcd_s3_secret_name": name,
    }
    play = directory / (name + ".yml")
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Owned Secret reconciliation fixture",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "become": False,
                    "vars": variables,
                    "tasks": [private],
                }
            ]
        ),
        encoding="utf-8",
    )
    return play


def configuration(native, api, *, wrong_ca=False, wrong_token=False):
    path = native / ("wrong-ca" if wrong_ca else "wrong-token" if wrong_token else "kubeconfig")
    trust = native / "untrusted/ca.crt" if wrong_ca else native / "ca.crt"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [
                    {
                        "name": "fixture",
                        "cluster": {"server": api.endpoint, "certificate-authority": str(trust)},
                    }
                ],
                "contexts": [
                    {"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}
                ],
                "users": [
                    {
                        "name": "fixture",
                        "user": {"token": "synthetic-denied" if wrong_token else api.token},
                    }
                ],
                "current-context": "fixture",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def environment(root, native):
    (native / "home").mkdir(mode=0o700, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "PYTHON", "KUBE"))}
    env.update(
        PATH=str(native) + ":" + os.environ["PATH"],
        TMPDIR=str(native),
        HOME=str(native / "home"),
        ANSIBLE_ROLES_PATH=str(root / "roles"),
        ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
        ANSIBLE_REMOTE_TEMP=str(native / "remote"),
        ANSIBLE_NOCOLOR="1",
        KUBECTL_KUBERC="false",
    )
    return env


def execute(play, env, output, label, check=False):
    args = [
        str(Path(sys.executable).with_name("ansible-playbook")),
        "-i",
        "localhost,",
        str(play),
        "-vvv",
        "--diff",
    ]
    if check:
        args.append("--check")
    result = subprocess.run(args, env=env, capture_output=True, timeout=120)
    log = result.stdout + b"\n" + result.stderr
    (output / (label + ".log")).write_bytes(log)
    recap = re.search(rb"localhost\s+: ok=\d+\s+changed=(\d+).*failed=(\d+)", log)
    return result.returncode, int(recap[1]) if recap else None, log


def verify(root, output, native, supplied=None):
    tools = runpy.run_path(str(root / "scripts/check-snapshot-config.py"))
    tools["guard"](root)
    native.mkdir(mode=0o700)
    health = runpy.run_path(str(root / "scripts/check-cluster-health.py"))
    identity = health["acquire_client"](root, native / "kubectl", supplied)
    health["make_certificates"](native)
    (native / "untrusted").mkdir(mode=0o700)
    health["make_certificates"](native / "untrusted")
    api = SecretAPI(native)
    observations = []
    block = tools["snapshot_block"](root)
    env = environment(root, native)
    canaries = []
    try:
        config = configuration(native, api)
        directory = native / "sequential"
        directory.mkdir(mode=0o700)
        source = directory / "source.env"
        first = "synthetic-snapshot-first-" + os.urandom(12).hex()
        second = "synthetic-snapshot-second-" + os.urandom(12).hex()
        canaries.extend([first, second])
        for case in [
            "create",
            "repeat",
            "rotation",
            "field-removal",
            "live-drift",
            "unrelated-metadata",
            "read-error",
            "diff-conflict",
            "apply-error",
            "wrong-ca",
            "wrong-token",
            "check-mode",
            "external-diff",
            "stale-stage-preflight",
            "allocation-failure",
        ]:
            value = first if case in {"create", "repeat"} else second
            payload = f"etcd-s3-secret-key={value}\n"
            if case in {"create", "repeat", "rotation"}:
                payload += "etcd-s3-bucket=synthetic-bucket\n"
            source.write_text(payload, encoding="utf-8")
            source.chmod(0o600)
            chosen_block = copy.deepcopy(block)
            preserved = directory / "prior-stage"
            if case in {"stale-stage-preflight", "allocation-failure"}:
                preserved.mkdir(mode=0o700, exist_ok=True)
                (preserved / "sentinel").write_text("synthetic-prior-invocation", encoding="utf-8")
                if case == "stale-stage-preflight":
                    source.write_text(payload + "etcd-s3-insecure=true\n", encoding="utf-8")
                else:
                    allocation = next(
                        t
                        for t in chosen_block["block"]
                        if t["name"].startswith("Allocate invocation")
                    )
                    allocation["ansible.builtin.tempfile"]["path"] = str(
                        directory / "missing-parent"
                    )
            if case == "live-drift":
                api.live["probe"]["data"]["etcd-s3-secret-key"] = base64.b64encode(
                    b"synthetic-drift"
                ).decode()
            if case == "unrelated-metadata":
                api.live["probe"]["metadata"]["labels"] = {"other-owner": "preserved"}
            api.failure = {
                "read-error": "read",
                "diff-conflict": "diff",
                "apply-error": "apply",
            }.get(case)
            if case in {"diff-conflict", "apply-error"}:
                api.live["probe"]["data"]["etcd-s3-secret-key"] = base64.b64encode(
                    b"synthetic-drift"
                ).decode()
            if case in {"wrong-ca", "wrong-token"}:
                chosen = configuration(
                    native, api, wrong_ca=case == "wrong-ca", wrong_token=case == "wrong-token"
                )
            else:
                chosen = config
            if case == "external-diff":
                env["KUBECTL_EXTERNAL_DIFF"] = "sh -c 'exit 0'"
                api.live["probe"]["data"]["etcd-s3-secret-key"] = base64.b64encode(
                    b"synthetic-drift"
                ).decode()
            play = make_play(root, directory, api, chosen, source, "probe", chosen_block)
            if case in {"stale-stage-preflight", "allocation-failure"}:
                document = yaml.safe_load(play.read_text(encoding="utf-8"))
                document[0]["vars"]["certweaver_snapshot_stage"] = {"path": str(preserved)}
                play.write_text(yaml.safe_dump(document), encoding="utf-8")
            start = len(api.events)
            rc, changed, log = execute(play, env, output, case, check=case == "check-mode")
            updates = sum(e["method"] == "PATCH" and not e["dryRun"] for e in api.events[start:])
            fails = case in {
                "read-error",
                "diff-conflict",
                "apply-error",
                "wrong-ca",
                "wrong-token",
                "stale-stage-preflight",
                "allocation-failure",
            }
            changes = case in {"create", "rotation", "field-removal", "live-drift", "external-diff"}
            require(rc == (2 if fails else 0), "Unexpected reconciliation result: " + case)
            require(
                updates == (1 if changes or case == "apply-error" else 0),
                "Unexpected live apply count: " + case,
            )
            if not fails:
                require(changed == int(changes), "Incorrect persistent change count: " + case)
            require(
                not list(directory.glob("certweaver-etcd-s3-*")),
                "Private staging survived: " + case,
            )
            require(
                all(
                    c.encode() not in log and base64.b64encode(c.encode()) not in log
                    for c in canaries
                ),
                "Private credential appeared in diagnostics",
            )
            if case == "check-mode":
                require(len(api.events) == start, "Check mode contacted the API")
            if case in {"stale-stage-preflight", "allocation-failure"}:
                require(
                    (preserved / "sentinel").read_text(encoding="utf-8")
                    == "synthetic-prior-invocation",
                    "Cleanup removed another staging identity",
                )
            if changes:
                require(
                    base64.b64decode(api.live["probe"]["data"]["etcd-s3-secret-key"]).decode()
                    == value,
                    "API received different credentials",
                )
            observations.append(
                {
                    "case": case,
                    "exitCode": rc,
                    "changed": changed,
                    "liveApplyRequests": updates,
                    "expectedResultVerified": True,
                    "privateCanaryAbsentFromOutput": True,
                    "stagingRemoved": True,
                }
            )
        for same in [False, True]:
            directory = native / ("concurrent-same" if same else "concurrent-distinct")
            directory.mkdir(mode=0o700)
            values = [first, first if same else second]
            processes = []
            handles = []
            try:
                for mode, value in zip(["a", "b"], values, strict=True):
                    source = directory / (mode + ".env")
                    source.write_text(f"etcd-s3-secret-key={value}\n", encoding="utf-8")
                    source.chmod(0o600)
                    play = make_play(
                        root, directory, api, config, source, "probe-" + mode, block, mode
                    )
                    handle = (output / (directory.name + "-" + mode + ".log")).open("wb")
                    handles.append(handle)
                    processes.append(
                        subprocess.Popen(
                            [
                                str(Path(sys.executable).with_name("ansible-playbook")),
                                "-i",
                                "localhost,",
                                str(play),
                                "-vvv",
                                "--diff",
                            ],
                            env=env,
                            stdout=handle,
                            stderr=subprocess.STDOUT,
                        )
                    )
                    if mode == "a":
                        deadline = time.monotonic() + 40
                        while not (directory / "a-ready").exists():
                            require(
                                processes[0].poll() is None and time.monotonic() < deadline,
                                "First concurrent fixture did not reach the barrier",
                            )
                            time.sleep(0.05)
                codes = [processes[0].wait(timeout=60)]
                (directory / "a-done").touch(mode=0o600)
                codes.append(processes[1].wait(timeout=60))
                require(codes == [0, 0], "Concurrent reconciliation failed")
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                for handle in handles:
                    handle.close()
            for mode, expected in zip(["a", "b"], values, strict=True):
                require(
                    base64.b64decode(
                        api.live["probe-" + mode]["data"]["etcd-s3-secret-key"]
                    ).decode()
                    == expected,
                    "Concurrent invocation published another invocation's credential",
                )
                log = (output / (directory.name + "-" + mode + ".log")).read_bytes()
                require(
                    all(
                        c.encode() not in log and base64.b64encode(c.encode()) not in log
                        for c in canaries
                    ),
                    "Concurrent diagnostics disclosed credentials",
                )
            require(not list(directory.glob("certweaver-etcd-s3-*")), "Concurrent staging survived")
            observations.append(
                {
                    "case": directory.name,
                    "exitCodes": codes,
                    "expectedResultVerified": True,
                    "privateCanaryAbsentFromOutput": True,
                    "stagingRemoved": True,
                    "credentialIsolationVerified": True,
                }
            )
    finally:
        api.close()
    record = {
        "scope": "Actual source Ansible block and pinned kubectl with authenticated "
        "localhost HTTPS "
        "discovery/Secret model, including two real concurrent Ansible processes. Synthetic API "
        "does not qualify Kubernetes SSA ownership/admission, remote privilege, "
        "object storage or production.",
        "clientIdentity": identity,
        "observations": observations,
    }
    (output / "snapshot-reconcile-result.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    return record


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--barrier":
        barrier(sys.argv[2:])
        raise SystemExit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--kubectl", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux root for owned credential fixtures")
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-snapshot-reconcile-") as temporary:
        result = verify(root, output, Path(temporary) / "cases", args.kubectl)
    print("Verified " + str(len(result["observations"])) + " snapshot reconciliation cases")
