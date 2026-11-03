"""Exercise managed operator preparation and private export with a real TLS client."""

from __future__ import annotations

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
import threading
from pathlib import Path
from urllib.parse import urlsplit

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def configuration_by_name(value):
    """Compare named kubeconfig records without discarding fields or accepting duplicates."""
    result = copy.deepcopy(value)
    for key in ["clusters", "contexts", "users"]:
        entries = result.get(key, [])
        require(
            isinstance(entries, list)
            and all(isinstance(e, dict) and isinstance(e.get("name"), str) for e in entries),
            "Kubeconfig named entries must be explicit records",
        )
        names = [e["name"] for e in entries]
        require(len(set(names)) == len(names), "Duplicate kubeconfig named entry")
        result[key] = {e["name"]: e for e in entries}
    return result


def guard(root):
    role = root / "roles/cluster_addons/tasks"
    main = yaml.safe_load((role / "main.yml").read_text())
    include = next(
        t
        for t in main
        if t.get("ansible.builtin.include_tasks") == "_configure_operator_endpoint.yml"
    )
    export = next(
        t for t in main if t.get("ansible.builtin.include_tasks") == "_export_kubeconfig.yml"
    )
    require(
        include.get("when") == "certweaver_mode in ['rke2-ha', 'k3s-ha']"
        and main.index(include) < main.index(export)
        and not any("ansible.builtin.replace" in t for t in main),
        "Selected endpoint preparation must precede export without textual replacement",
    )
    for name in [
        "Copy cluster kubeconfig into the operator path",
        "Protect an in-place existing-cluster kubeconfig",
    ]:
        require(
            "certweaver_mode == 'existing-kubernetes'"
            in next(t for t in main if t["name"] == name).get("when", []),
            "Managed operator credentials must be prepared before final publication",
        )
    document = yaml.safe_load((role / "_configure_operator_endpoint.yml").read_text())
    block = document[1]
    require(
        "not (lookup('ansible.builtin.config', 'DEFAULT_DEBUG') | bool)"
        in document[0]["ansible.builtin.assert"]["that"]
        and block.get("when") == "not ansible_check_mode"
        and block.get("no_log") is True
        and block.get("diff") is False
        and all(
            t.get("no_log", True) is True and t.get("diff", False) is False
            for t in [*block["block"], *block["always"]]
        ),
        "Private preparation requires debug/check-mode and logging boundaries",
    )
    tasks = block["block"]
    views = [t for t in tasks if "Inspect the " in t["name"] and "context" in t["name"]]
    expected_view = [
        "kubectl",
        "--kubeconfig={{ certweaver_operator_stage.path }}/kubeconfig",
        "config",
        "view",
        "--minify",
        "--output=json",
    ]
    require(
        len(views) == 2
        and all(
            t["ansible.builtin.command"]["argv"] == expected_view and t.get("timeout") == 30
            for t in views
        ),
        "Inspect only selected staged contexts without raw credentials",
    )
    checks = next(t for t in tasks if t["name"].startswith("Require one selected"))
    conditions = checks["ansible.builtin.assert"]["that"]
    require(
        len(conditions) == 5
        and "insecure-skip-tls-verify" in conditions[3]
        and "not (" in conditions[3]
        and "proxy-url" in conditions[4]
        and "| length == 0" in conditions[4],
        "TLS verification and direct routing are mandatory",
    )
    update = next(t for t in tasks if t["name"].startswith("Set the selected"))
    require(
        update["ansible.builtin.command"]["argv"]
        == [
            "kubectl",
            "--kubeconfig={{ certweaver_operator_stage.path }}/kubeconfig",
            "config",
            "set-cluster",
            "{{ (certweaver_operator_context_before.stdout | from_json)['clusters'][0].name }}",
            "--server={{ certweaver_operator_api_endpoint }}",
            "--tls-server-name={{ certweaver_operator_selected_cluster"
            ".get('tls-server-name', '') }}",
        ],
        "Update exactly the selected staged cluster, preserving its other fields",
    )
    require(
        update.get("vars")
        == {
            "certweaver_operator_selected_cluster": "{{ (certweaver_operator_context_before.stdout "
            "| from_json)['clusters'][0]['cluster'] }}"
        },
        "TLS name must come from the inspected selected cluster",
    )
    destination_policy = next(t for t in tasks if t["name"].startswith("Require an absent"))
    require(
        destination_policy["ansible.builtin.assert"]["that"][-1]
        == "not certweaver_operator_destination.stat.exists or "
        "certweaver_operator_destination.stat.dev != certweaver_operator_source.stat.dev or "
        "certweaver_operator_destination.stat.inode != certweaver_operator_source.stat.inode",
        "Distribution source and final operator destination must be distinct files",
    )
    publish = tasks[-1]["ansible.builtin.copy"]
    require(
        publish
        == {
            "src": "{{ certweaver_operator_stage.path }}/kubeconfig",
            "dest": "{{ certweaver_kubeconfig_path }}",
            "remote_src": True,
            "owner": "root",
            "group": "root",
            "mode": "0600",
            "follow": False,
            "unsafe_writes": False,
            "backup": False,
            "force": True,
        },
        "Only a private atomic copy may publish prepared credentials",
    )
    require(
        len(tasks[-2]["ansible.builtin.assert"]["that"]) == 4
        and block["always"][0]["ansible.builtin.file"]
        == {"path": "{{ certweaver_operator_stage.path }}", "state": "absent"}
        and block["always"][0].get("when") == "certweaver_operator_stage.path is defined",
        "Verify preserved selected configuration and always remove private staging",
    )


def verify(root, output, native, supplied=None):
    guard(root)
    native.mkdir(mode=0o700)
    health = runpy.run_path(str(Path(__file__).with_name("check-cluster-health.py")))
    client = native / "kubectl"
    identity = health["acquire_client"](root, client, supplied)
    health["make_certificates"](native)
    untrusted = native / "untrusted"
    untrusted.mkdir(mode=0o700)
    health["make_certificates"](untrusted)
    expected_token = ""
    requests = []

    class API(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            allowed = (
                path == "/readyz"
                and self.headers.get("Authorization") == "Bearer " + expected_token
            )
            requests.append({"path": path, "authorized": allowed})
            body = b"ok" if allowed else b"Unauthorized"
            self.send_response(200 if allowed else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(native / "server.crt", native / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    endpoint = "https://127.0.0.1:" + str(server.server_port)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "KUBE", "PYTHON"))}
    env.update(
        PATH=str(native) + ":" + os.environ["PATH"],
        TMPDIR=str(native),
        ANSIBLE_ROLES_PATH=str(root / "roles"),
        ANSIBLE_LOCAL_TEMP=str(native / "ansible"),
        ANSIBLE_NOCOLOR="1",
        PYTHONDONTWRITEBYTECODE="1",
        KUBECTL_KUBERC="false",
    )
    main = yaml.safe_load((root / "roles/cluster_addons/tasks/main.yml").read_text())
    endpoint_call = next(
        t
        for t in main
        if t.get("ansible.builtin.include_tasks") == "_configure_operator_endpoint.yml"
    )
    exports = [
        main[0],
        next(t for t in main if t.get("ansible.builtin.include_tasks") == "_export_kubeconfig.yml"),
    ]
    observations = []
    cases = [
        "plain",
        "double-quoted",
        "single-quoted",
        "multiple-contexts",
        "custom-old-port",
        "k3s",
        "repeat",
        "rotation",
        "existing",
        "check-mode",
        "missing-context",
        "insecure",
        "proxy",
        "wrong-ca",
        "wrong-server-name",
        "explicit-server-name",
        "source-alias",
        "unauthorized",
        "invalid-vip",
        "invalid-port",
    ]
    try:
        for case in cases:
            folder = native / case
            folder.mkdir(mode=0o700)
            source = folder / "distribution.yml"
            operator = folder / "operator.yml"
            private = folder / "private"
            private.mkdir(mode=0o700)
            target = private / "kubeconfig"
            canary = "synthetic-operator-token-" + os.urandom(12).hex()
            expected_token = canary
            ca = (untrusted if case == "wrong-ca" else native) / "ca.crt"
            cluster = {
                "server": endpoint if case == "existing" else "https://127.0.0.1:6443",
                "certificate-authority-data": base64.b64encode(ca.read_bytes()).decode(),
            }
            if case == "custom-old-port":
                cluster["server"] = "https://127.0.0.1:7443"
            if case == "insecure":
                cluster.pop("certificate-authority-data")
                cluster["insecure-skip-tls-verify"] = True
            if case == "proxy":
                cluster["proxy-url"] = "http://127.0.0.1:9"
            if case == "wrong-server-name":
                cluster["tls-server-name"] = "wrong.invalid"
            if case == "explicit-server-name":
                cluster["tls-server-name"] = "127.0.0.1"
            config = {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "selected", "cluster": cluster}],
                "contexts": [
                    {
                        "name": "selected-context",
                        "context": {"cluster": "selected", "user": "operator"},
                    }
                ],
                "current-context": "missing" if case == "missing-context" else "selected-context",
                "users": [{"name": "operator", "user": {"token": canary}}],
            }
            if case == "multiple-contexts":
                config["clusters"].insert(
                    0, {"name": "unselected", "cluster": {"server": "https://192.0.2.99:6443"}}
                )
                config["contexts"].insert(
                    0, {"name": "other", "context": {"cluster": "unselected", "user": "operator"}}
                )
            data = yaml.safe_dump(config, sort_keys=False)
            if case in {"single-quoted", "double-quoted"}:
                quote = "'" if case == "single-quoted" else '"'
                data = data.replace(
                    "server: https://127.0.0.1:6443",
                    "server: " + quote + "https://127.0.0.1:6443" + quote,
                )
            source.write_text(data)
            source.chmod(0o640 if case == "k3s" else 0o600)
            original = source.read_bytes()
            if case == "source-alias":
                operator = source
            # Rejected preparation must preserve the prior published operator file.
            if case in {"missing-context", "insecure", "proxy", "invalid-vip", "invalid-port"}:
                operator.write_bytes(b"previous private operator content")
                operator.chmod(0o600)
            values = {
                "ansible_python_interpreter": sys.executable,
                "ansible_remote_tmp": str(native / "remote"),
                "certweaver_mode": "existing-kubernetes"
                if case == "existing"
                else ("k3s-ha" if case == "k3s" else "rke2-ha"),
                "certweaver_deployment_name": "fixture-endpoint",
                "certweaver_fetch_kubeconfig": True,
                "certweaver_local_kubeconfig_path": str(target),
                "certweaver_kubeconfig_path": str(operator),
                "certweaver_cluster_kubeconfig_source": str(source),
                "certweaver_vip": "999.0.0.1" if case == "invalid-vip" else "127.0.0.1",
                "certweaver_api_front_port": 65536
                if case == "invalid-port"
                else server.server_port,
            }
            calls = []
            selected_calls = [exports[0]]
            if case == "existing":
                selected_calls += [
                    next(
                        t
                        for t in main
                        if t["name"] == "Copy cluster kubeconfig into the operator path"
                    )
                ]
            selected_calls += [
                endpoint_call,
                {
                    "name": "Observe validated operator preparation",
                    "ansible.builtin.debug": {"msg": "OPERATOR_PREPARATION_ADVANCED"},
                },
                exports[1],
            ]
            for original_task in selected_calls:
                task = copy.deepcopy(original_task)
                if "ansible.builtin.include_tasks" in task:
                    task["ansible.builtin.include_role"] = {
                        "name": "cluster_addons",
                        "tasks_from": task.pop("ansible.builtin.include_tasks"),
                    }
                calls.append(task)
            playbook = folder / "fixture.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "hosts": "localhost",
                            "connection": "local",
                            "become": False,
                            "gather_facts": False,
                            "vars": values,
                            "tasks": calls,
                        }
                    ]
                )
            )
            for iteration in range(2 if case in {"repeat", "rotation"} else 1):
                if iteration and case == "rotation":
                    canary += "-rotated"
                    expected_token = canary
                    config["users"][0]["user"]["token"] = canary
                    source.write_text(yaml.safe_dump(config))
                    original = source.read_bytes()
                command = [
                    str(Path(sys.executable).with_name("ansible-playbook")),
                    "-i",
                    "localhost,",
                    str(playbook),
                    "--diff",
                    "-vvv",
                ]
                if case == "check-mode":
                    command.append("--check")
                run = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=120)
                log = run.stdout + b"\n" + run.stderr
                label = case + "-" + str(iteration)
                (output / ("endpoint-" + label + ".log")).write_bytes(log)
                rejected = case in {
                    "missing-context",
                    "insecure",
                    "proxy",
                    "invalid-vip",
                    "invalid-port",
                    "source-alias",
                }
                require(
                    (run.returncode != 0) == rejected,
                    "Unexpected endpoint preparation result: " + label,
                )
                require(canary.encode() not in log, "Credential entered endpoint fixture output")
                require(
                    source.read_bytes() == original,
                    "Distribution kubeconfig changed during preparation",
                )
                if rejected:
                    require(
                        operator.read_bytes()
                        == (
                            original
                            if case == "source-alias"
                            else b"previous private operator content"
                        )
                        and not target.exists()
                        and b'"msg": "OPERATOR_PREPARATION_ADVANCED"' not in log,
                        "Rejected preparation changed the prior operator or advanced to export",
                    )
                elif case == "check-mode":
                    require(
                        not operator.exists() and not target.exists(),
                        "Check mode published credentials",
                    )
                else:
                    expected = copy.deepcopy(config)
                    next(c for c in expected["clusters"] if c["name"] == "selected")["cluster"][
                        "server"
                    ] = endpoint
                    require(
                        configuration_by_name(yaml.safe_load(operator.read_text()))
                        == configuration_by_name(expected),
                        "Prepared configuration changed fields other than selected server",
                    )
                    require(
                        target.read_bytes() == operator.read_bytes()
                        and target.stat().st_mode & 0o777 == 0o600,
                        "Controller export differs from prepared operator bytes or mode",
                    )
                    if iteration and case == "repeat":
                        require(
                            re.search(rb"changed=0\s", log),
                            "Full preparation/export was not idempotent",
                        )
                    if case == "unauthorized":
                        expected_token = canary + "-not-accepted"
                    requests.clear()
                    probe = subprocess.run(
                        [
                            str(client),
                            "--kubeconfig=" + str(target),
                            "--request-timeout=3s",
                            "get",
                            "--raw=/readyz",
                        ],
                        env=env,
                        capture_output=True,
                        timeout=15,
                    )
                    probe_log = probe.stdout + b"\n" + probe.stderr
                    (output / ("endpoint-" + label + "-client.log")).write_bytes(probe_log)
                    denied = case in {"wrong-ca", "wrong-server-name", "unauthorized"}
                    require(
                        (probe.returncode != 0) == denied,
                        "Unexpected real TLS client result: " + label,
                    )
                    if not denied:
                        require(
                            probe.stdout.strip() == b"ok"
                            and requests == [{"path": "/readyz", "authorized": True}],
                            "Real client did not authenticate to the configured TLS endpoint",
                        )
                    elif case == "unauthorized":
                        require(
                            requests and not any(r["authorized"] for r in requests),
                            "Unauthorized token was accepted",
                        )
                    else:
                        require(
                            not requests and b"x509:" in probe_log,
                            "Trust/hostname case was not rejected by TLS verification",
                        )
                    require(
                        canary.encode() not in probe_log,
                        "Client error output contained credentials",
                    )
                require(
                    not list(native.glob("certweaver-operator-*")),
                    "Private staging directory survived preparation",
                )
                observations.append(
                    {
                        "case": label,
                        "expectedResultVerified": True,
                        "preparationExitCode": run.returncode,
                        "realTlsClientExercised": not rejected and case != "check-mode",
                        "credentialAbsentFromOutput": True,
                    }
                )
    finally:
        server.shutdown()
        worker.join(timeout=10)
        server.server_close()
    result = {
        "scope": "Actual managed preparation/export tasks and pinned real TLS client against "
        "synthetic local authenticated API; no live cluster, remote SSH/become "
        "or production acceptance",
        "client": identity,
        "observations": observations,
    }
    (output / "operator-endpoint-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
