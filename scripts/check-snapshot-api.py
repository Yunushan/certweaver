"""Qualify snapshot reconciliation against isolated real Kubernetes API processes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import runpy
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard(root):
    tools = runpy.run_path(str(root / "scripts/install-ci-tool.py"))
    records = {n: tools["tool_record"](root, n) for n in ["kube-apiserver", "etcd"]}
    baseline = yaml.safe_load((root / "config/versions.yml").read_text(encoding="utf-8"))
    require(
        all(
            baseline[n].split("+", 1)[0] == records["kube-apiserver"]["version"]
            for n in ["rke2", "k3s"]
        ),
        "API fixture must match the selected upstream patch",
    )
    return records


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    require(process.poll() is not None, "Owned API process did not terminate")


class ControlPlane:
    """Own all files/processes and expose only mutually authenticated loopback TLS."""

    def __init__(self, native, output, api_binary, etcd_binary):
        self.native, self.output = native, output
        self.api_binary, self.etcd_binary = api_binary, etcd_binary
        self.cert = native / "certs"
        self.audit_path = native / "audit.jsonl"
        self.processes, self.handles = [], []
        for name in ["certs", "data", "home"]:
            (native / name).mkdir(mode=0o700)
        self.env = {
            k: v for k, v in os.environ.items() if not k.startswith(("KUBE", "ETCD_", "PYTHON"))
        }
        self.env.update(HOME=str(native / "home"), TMPDIR=str(native))

    def run(self, args):
        return subprocess.run(
            args, env=self.env, cwd=self.native, check=True, capture_output=True, timeout=30
        )

    def certificates(self):
        cert = self.cert
        self.run(
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
                "/CN=CertWeaver isolated fixture CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(cert / "ca.key"),
                "-out",
                str(cert / "ca.crt"),
            ]
        )
        for name, subject, usage in [
            ("server", "/CN=CertWeaver loopback API", "serverAuth,clientAuth"),
            ("admin", "/CN=certweaver-fixture-admin/O=system:masters", "clientAuth"),
            ("denied", "/CN=certweaver-fixture-denied", "clientAuth"),
            ("etcd-client", "/CN=certweaver-fixture-etcd-client", "clientAuth"),
        ]:
            extension = cert / (name + ".ext")
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=" + usage + "\nsubjectAltName=IP:127.0.0.1\n",
                encoding="utf-8",
            )
            self.run(
                [
                    "openssl",
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    subject,
                    "-keyout",
                    str(cert / (name + ".key")),
                    "-out",
                    str(cert / (name + ".csr")),
                ]
            )
            self.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(cert / (name + ".csr")),
                    "-CA",
                    str(cert / "ca.crt"),
                    "-CAkey",
                    str(cert / "ca.key"),
                    "-CAcreateserial",
                    "-days",
                    "1",
                    "-extfile",
                    str(extension),
                    "-out",
                    str(cert / (name + ".crt")),
                ]
            )
        self.run(["openssl", "genrsa", "-out", str(cert / "sa.key"), "2048"])
        self.run(
            ["openssl", "rsa", "-in", str(cert / "sa.key"), "-pubout", "-out", str(cert / "sa.pub")]
        )
        for path in cert.glob("*.key"):
            path.chmod(0o600)

    def context(self, user):
        context = ssl.create_default_context(cafile=str(self.cert / "ca.crt"))
        context.load_cert_chain(self.cert / (user + ".crt"), self.cert / (user + ".key"))
        return context

    def request(self, path, value=None, *, method="GET", user="admin", apply=False, etcd=False):
        context = self.context("etcd-client" if etcd else user)
        request = urllib.request.Request(
            (self.etcd_url if etcd else self.url) + path,
            data=json.dumps(value).encode() if value is not None else None,
            method=method,
            headers={
                "Content-Type": "application/apply-patch+yaml" if apply else "application/json"
            },
        )
        try:
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def launch(self, name, args):
        handle = (self.output / (name + ".log")).open("wb")
        self.handles.append(handle)
        process = subprocess.Popen(
            args, env=self.env, cwd=self.native, stdout=handle, stderr=subprocess.STDOUT
        )
        self.processes.append(process)
        return process

    def ready(self, process, path, *, etcd=False):
        deadline = time.monotonic() + 60
        while True:
            require(process.poll() is None, "Owned process exited before readiness")
            try:
                status, _ = self.request(path, etcd=etcd)
                if status == 200:
                    return
            except (OSError, urllib.error.URLError):
                pass  # The owned process may not yet be listening; the deadline remains enforced.
            require(time.monotonic() < deadline, "Owned API process readiness timed out")
            time.sleep(0.2)

    def start(self):
        self.certificates()
        ports = [free_port(), free_port(), free_port()]
        require(len(set(ports)) == 3, "Fixture ports collided before startup")
        self.etcd_url, peer, self.url = ["https://127.0.0.1:" + str(p) for p in ports]
        cert = self.cert
        etcd = self.launch(
            "etcd",
            [
                str(self.etcd_binary),
                "--name=fixture",
                "--data-dir=" + str(self.native / "data"),
                "--listen-client-urls=" + self.etcd_url,
                "--advertise-client-urls=" + self.etcd_url,
                "--listen-peer-urls=" + peer,
                "--initial-advertise-peer-urls=" + peer,
                "--initial-cluster=fixture=" + peer,
                "--initial-cluster-token=certweaver-local-fixture",
                "--cert-file=" + str(cert / "server.crt"),
                "--key-file=" + str(cert / "server.key"),
                "--trusted-ca-file=" + str(cert / "ca.crt"),
                "--client-cert-auth=true",
                "--peer-cert-file=" + str(cert / "server.crt"),
                "--peer-key-file=" + str(cert / "server.key"),
                "--peer-trusted-ca-file=" + str(cert / "ca.crt"),
                "--peer-client-cert-auth=true",
            ],
        )
        self.ready(etcd, "/health", etcd=True)
        encryption = self.native / "encryption.json"
        encryption.write_text(
            json.dumps(
                {
                    "apiVersion": "apiserver.config.k8s.io/v1",
                    "kind": "EncryptionConfiguration",
                    "resources": [
                        {
                            "resources": ["secrets"],
                            "providers": [
                                {
                                    "aescbc": {
                                        "keys": [
                                            {
                                                "name": "fixture-key",
                                                "secret": base64.b64encode(os.urandom(32)).decode(),
                                            }
                                        ]
                                    }
                                },
                                {"identity": {}},
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        encryption.chmod(0o600)
        audit = self.native / "audit-policy.json"
        audit.write_text(
            json.dumps(
                {
                    "apiVersion": "audit.k8s.io/v1",
                    "kind": "Policy",
                    "omitStages": ["RequestReceived"],
                    "rules": [{"level": "Metadata"}],
                }
            ),
            encoding="utf-8",
        )
        self.audit_path = self.native / "audit.jsonl"
        server = self.launch(
            "api",
            [
                str(self.api_binary),
                "--bind-address=127.0.0.1",
                "--advertise-address=127.0.0.1",
                "--secure-port=" + str(ports[2]),
                "--cert-dir=" + str(cert),
                "--tls-cert-file=" + str(cert / "server.crt"),
                "--tls-private-key-file=" + str(cert / "server.key"),
                "--client-ca-file=" + str(cert / "ca.crt"),
                "--anonymous-auth=false",
                "--authorization-mode=RBAC",
                "--service-cluster-ip-range=10.43.0.0/24",
                "--service-account-issuer=" + self.url,
                "--service-account-key-file=" + str(cert / "sa.pub"),
                "--service-account-signing-key-file=" + str(cert / "sa.key"),
                "--etcd-servers=" + self.etcd_url,
                "--etcd-cafile=" + str(cert / "ca.crt"),
                "--etcd-certfile=" + str(cert / "etcd-client.crt"),
                "--etcd-keyfile=" + str(cert / "etcd-client.key"),
                "--encryption-provider-config=" + str(encryption),
                "--profiling=false",
                "--audit-policy-file=" + str(audit),
                "--audit-log-path=" + str(self.audit_path),
                "--audit-log-mode=blocking",
            ],
        )
        self.ready(server, "/readyz")

    def kubeconfig(self, user="admin"):
        path = self.native / (user + ".kubeconfig")
        path.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [
                        {
                            "name": "fixture",
                            "cluster": {
                                "server": self.url,
                                "certificate-authority": str(self.cert / "ca.crt"),
                            },
                        }
                    ],
                    "contexts": [
                        {"name": "fixture", "context": {"cluster": "fixture", "user": user}}
                    ],
                    "users": [
                        {
                            "name": user,
                            "user": {
                                "client-certificate": str(self.cert / (user + ".crt")),
                                "client-key": str(self.cert / (user + ".key")),
                            },
                        }
                    ],
                    "current-context": "fixture",
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def audit_events(self, name):
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
            if line
            and json.loads(line).get("objectRef", {}).get("resource") == "secrets"
            and json.loads(line).get("objectRef", {}).get("name") == name
        ]

    def stop(self):
        for process in reversed(self.processes):
            stop_process(process)
        for handle in self.handles:
            handle.close()


def secret(name, value, bucket=True):
    data = {"etcd-s3-secret-key": base64.b64encode(value.encode()).decode()}
    if bucket:
        data["etcd-s3-bucket"] = base64.b64encode(b"synthetic-bucket").decode()
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": "kube-system"},
        "type": "etcd.k3s.cattle.io/s3-config-secret",
        "data": data,
    }


def apply_secret(plane, value, manager="certweaver", dry=False):
    return plane.request(
        "/api/v1/namespaces/kube-system/secrets/"
        + value["metadata"]["name"]
        + "?fieldManager="
        + manager
        + ("&dryRun=All" if dry else ""),
        value,
        method="PATCH",
        apply=True,
    )


def verify(root, output, native, api_archive=None, etcd_archive=None, supplied=None):
    records = guard(root)
    installer = runpy.run_path(str(root / "scripts/install-ci-tool.py"))
    binaries = {
        name: installer["install_tool"](name, root, archive=archive)
        for name, archive in [("kube-apiserver", api_archive), ("etcd", etcd_archive)]
    }
    native.mkdir(mode=0o700)
    model = runpy.run_path(str(root / "scripts/check-snapshot-reconcile.py"))
    snapshot = runpy.run_path(str(root / "scripts/check-snapshot-config.py"))
    snapshot["guard"](root)
    health = runpy.run_path(str(root / "scripts/check-cluster-health.py"))
    health["acquire_client"](root, native / "kubectl", supplied)
    identities = {
        name: subprocess.run(
            [str(binary), "--version"], capture_output=True, check=True, timeout=30
        ).stdout.decode()
        for name, binary in binaries.items()
    }
    require(
        identities["kube-apiserver"].strip() == "Kubernetes " + records["kube-apiserver"]["version"]
        and "etcd Version: " + records["etcd"]["version"][1:] in identities["etcd"],
        "Control-plane executable identities do not match their locks",
    )
    plane = ControlPlane(native, output, binaries["kube-apiserver"], binaries["etcd"])
    observations = []
    canaries = [
        "synthetic-real-api-first-" + os.urandom(12).hex(),
        "synthetic-real-api-second-" + os.urandom(12).hex(),
    ]
    try:
        plane.start()
        env = model["environment"](root, native)
        config = plane.kubeconfig()
        block = snapshot["snapshot_block"](root)
        directory = native / "cases"
        directory.mkdir(mode=0o700)
        source = directory / "source.env"
        for case in [
            "create",
            "repeat",
            "rotation",
            "owned-field-removal",
            "foreign-metadata",
            "owned-manager-drift",
            "ownership-conflict",
            "immutable",
            "rbac-denied",
            "check-mode",
        ]:
            value = canaries[0] if case in {"create", "repeat"} else canaries[1]
            bucket = case in {"create", "repeat", "rotation"}
            payload = (
                "etcd-s3-secret-key="
                + value
                + "\n"
                + ("etcd-s3-bucket=synthetic-bucket\n" if bucket else "")
            )
            source.write_text(payload, encoding="utf-8")
            source.chmod(0o600)
            target = case if case in {"ownership-conflict", "immutable", "rbac-denied"} else "probe"
            if case == "foreign-metadata":
                metadata = {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": target,
                        "namespace": "kube-system",
                        "labels": {"other-owner": "preserved"},
                    },
                    "type": "etcd.k3s.cattle.io/s3-config-secret",
                }
                require(
                    apply_secret(plane, metadata, "foreign-metadata")[0] == 200,
                    "Could not establish independent metadata ownership",
                )
            elif case == "owned-manager-drift":
                require(
                    apply_secret(plane, secret(target, "synthetic-owned-drift", False))[0] == 200,
                    "Could not establish same-manager drift",
                )
            elif case == "ownership-conflict":
                require(
                    apply_secret(
                        plane, secret(target, "synthetic-other-owner", False), "foreign-owner"
                    )[0]
                    == 201,
                    "Could not establish foreign ownership",
                )
            elif case == "immutable":
                immutable = secret(target, "synthetic-immutable", False)
                immutable["immutable"] = True
                require(
                    apply_secret(plane, immutable)[0] == 201, "Could not establish immutable Secret"
                )
            before_code, before = plane.request("/api/v1/namespaces/kube-system/secrets/" + target)
            before = json.loads(before) if before_code == 200 else None
            chosen = plane.kubeconfig("denied") if case == "rbac-denied" else config
            play = model["make_play"](root, directory, None, chosen, source, target, block)
            start = len(plane.audit_events(target))
            code, changed, log = model["execute"](
                play, env, output, case, check=case == "check-mode"
            )
            failures = case in {"ownership-conflict", "immutable", "rbac-denied"}
            changes = case in {"create", "rotation", "owned-field-removal", "owned-manager-drift"}
            require(
                code == (2 if failures else 0) and changed == int(changes),
                "Unexpected real API reconciliation outcome: " + case,
            )
            events = plane.audit_events(target)[start:]
            mutations = [
                e
                for e in events
                if e.get("verb") in {"create", "patch", "update", "delete"}
                and "dryRun=All" not in e.get("requestURI", "")
            ]
            if failures:
                expected_status = {"ownership-conflict": 409, "immutable": 422, "rbac-denied": 403}[
                    case
                ]
                require(
                    any(e.get("responseStatus", {}).get("code") == expected_status for e in events),
                    "Wrong API failure reason: " + case,
                )
            require(len(mutations) == int(changes), "Unexpected persistent API request: " + case)
            after_code, after = plane.request("/api/v1/namespaces/kube-system/secrets/" + target)
            after = json.loads(after) if after_code == 200 else None
            if changes:
                require(
                    after["data"] == secret(target, value, bucket)["data"],
                    "Real API stored unexpected Secret data",
                )
            elif before is not None:
                require(after == before, "Unchanged/rejected reconciliation mutated the object")
            else:
                require(after is None, "Rejected reconciliation created an object")
            if case == "foreign-metadata":
                require(
                    after["metadata"]["labels"]["other-owner"] == "preserved",
                    "Foreign metadata was not preserved",
                )
            require(not list(directory.glob("certweaver-etcd-s3-*")), "Real API staging survived")
            require(
                all(
                    c.encode() not in log and base64.b64encode(c.encode()) not in log
                    for c in canaries
                ),
                "Secret canary appeared in Ansible diagnostics",
            )
            observations.append(
                {
                    "case": case,
                    "exitCode": code,
                    "changed": changed,
                    "persistentApiRequests": len(mutations),
                    "expectedResultVerified": True,
                    "privateCanaryAbsentFromOutput": True,
                    "stagingRemoved": True,
                }
            )
        # A real admission policy rejects even the comparison's dry-run write.
        policy = {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "fixture-secret-denial"},
            "spec": {
                "failurePolicy": "Fail",
                "matchConstraints": {
                    "resourceRules": [
                        {
                            "apiGroups": [""],
                            "apiVersions": ["v1"],
                            "operations": ["CREATE", "UPDATE"],
                            "resources": ["secrets"],
                        }
                    ]
                },
                "validations": [
                    {
                        "expression": "object.metadata.name != 'admission-rejected'",
                        "message": "Synthetic denial",
                    }
                ],
            },
        }
        require(
            plane.request(
                "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies",
                policy,
                method="POST",
            )[0]
            == 201,
            "Admission policy creation failed",
        )
        binding = {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "fixture-secret-denial"},
            "spec": {"policyName": "fixture-secret-denial", "validationActions": ["Deny"]},
        }
        require(
            plane.request(
                "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings",
                binding,
                method="POST",
            )[0]
            == 201,
            "Admission binding creation failed",
        )
        deadline = time.monotonic() + 30
        while True:
            status, body = apply_secret(
                plane, secret("admission-rejected", canaries[1], False), dry=True
            )
            if status == 422 and b"fixture-secret-denial" in body and b"Synthetic denial" in body:
                break
            require(
                status in {200, 201} and time.monotonic() < deadline,
                "Real admission enforcement did not become ready",
            )
            time.sleep(0.1)
        source.write_text("etcd-s3-secret-key=" + canaries[1] + "\n", encoding="utf-8")
        play = model["make_play"](
            root, directory, None, config, source, "admission-rejected", block
        )
        start = len(plane.audit_events("admission-rejected"))
        code, changed, log = model["execute"](play, env, output, "admission-denied")
        events = plane.audit_events("admission-rejected")[start:]
        require(
            code == 2
            and changed == 0
            and all(
                "dryRun=All" in e["requestURI"]
                for e in events
                if e.get("verb") in {"create", "patch", "update"}
            ),
            "Admission rejection did not stop persistent apply",
        )
        require(
            plane.request("/api/v1/namespaces/kube-system/secrets/admission-rejected")[0] == 404,
            "Rejected Secret was persisted",
        )
        observations.append(
            {
                "case": "admission-denied",
                "exitCode": code,
                "changed": changed,
                "expectedResultVerified": True,
            }
        )
        status, body = plane.request(
            "/v3/kv/range",
            {"key": base64.b64encode(b"/registry/secrets/kube-system/probe").decode()},
            method="POST",
            etcd=True,
        )
        require(status == 200, "Could not inspect owned encrypted fixture storage")
        raw = base64.b64decode(json.loads(body)["kvs"][0]["value"])
        require(
            status == 200
            and raw.startswith(b"k8s:enc:aescbc:v1:fixture-key:")
            and all(c.encode() not in raw for c in canaries),
            "Fixture Secret storage is not encrypted",
        )
        observations.append(
            {
                "case": "encrypted-storage",
                "envelopePrefixVerified": True,
                "plaintextCanaryAbsent": True,
                "expectedResultVerified": True,
            }
        )
    finally:
        plane.stop()
        terminal = all(p.poll() is not None for p in plane.processes)
        for path in output.glob("*.log"):
            log = path.read_bytes()
            require(
                all(
                    c.encode() not in log and base64.b64encode(c.encode()) not in log
                    for c in canaries
                ),
                "Fixture diagnostics disclosed a Secret canary",
            )
        if plane.audit_path.exists():
            audit = plane.audit_path.read_bytes()
            require(
                all(
                    c.encode() not in audit and base64.b64encode(c.encode()) not in audit
                    for c in canaries
                ),
                "Metadata audit disclosed a Secret canary",
            )
            require(
                all(
                    "requestObject" not in json.loads(line)
                    and "responseObject" not in json.loads(line)
                    for line in audit.splitlines()
                    if line
                ),
                "Audit included request/response payloads",
            )
            (output / "metadata-audit.jsonl").write_bytes(audit)
        (output / "cleanup.json").write_text(
            json.dumps({"allOwnedProcessesTerminal": terminal}) + "\n"
        )
    require(terminal, "API process cleanup incomplete")
    observations.append(
        {
            "case": "process-cleanup",
            "allOwnedProcessesTerminal": True,
            "expectedResultVerified": True,
        }
    )
    receipts = {
        n: json.loads((root / ".certweaver/tools" / (n + ".receipt.json")).read_text())
        for n in binaries
    }
    report = {
        "scope": "Actual source Ansible block, real pinned kubectl and upstream Kubernetes API "
        "server/etcd, mutually authenticated loopback TLS, RBAC, SSA/admission "
        "and fixture encryption. Synthetic CA, clients, keys/data; "
        "no workers/controllers, RKE2/K3s runtime, remote privilege, "
        "object storage/restore, production key custody or independent acceptance.",
        "identities": identities,
        "toolReceipts": receipts,
        "metadataAuditSha256": hashlib.sha256(
            (output / "metadata-audit.jsonl").read_bytes()
        ).hexdigest(),
        "observations": observations,
    }
    (output / "snapshot-api-result.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--kube-apiserver-archive", type=Path)
    parser.add_argument("--etcd-archive", type=Path)
    parser.add_argument("--kubectl", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux root for owned Ansible credential fixtures")
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-snapshot-api-") as temporary:
        result = verify(
            root,
            output,
            Path(temporary) / "cases",
            args.kube_apiserver_archive,
            args.etcd_archive,
            args.kubectl,
        )
    print("Verified " + str(len(result["observations"])) + " real API snapshot cases")
