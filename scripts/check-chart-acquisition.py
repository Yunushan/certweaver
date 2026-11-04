"""Exercise actual Helm and Ansible chart verification without a Kubernetes cluster."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import io
import json
import os
import runpy
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def chart(name="fixture", version="1.2.3", message="immutable-chart-fixture"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for filename, text in {
            "Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: {version}\ntype: application\n",
            "values.yaml": "message: " + message + "\n",
            "templates/configmap.yaml": (
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
                "data:\n  message: {{ .Values.message | quote }}\n"
            ),
        }.items():
            member = tarfile.TarInfo(name + "/" + filename)
            data = text.encode()
            member.size, member.mode = len(data), 0o644
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def verify(root, output, native, helm):
    installer = runpy.run_path(str(root / "scripts/install-ci-tool.py"))
    record = installer["tool_record"](root, "helm")
    require(not helm.is_symlink() and helm.is_file(), "Helm must be a regular pinned executable")
    require(
        installer["digest"](helm) == record["executableSha256"], "Helm executable digest differs"
    )
    ca, key, certificate = native / "ca.crt", native / "server.key", native / "server.crt"
    extensions = native / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    commands = [
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
            "/CN=Synthetic chart CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(native / "ca.key"),
            "-out",
            str(ca),
        ],
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Synthetic chart server",
            "-keyout",
            str(key),
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
            str(ca),
            "-CAkey",
            str(native / "ca.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        ],
    ]
    for command in commands:
        require(
            subprocess.run(command, capture_output=True, timeout=30).returncode == 0,
            "Fixture certificate creation failed",
        )
    original = chart()
    original_digest = hashlib.sha256(original).hexdigest()

    class Handler(http.server.BaseHTTPRequestHandler):
        def payload(self):
            server = self.server
            payload = server.payload
            digest = hashlib.sha256(payload).hexdigest()
            config = b'{"name":"fixture","version":"1.2.3"}'
            config_digest = hashlib.sha256(config).hexdigest()
            manifest = json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.cncf.helm.config.v1+json",
                        "digest": "sha256:" + config_digest,
                        "size": len(config),
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                            "digest": "sha256:" + digest,
                            "size": len(payload),
                        }
                    ],
                }
            ).encode()
            path = self.path.split("?", 1)[0]
            if path == "/v2/":
                return b"{}", "application/json", 200
            if (
                path == "/v2/charts/fixture/manifests/1.2.3"
                or path
                == "/v2/charts/fixture/manifests/sha256:" + hashlib.sha256(manifest).hexdigest()
            ):
                return manifest, "application/vnd.oci.image.manifest.v1+json", 200
            if path == "/v2/charts/fixture/blobs/sha256:" + config_digest:
                return config, "application/vnd.cncf.helm.config.v1+json", 200
            if path in {"/repo/fixture-1.2.3.tgz", "/v2/charts/fixture/blobs/sha256:" + digest}:
                return payload, "application/octet-stream", 200
            if path == "/repo/index.yaml":
                index = {
                    "apiVersion": "v1",
                    "entries": {
                        "fixture": [
                            {
                                "apiVersion": "v2",
                                "name": "fixture",
                                "version": "1.2.3",
                                "urls": [
                                    f"https://127.0.0.1:{server.server_address[1]}/repo/fixture-1.2.3.tgz"
                                ],
                                "digest": digest,
                            }
                        ]
                    },
                }
                return yaml.safe_dump(index).encode(), "application/yaml", 200
            return b"not found", "text/plain", 404

        def respond(self, head=False):
            self.server.requests += 1
            content, kind, status = self.payload()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(content)))
            self.send_header(
                "Docker-Content-Digest", "sha256:" + hashlib.sha256(content).hexdigest()
            )
            self.end_headers()
            if not head:
                self.wfile.write(content)

        def do_GET(self):
            self.respond()

        def do_HEAD(self):
            self.respond(True)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.payload, server.requests = original, 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    observations = []
    shared = native / "shared-cache"
    (native / "consumer-helm/plugins").mkdir(parents=True)

    def run(
        case,
        *,
        route="https",
        checksum=None,
        version="1.2.3",
        expected=True,
        cache=None,
        trusted=True,
        check=False,
        repository_scheme="https",
    ):
        cache = cache or native / (case + "-cache")
        target = native / (case + "-consumer")
        uri = f"127.0.0.1:{server.server_address[1]}"
        values = {
            "ansible_python_interpreter": sys.executable,
            "certweaver_chart_cache_root": str(cache),
            "certweaver_chart_helm_executable": str(helm),
            "certweaver_chart_key": "fixture",
            "certweaver_chart_name": "fixture",
            "certweaver_chart_version": version,
            "certweaver_chart_checksum": "sha256:" + original_digest
            if checksum is None
            else checksum,
            "certweaver_chart_reference": "oci://" + uri + "/charts/fixture"
            if route == "oci"
            else "fixture",
            "certweaver_chart_repository": ""
            if route == "oci"
            else repository_scheme + "://" + uri + "/repo",
        }
        playbook = native / (case + ".yml")
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Synthetic chart verification and local rendering only",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "become": False,
                        "vars": values,
                        "environment": {
                            "HELM_CONFIG_HOME": str(native / "consumer-helm/config"),
                            "HELM_CACHE_HOME": str(native / "consumer-helm/cache"),
                            "HELM_DATA_HOME": str(native / "consumer-helm/data"),
                            "HELM_PLUGINS": str(native / "consumer-helm/plugins"),
                            "DOCKER_CONFIG": str(native / "consumer-helm/docker"),
                            "SSL_CERT_FILE": str(ca)
                            if trusted
                            else "/etc/ssl/certs/ca-certificates.crt",
                            "KUBECONFIG": "/dev/null",
                            "HELM_KUBEAPISERVER": "https://127.0.0.1:1",
                        },
                        "tasks": [
                            {
                                "name": "Acquire actual verified chart role",
                                "ansible.builtin.include_role": {"name": "verified_chart"},
                            },
                            {
                                "name": "Render only the verified local chart without a cluster",
                                "ansible.builtin.command": {
                                    "argv": [
                                        str(helm),
                                        "template",
                                        "fixture",
                                        "{{ certweaver_chart_archive_path }}",
                                    ]
                                },
                                "changed_when": False,
                                "register": "fixture_render",
                                "when": "not ansible_check_mode and certweaver_chart_verified",
                            },
                            {
                                "name": "Record local rendering only after acquisition succeeds",
                                "ansible.builtin.copy": {
                                    "content": "{{ fixture_render.stdout }}",
                                    "dest": str(target),
                                    "mode": "0600",
                                },
                                "when": "not ansible_check_mode and certweaver_chart_verified",
                            },
                        ],
                    }
                ]
            )
        )
        before = server.requests
        args = [
            str(Path(sys.executable).parent / "ansible-playbook"),
            "-i",
            "localhost,",
            str(playbook),
        ]
        if check:
            args.append("--check")
        result = subprocess.run(args, cwd=root, capture_output=True, timeout=180, check=False)
        log = result.stdout + b"\n" + result.stderr
        (output / (case + ".log")).write_bytes(log)
        require(
            (result.returncode == 0) == expected,
            case + ": unexpected Ansible result; inspect local log",
        )
        if expected and not check:
            require(
                "immutable-chart-fixture" in target.read_text(),
                case + ": verified chart was not rendered",
            )
        else:
            require(not target.exists(), case + ": unverified chart reached the consumer")
        observations.append(
            {
                "case": case,
                "route": route,
                "exitCode": result.returncode,
                "httpsRequests": server.requests - before,
                "renderedConsumer": target.exists(),
                "expectedResultVerified": True,
            }
        )
        return log

    try:
        run("https-valid", cache=shared)
        run("https-cache-hit", cache=shared)
        require(observations[-1]["httpsRequests"] == 0, "Verified chart cache contacted upstream")
        run("oci-valid", route="oci")
        for case in ["missing-checksum", "version-range", "insecure-source"]:
            kwargs = (
                {"checksum": ""}
                if case == "missing-checksum"
                else {"version": ">=1.0.0"}
                if case == "version-range"
                else {"repository_scheme": "http"}
            )
            run(case, expected=False, **kwargs)
            require(
                observations[-1]["httpsRequests"] == 0, case + ": invalid inputs reached transport"
            )
        server.payload = chart(message="changed remote fixture")
        log = run("changed-remote", expected=False)
        require(
            b"Downloaded chart checksum differs" in log,
            "Changed remote content did not fail its digest check",
        )
        for case, payload in [
            ("wrong-name", chart(name="other")),
            ("wrong-version", chart(version="2.0.0")),
        ]:
            server.payload = payload
            log = run(
                case, checksum="sha256:" + hashlib.sha256(payload).hexdigest(), expected=False
            )
            require(
                b"does not match the requested chart name and version" in log,
                case + ": expected metadata rejection missing",
            )
        server.payload = original
        cached = shared / "fixture" / original_digest / "chart.tgz"
        cached.write_bytes(b"changed cached bytes")
        run("cache-repair", cache=shared)
        require(
            hashlib.sha256(cached.read_bytes()).hexdigest() == original_digest,
            "Cached chart was not repaired",
        )
        run("cached-version-mismatch", cache=shared, version="1.2.4", expected=False)
        require(
            observations[-1]["httpsRequests"] == 0, "Cached version mismatch contacted upstream"
        )
        for route in ["https", "oci"]:
            log = run("untrusted-ca-" + route, route=route, trusted=False, expected=False)
            require(
                b"certificate" in log.lower() and observations[-1]["httpsRequests"] == 0,
                "Untrusted chart CA was not rejected before HTTP",
            )
        bad_cache = native / "symlink-cache"
        shutil.copytree(shared, bad_cache)
        bad_file = bad_cache / "fixture" / original_digest / "chart.tgz"
        bad_file.unlink()
        bad_file.symlink_to(cached)
        run("substituted-cache", cache=bad_cache, expected=False)
        require(observations[-1]["httpsRequests"] == 0, "Substituted cache reached upstream")
        check_cache = native / "check-cache"
        run("check-mode", cache=check_cache, check=True)
        require(
            not check_cache.exists() and observations[-1]["httpsRequests"] == 0,
            "Check mode acquired a chart",
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)
    result = {
        "scope": (
            "Real pinned Helm and actual Ansible chart role against temporary HTTPS/OCI fixtures; "
            "local rendering only, no Kubernetes cluster, release installation "
            "or upstream trust approval"
        ),
        "helmVersion": record["version"],
        "helmExecutableSha256": record["executableSha256"],
        "observations": observations,
    }
    (output / "chart-acquisition-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error(
            "Use isolated Linux with root permissions for private chart ownership fixtures"
        )
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(root):
        parser.error("Output must be a fresh directory inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-chart-fixture-") as temporary:
        result = verify(root, output, Path(temporary), args.helm.absolute())
    print(f"Verified {len(result['observations'])} real-Helm chart acquisition/rendering cases")
