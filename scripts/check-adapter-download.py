"""Verify checksum-gated adapter downloads with temporary localhost HTTPS fixtures."""

import hashlib
import http.server
import io
import json
import os
import ssl
import stat
import subprocess
import tarfile
import threading
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(python, repo, native, out, env):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        member = tarfile.TarInfo("fixture-binary")
        member.size = 16
        member.mode = 0o755
        bundle.addfile(member, io.BytesIO(b"fixture-content\n"))
    good = archive.getvalue()
    checksum = "sha256:" + hashlib.sha256(good).hexdigest()
    certificate = native / "fixture.crt"
    key = native / "fixture.key"
    ca = native / "ca.crt"
    ca_key = native / "ca.key"
    request = native / "fixture.csr"
    extensions = native / "fixture.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n"
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
            "/CN=CertWeaver synthetic fixture CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(ca_key),
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
            "/CN=CertWeaver synthetic HTTPS fixture",
            "-keyout",
            str(key),
            "-out",
            str(request),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca),
            "-CAkey",
            str(ca_key),
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
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("Synthetic TLS fixture certificate creation failed")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.requests += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.server.payload)))
            self.end_headers()
            self.wfile.write(self.server.payload)

        def do_HEAD(self):
            self.server.requests += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.server.payload)))
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.requests = 0
    server.payload = good
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    import yaml

    observations = []
    try:
        for case in [
            "valid",
            "cache-hit",
            "cache-repair",
            "tampered",
            "missing-pin",
            "unsupported-architecture",
            "invalid-url",
            "check-mode",
            "architecture-pin",
        ]:
            directory = native / ("case-" + case)
            directory.mkdir()
            cache = directory / "cache"
            if case in ["cache-hit", "cache-repair"]:
                cache = native / "case-valid/cache"
            target = directory / "installed"
            target.mkdir()
            marker = target / "fixture-binary"
            if case == "cache-repair":
                payload = cache / "fixture-amd64" / checksum[7:] / "payload"
                payload.write_bytes(b"tampered cached bytes")
            values = {"fixture": checksum} if case != "missing-pin" else {}
            if case == "architecture-pin":
                values = {"fixture_amd64": checksum, "fixture": "sha256:" + "0" * 64}
            variables = {
                "ansible_python_interpreter": python,
                "certweaver_adapter_checksums": values,
                "certweaver_adapter_arch": "ppc64"
                if case == "unsupported-architecture"
                else "amd64",
                "certweaver_download_name": "fixture",
                "certweaver_download_url": ("http" if case == "invalid-url" else "https")
                + "://127.0.0.1:"
                + str(server.server_address[1])
                + "/fixture.tar.gz",
                "certweaver_adapter_cache_root": str(cache),
                "certweaver_required_version": "1.2.3",
                "certweaver_required_adapter": "fixture",
                "certweaver_require_binary_version": True,
            }
            tasks = [
                {
                    "name": "Validate release version",
                    "ansible.builtin.include_tasks": str(
                        repo / "roles/pki_adapter/tasks/_require_version.yml"
                    ),
                },
                {
                    "name": "Acquire exact-source helper",
                    "ansible.builtin.include_tasks": str(
                        repo / "roles/pki_adapter/tasks/_download_verified.yml"
                    ),
                },
                {
                    "name": "Extract approved fixture after verification",
                    "ansible.builtin.unarchive": {
                        "src": "{{ certweaver_adapter_payload_path }}",
                        "dest": str(target),
                        "remote_src": True,
                        "include": ["fixture-binary"],
                    },
                    "when": "not ansible_check_mode",
                },
            ]
            playbook = directory / "probe.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Synthetic checksum gate probe",
                            "hosts": "localhost",
                            "connection": "local",
                            "gather_facts": False,
                            "become": False,
                            "vars": variables,
                            "environment": {"SSL_CERT_FILE": str(ca)},
                            "tasks": tasks,
                        }
                    ]
                )
            )
            server.payload = b"deliberately changed transport bytes" if case == "tampered" else good
            before = server.requests
            command = [
                str(Path(python).parent / "ansible-playbook"),
                "-i",
                "localhost,",
                str(playbook),
            ]
            if case == "check-mode":
                command.append("--check")
            result = subprocess.run(command, cwd=repo, env=env, capture_output=True, timeout=120)
            log = result.stdout + b"\n" + result.stderr
            (out / ("https-" + case + ".log")).write_bytes(log)
            success = case in [
                "valid",
                "cache-hit",
                "cache-repair",
                "check-mode",
                "architecture-pin",
            ]
            require(
                (result.returncode == 0) == success,
                f"{case}: unexpected Ansible exit {result.returncode}; inspect its private log",
            )
            if case == "tampered":
                require(b"did not match" in log, "Tampered payload did not fail its checksum check")
            if case in [
                "missing-pin",
                "unsupported-architecture",
                "invalid-url",
                "check-mode",
                "cache-hit",
            ]:
                require(server.requests == before, f"{case}: unexpected transport request")
            if case == "check-mode":
                require(
                    not cache.exists() and not marker.exists(), "Check mode changed fixture files"
                )
            elif success:
                require(
                    marker.read_bytes() == b"fixture-content\n",
                    f"{case}: incorrect installed bytes",
                )
                payload = cache / "fixture-amd64" / checksum[7:] / "payload"
                require(
                    hashlib.sha256(payload.read_bytes()).hexdigest() == checksum[7:],
                    f"{case}: cached payload digest differs",
                )
                require(
                    stat.S_IMODE(payload.stat().st_mode) == 0o600, f"{case}: cache mode differs"
                )
                require(payload.stat().st_uid == 0, f"{case}: cache is not root owned")
            else:
                require(not marker.exists(), f"{case}: rejected bytes reached extraction")
            observations.append(
                {
                    "case": case,
                    "exitCode": result.returncode,
                    "httpsRequests": server.requests - before,
                    "installedFixture": marker.exists(),
                    "expectedResultVerified": True,
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
    record = {
        "scope": (
            "Local temporary synthetic HTTPS transport and exact Ansible helper/module behavior; "
            "no production deployment, upstream approval or Windows runtime qualification"
        ),
        "tlsValidationEnabled": True,
        "observations": observations,
    }
    (out / "https-acquisition-result.json").write_text(json.dumps(record, indent=2))
    print("All HTTPS acquisition cases verified", flush=True)


if __name__ == "__main__":
    import argparse
    import sys
    import tempfile

    parser = argparse.ArgumentParser(
        description="Synthetic HTTPS/Ansible checksum verification; no production approval"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error(
            "Use isolated Linux with root permissions for the private root-owned fixture cache"
        )
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if not output.resolve().is_relative_to(root) or output.exists() or output.is_symlink():
        parser.error("The output directory must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-adapter-https-") as temporary:
        verify(sys.executable, root, Path(temporary), output, os.environ.copy())
