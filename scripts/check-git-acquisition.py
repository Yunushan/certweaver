"""Qualify immutable Git checkout and acme.sh reconciliation with localhost fixtures."""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(root, output, native):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_AUTHOR_NAME="CertWeaver synthetic Git fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="CertWeaver synthetic Git fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )

    def command(argv, cwd=native):
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, timeout=60)
        require(result.returncode == 0, "Synthetic Git/TLS fixture creation failed")
        return result.stdout

    ca, key, certificate = native / "ca.crt", native / "server.key", native / "server.crt"
    extensions = native / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    command(
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
            "/CN=Synthetic Git fixture CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(native / "ca.key"),
            "-out",
            str(ca),
        ]
    )
    command(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Synthetic Git fixture",
            "-keyout",
            str(key),
            "-out",
            str(native / "server.csr"),
        ]
    )
    command(
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
        ]
    )
    served = native / "upstream"
    served.mkdir()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.server.requests += 1
            super().do_GET()

        def do_HEAD(self):
            self.server.requests += 1
            super().do_HEAD()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(Handler, directory=str(served))
    )
    server.requests = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    repository = f"https://127.0.0.1:{server.server_address[1]}/fixture.git"
    wrong_repository = f"https://127.0.0.1:{server.server_address[1]}/wrong.git"
    work = native / "work"
    work.mkdir()
    git = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false"]
    command([*git, "init", "-b", "fixture"], work)
    installer = work / "acme.sh"
    installer.write_text("""#!/bin/sh
# Synthetic fixture version one. Never an upstream installer.
set -eu
home= config= cert= automatic=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --install) ;;
    --home) home="$2"; shift ;;
    --config-home) config="$2"; shift ;;
    --cert-home) cert="$2"; shift ;;
    --accountemail) shift ;;
    --auto-upgrade) automatic="$2"; shift ;;
    *) exit 31 ;;
  esac
  shift
done
[ "$automatic" = 0 ] || exit 32
for directory in "$home" "$config" "$cert"; do
  case "$directory" in "$CERTWEAVER_SYNTHETIC_ROOT"/*) ;; *) exit 33 ;; esac
done
mkdir -p "$home" "$config" "$cert"
cp "$0" "$home/acme.sh"
chmod 700 "$home/acme.sh"
printf "AUTO_UPGRADE='1'\\n" > "$config/account.conf"
printf 'installed\\n' >> "$home/fixture-installs.count"
""")
    installer.chmod(0o700)
    (work / ".gitignore").write_text("*.ignored\n")
    (work / "nested").mkdir()
    (work / "nested/data").write_text("approved fixture bytes\n")
    (work / "script-link").symlink_to("acme.sh")

    def commit(message):
        command([*git, "add", "--all"], work)
        command([*git, "commit", "-m", message], work)
        return command([*git, "rev-parse", "HEAD"], work).decode().strip()

    first = commit("Synthetic fixture revision one")
    installer.write_text(installer.read_text().replace("version one", "version two"))
    second = commit("Synthetic fixture revision two")
    outside = native / "outside"
    outside.write_text("synthetic outside source tree\n")
    (work / "outside-link").symlink_to(outside)
    escape = commit("Synthetic unsupported external symlink")
    (work / "outside-link").unlink()
    (work / ".gitmodules").write_text(
        '[submodule "module"]\n path = module\n url = ' + wrong_repository + "\n"
    )
    command([*git, "add", "--all"], work)
    command([*git, "update-index", "--add", "--cacheinfo", "160000," + first + ",module"], work)
    command([*git, "commit", "-m", "Synthetic unqualified submodule"], work)
    submodule = command([*git, "rev-parse", "HEAD"], work).decode().strip()
    command([*git, "clone", "--bare", "--no-hardlinks", str(work), str(served / "fixture.git")])
    command([*git, "--git-dir=" + str(served / "fixture.git"), "update-server-info"])
    other = native / "other"
    other.mkdir()
    command([*git, "init", "-b", "other"], other)
    (other / "different").write_text("wrong repository fixture\n")
    command([*git, "add", "--all"], other)
    command([*git, "commit", "-m", "Different synthetic repository"], other)
    command([*git, "clone", "--bare", "--no-hardlinks", str(other), str(served / "wrong.git")])
    command([*git, "--git-dir=" + str(served / "wrong.git"), "update-server-info"])
    observations = []
    shared_cache, shared_home = native / "cache", native / "installation"

    def run(
        case,
        reference,
        *,
        cache=shared_cache,
        home=shared_home,
        url=repository,
        check=False,
        trusted=True,
        expected=True,
    ):
        home_root = home.parent / (home.name + "-state")
        playbook = native / (case + ".yml")
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Synthetic immutable source and installation probe",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "become": False,
                        "vars": {
                            "ansible_python_interpreter": sys.executable,
                            "certweaver_adapter_cache_root": str(cache),
                            "certweaver_adapter_versions": {"acme_sh_ref": reference},
                            "certweaver_adapter_options": {},
                            "certweaver_git_name": "fixture",
                            "certweaver_git_repository": url,
                            "certweaver_git_commit": reference,
                            "certweaver_acme_sh_home": str(home),
                            "certweaver_acme_sh_config_home": str(home_root / "config"),
                            "certweaver_acme_sh_cert_home": str(home_root / "certificates"),
                        },
                        "environment": {
                            "GIT_SSL_NO_VERIFY": "1",
                            "GIT_SSL_CAINFO": str(ca)
                            if trusted
                            else "/etc/ssl/certs/ca-certificates.crt",
                            "CERTWEAVER_SYNTHETIC_ROOT": str(native),
                        },
                        "tasks": [
                            {
                                "name": "Use actual checkout helper",
                                "ansible.builtin.include_role": {
                                    "name": "pki_adapter",
                                    "tasks_from": "_checkout_verified_git",
                                },
                            },
                            {
                                "name": "Use actual acme.sh reconciliation helper",
                                "ansible.builtin.include_role": {
                                    "name": "pki_adapter",
                                    "tasks_from": "_install_acme_sh",
                                },
                            },
                        ],
                    }
                ]
            )
        )
        before = server.requests
        argv = [
            str(Path(sys.executable).parent / "ansible-playbook"),
            "-i",
            "localhost,",
            str(playbook),
        ]
        if check:
            argv.append("--check")
        result = subprocess.run(argv, cwd=root, capture_output=True, timeout=180, check=False)
        (output / (case + ".log")).write_bytes(result.stdout + b"\n" + result.stderr)
        require(
            (result.returncode == 0) == expected,
            case + ": unexpected Ansible exit; inspect local log",
        )
        marker = home / ".certweaver-source.sha256"
        if expected and not check:
            require(
                marker.read_text().startswith(reference + ":"),
                case + ": wrong installed commit marker",
            )
            require(
                "AUTO_UPGRADE='0'" in (home_root / "config/account.conf").read_text(),
                case + ": automatic upgrade remains enabled",
            )
        elif not expected:
            require(
                not marker.exists() and not (home / "acme.sh").exists(),
                case + ": rejected source was installed",
            )
        observations.append(
            {
                "case": case,
                "exitCode": result.returncode,
                "httpsRequests": server.requests - before,
                "installedMarker": marker.exists(),
                "expectedResultVerified": True,
            }
        )
        return result

    try:
        for case, reference, count in [
            ("initial", first, 1),
            ("repeat", first, 1),
            ("upgrade", second, 2),
            ("repeat-upgraded", second, 2),
            ("rollback", first, 3),
        ]:
            run(case, reference)
            require(
                len((shared_home / "fixture-installs.count").read_text().splitlines()) == count,
                case + ": installation count differs",
            )
            if case.startswith("repeat") or case == "rollback":
                require(
                    observations[-1]["httpsRequests"] == 0,
                    case + ": verified cache unexpectedly contacted upstream",
                )
        (shared_home / "acme.sh").write_text("synthetic installed drift\n")
        run("installed-drift-repair", first)
        require(
            len((shared_home / "fixture-installs.count").read_text().splitlines()) == 4,
            "Installed drift was not repaired",
        )
        (shared_home / "acme.sh").unlink()
        run("missing-installed-repair", first)
        require(
            len((shared_home / "fixture-installs.count").read_text().splitlines()) == 5,
            "Missing installed executable was not repaired",
        )
        for case, reference in [
            ("missing-pin", ""),
            ("mutable-tag", "fixture"),
            ("abbreviated-pin", first[:12]),
            ("nonexistent-pin", "f" * 40),
            ("external-symlink", escape),
            ("unqualified-submodule", submodule),
        ]:
            run(
                case,
                reference,
                cache=native / (case + "-cache"),
                home=native / (case + "-home"),
                expected=False,
            )
            if case in {"missing-pin", "mutable-tag", "abbreviated-pin"}:
                require(
                    observations[-1]["httpsRequests"] == 0,
                    case + ": invalid reference reached transport",
                )
        run(
            "wrong-repository",
            first,
            cache=native / "wrong-cache",
            home=native / "wrong-home",
            url=wrong_repository,
            expected=False,
        )
        tls_result = run(
            "untrusted-ca",
            first,
            cache=native / "tls-cache",
            home=native / "tls-home",
            trusted=False,
            expected=False,
        )
        require(
            b"certificate" in (tls_result.stdout + tls_result.stderr).lower()
            and observations[-1]["httpsRequests"] == 0,
            "Untrusted CA was not rejected during TLS certificate verification",
        )
        for case in ["cached-bytes", "ignored-file", "cached-origin"]:
            cache = native / (case + "-cache")
            shutil.copytree(shared_cache, cache, symlinks=True)
            source = cache / "git/fixture" / first
            if case == "cached-bytes":
                script = source / "acme.sh"
                before = script.stat()
                command([*git, "update-index", "--assume-unchanged", "acme.sh"], source)
                script.write_bytes(b"@" + script.read_bytes()[1:])
                os.utime(script, ns=(before.st_atime_ns, before.st_mtime_ns))
            elif case == "ignored-file":
                (source / "extra.ignored").write_text("unreviewed fixture bytes\n")
            else:
                command([*git, "remote", "set-url", "origin", wrong_repository], source)
            run(case, first, cache=cache, home=native / (case + "-home"), expected=False)
            require(observations[-1]["httpsRequests"] == 0, case + ": bad cache reached transport")
        cache, home = native / "check-cache", native / "check-home"
        run("check-mode", first, cache=cache, home=home, check=True)
        require(
            not cache.exists() and not home.exists() and observations[-1]["httpsRequests"] == 0,
            "Check mode acquired or installed source",
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)
    record = {
        "scope": (
            "Synthetic localhost HTTPS Git, exact Ansible checkout and synthetic "
            "acme.sh-compatible installer only; no actual upstream installation, "
            "certificate issuance, production deployment or trust approval"
        ),
        "tlsValidationEnabled": True,
        "inheritedTlsBypassIgnored": True,
        "fixtureCommits": {"first": first, "second": second},
        "observations": observations,
    }
    (output / "git-acquisition-result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.absolute()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use isolated Linux with root permissions for temporary ownership fixtures")
    if not output.resolve().is_relative_to(root) or output.exists() or output.is_symlink():
        parser.error("The output directory must be fresh and inside the checkout")
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="certweaver-git-fixture-") as temporary:
        result = verify(root, output, Path(temporary))
    print(f"Verified {len(result['observations'])} synthetic Git acquisition/reconciliation cases")
