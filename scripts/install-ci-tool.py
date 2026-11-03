"""Install a reviewed Linux/amd64 CI tool using pinned archive and binary hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
REPOSITORIES = {
    "trivy": "aquasecurity/trivy",
    "syft": "anchore/syft",
    "helm": "helm/helm",
    "cosign": "sigstore/cosign",
    "kube-apiserver": "kubernetes/kubernetes",
    "etcd": "etcd-io/etcd",
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != "https":
            raise ValueError("CI tool downloads cannot redirect outside HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def tool_record(root: Path, name: str) -> dict:
    manifest = json.loads((root / "ci/tools.lock.json").read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 1 or manifest.get("platform") != "linux-amd64":
        raise ValueError("Unsupported CI tool lock format/platform")
    record = manifest["tools"][name]
    kind = record.get("format", "tar.gz")
    if (
        name not in REPOSITORIES
        or record.get("repository") != REPOSITORIES[name]
        or record.get("member")
        != (
            "linux-amd64/helm"
            if name == "helm"
            else f"etcd-{record['version']}-linux-amd64/etcd"
            if name == "etcd"
            else name
        )
        or not re.fullmatch(r"v\d+\.\d+\.\d+", record["version"])
        or kind != ("raw" if name in {"cosign", "kube-apiserver"} else "tar.gz")
    ):
        raise ValueError("Unexpected CI tool identity")
    url = urlparse(record["url"])
    if name == "kube-apiserver":
        source_allowed = url.netloc == "dl.k8s.io" and url.path == (
            f"/release/{record['version']}/bin/linux/amd64/kube-apiserver"
        )
    elif name == "etcd":
        source_allowed = url.netloc == "github.com" and url.path == (
            f"/etcd-io/etcd/releases/download/{record['version']}/"
            f"etcd-{record['version']}-linux-amd64.tar.gz"
        )
    else:
        source_allowed = (
            url.netloc == "get.helm.sh"
            and url.path == f"/helm-{record['version']}-linux-amd64.tar.gz"
            if name == "helm"
            else url.netloc == "github.com"
            and url.path.startswith(f"/{REPOSITORIES[name]}/releases/download/{record['version']}/")
            and (
                url.path
                == f"/sigstore/cosign/releases/download/{record['version']}/cosign-linux-amd64"
                if name == "cosign"
                else url.path.endswith(".tar.gz")
            )
        )
    if url.scheme != "https" or not source_allowed or url.query or url.fragment:
        raise ValueError("CI tool source is outside its approved release path")
    for key in ("archiveSha256", "executableSha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", record[key]):
            raise ValueError("Invalid CI tool digest")
    return record


def install_tool(name: str, root: Path, *, archive: Path | None = None) -> Path:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("The reviewed CI tool lock currently supports Linux/amd64 only")
    root = root.resolve()
    record = tool_record(root, name)
    payload_limit = MAX_EXECUTABLE_BYTES if record.get("format") == "raw" else MAX_ARCHIVE_BYTES
    directory = root / ".certweaver/tools"
    if directory.is_symlink() or not directory.resolve().is_relative_to(root):
        raise ValueError("CI tool directory escapes the checkout")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    target = directory / name
    mode = "CACHED_EXECUTABLE"
    if target.exists() or target.is_symlink():
        if (
            target.is_symlink()
            or not target.is_file()
            or digest(target) != record["executableSha256"]
        ):
            raise ValueError(
                "Existing CI tool has an unexpected type or digest; refusing to execute it"
            )
    else:
        mode = "OFFLINE_ARCHIVE" if archive is not None else "DOWNLOADED_ARCHIVE"
        with tempfile.TemporaryDirectory(prefix=f"{name}-", dir=directory) as temporary:
            work = Path(temporary)
            payload = archive or work / "download.tar.gz"
            if archive is None:
                request = urllib.request.Request(
                    record["url"], headers={"User-Agent": "CertWeaver-CI"}
                )
                opener = urllib.request.build_opener(HTTPSRedirects())
                started, size = time.monotonic(), 0
                with opener.open(request, timeout=45) as source, payload.open("xb") as output:
                    while block := source.read(1024 * 1024):
                        size += len(block)
                        if size > payload_limit or time.monotonic() - started > 180:
                            raise ValueError("CI tool download exceeded size/time limits")
                        output.write(block)
            if (
                payload.is_symlink()
                or not payload.is_file()
                or not 0 < payload.stat().st_size <= payload_limit
                or digest(payload) != record["archiveSha256"]
            ):
                raise ValueError("CI tool archive digest/size verification failed")
            executable = work / name
            if record.get("format") == "raw":
                with payload.open("rb") as source, executable.open("xb") as output:
                    copied = 0
                    while block := source.read(1024 * 1024):
                        copied += len(block)
                        if copied > MAX_EXECUTABLE_BYTES:
                            raise ValueError("Raw CI executable exceeds its size limit")
                        output.write(block)
            else:
                extract_executable(payload, executable, record)
            if digest(executable) != record["executableSha256"]:
                raise ValueError("CI tool executable digest verification failed")
            executable.chmod(0o700)
            os.replace(executable, target)
    target.chmod(0o700)
    receipt = {
        **record,
        "name": name,
        "status": "LOCKED_CI_TOOL_VERIFIED",
        "verificationMode": mode,
        "archiveVerifiedThisRun": mode != "CACHED_EXECUTABLE",
    }
    receipt_path = directory / f"{name}.receipt.json"
    if receipt_path.is_symlink():
        raise ValueError("CI tool receipt cannot be a link")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return target


def extract_executable(payload: Path, executable: Path, record: dict) -> None:
    with tarfile.open(payload) as bundle:
        matches, expanded_size = [], 0
        for entries, member in enumerate(bundle, start=1):
            expanded_size += member.size
            if entries > 1000 or expanded_size > MAX_EXPANDED_BYTES:
                raise ValueError("CI tool archive exceeds inspection limits")
            if member.name == record["member"]:
                matches.append(member)
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > MAX_EXECUTABLE_BYTES:
            raise ValueError("CI tool archive lacks one bounded regular executable")
        with bundle.extractfile(matches[0]) as source, executable.open("xb") as output:
            copied = 0
            while block := source.read(1024 * 1024):
                copied += len(block)
                if copied > matches[0].size or copied > MAX_EXECUTABLE_BYTES:
                    raise ValueError("CI tool executable exceeded its declared size")
                output.write(block)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=sorted(REPOSITORIES))
    parser.add_argument(
        "--archive",
        type=Path,
        help="Offline archive or raw payload; both pinned hashes are required",
    )
    args = parser.parse_args()
    try:
        print(install_tool(args.name, Path(__file__).resolve().parents[1], archive=args.archive))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print(f"ERROR: CI tool installation failed: {exc}")
        raise SystemExit(1) from exc
