"""Shared GitHub/GitLab artifact qualification; never publishes or approves production."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def helpers(root: Path) -> dict:
    return {
        name: runpy.run_path(str(root / "scripts" / f"{name}.py"))
        for name in (
            "check-release",
            "install-ci-tool",
            "check-secret-scanner",
            "expand-release-assets",
            "release-evidence",
            "install-python-deps",
            "check-package-reproducibility",
        )
    }


def run_stage(label: str, command: list[str], *, root: Path, work: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TRIVY_", "SYFT_", "PIP_"))
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    result = subprocess.run(
        command, cwd=root, env=environment, capture_output=True, timeout=600, check=False
    )
    log = work / f"{label}.log"
    log.write_bytes(result.stdout + b"\n" + result.stderr)
    log.chmod(0o600)
    if result.returncode:
        raise ValueError(f"Release qualification {label} failed (exit {result.returncode})")


def read_json(path: Path) -> dict:
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Qualification report exceeds its size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Qualification report must be an object")
    return value


def package_inventory(pairs) -> dict[str, str]:
    result = {}
    for name, version in pairs:
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError("Runtime package identity/version is missing")
        name = re.sub(r"[-_.]+", "-", name).lower()
        if name in result and result[name] != version:
            raise ValueError("Contradictory runtime package versions")
        result[name] = version
    return result


def object_list(value) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("Qualification report contains a malformed record list")
    return value


def verify_runtime_coverage(runtime: Path, sbom: Path, report: Path, version: str) -> dict:
    expected = package_inventory(
        (dist.metadata.get("Name"), dist.version)
        for dist in importlib.metadata.distributions(path=[str(runtime)])
    )
    if expected.get("certweaver") != version:
        raise ValueError("Installed candidate metadata is missing or has the wrong version")
    bill = read_json(sbom)
    if bill.get("bomFormat") != "CycloneDX":
        raise ValueError("Runtime SBOM must use CycloneDX")
    observed_sbom = package_inventory(
        (c.get("name"), c.get("version"))
        for c in object_list(bill.get("components"))
        if c.get("type") == "library" and str(c.get("purl", "")).startswith("pkg:pypi/")
    )
    data = read_json(report)
    if (
        data.get("SchemaVersion") != 2
        or Path(data.get("ArtifactName", "")).resolve() != runtime.resolve()
    ):
        raise ValueError("Vulnerability report identity/schema does not match the runtime")
    results = object_list(data.get("Results"))
    observed_scan = package_inventory(
        (p.get("Name"), p.get("Version"))
        for entry in results
        if entry.get("Type") == "python-pkg"
        for p in object_list(entry.get("Packages"))
    )
    if expected != observed_sbom or expected != observed_scan:
        raise ValueError("Installed Python inventory, SBOM and vulnerability scan do not agree")
    if any(
        v.get("Severity") in {"HIGH", "CRITICAL"}
        for entry in results
        for v in object_list(entry.get("Vulnerabilities"))
    ):
        raise ValueError("Blocking vulnerabilities remain in the candidate report")
    return expected


def qualify_release(directory: Path, *, tag: str, commit: str, root: Path) -> dict:
    started = datetime.now(UTC)
    root, directory = root.resolve(), directory.resolve()
    if not directory.is_relative_to(root) or directory.is_symlink():
        raise ValueError("Release candidate directory must be inside the checkout")
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise ValueError("A full immutable source commit is required")
    scripts = helpers(root)
    release = scripts["check-release"]
    version = release["release_version"](tag, root)
    release["_checkout"](root, commit)
    wheel = f"certweaver-{version}-py3-none-any.whl"
    expected = {
        wheel,
        f"certweaver-{version}.tar.gz",
        f"certweaver-{tag}.tar.gz",
        f"certweaver-{tag}.zip",
    }
    files = list(directory.iterdir())
    if {p.name for p in files} != expected or any(
        p.is_symlink() or not p.is_file() or p.stat().st_size == 0 for p in files
    ):
        raise ValueError("Qualification requires exactly the four fresh regular candidate archives")
    work = root / ".certweaver/release-qualification"
    if not work.resolve().is_relative_to(root) or work.is_symlink():
        raise ValueError("Release qualification work directory escapes the checkout")
    work.mkdir(parents=True, mode=0o700, exist_ok=False)
    reproduction = scripts["check-package-reproducibility"]["qualified_build"](
        root, directory, commit=commit
    )
    for source, name in [
        (root / ".certweaver/package-build/receipt.json", "package-build.json"),
        (root / ".certweaver/package-reproduction/receipt.json", "package-reproduction.json"),
    ]:
        shutil.copyfile(source, work / name)
    tools = {
        name: scripts["install-ci-tool"]["install_tool"](name, root) for name in ("trivy", "syft")
    }
    config, ignore = work / "trivy.yaml", work / "empty.ignore"
    config.write_text("{}\n", encoding="utf-8")
    ignore.write_text("", encoding="utf-8")
    runtime = work / "runtime"
    requirements = scripts["install-python-deps"]["candidate_requirements"](
        root, directory / wheel, work / "candidate-runtime.lock"
    )
    run_stage(
        "runtime-install",
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-input",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-cache-dir",
            "--no-compile",
            "--index-url",
            "https://pypi.org/simple",
            "--target",
            str(runtime),
            "--report",
            str(work / "runtime-install.json"),
            "-r",
            str(requirements),
        ],
        root=root,
        work=work,
    )
    sbom = directory / f"certweaver-{tag}.sbom.cdx.json"
    run_stage(
        "runtime-sbom",
        [str(tools["syft"]), "scan", f"dir:{runtime}", "-o", f"cyclonedx-json={sbom}"],
        root=root,
        work=work,
    )
    scanner = scripts["check-secret-scanner"]["qualify_scanner"](str(tools["trivy"]))
    (work / "scanner-qualification.json").write_text(
        json.dumps(scanner, indent=2), encoding="utf-8"
    )
    inspection = scripts["expand-release-assets"]["expand_release"](directory, work / "inspection")
    (work / "archive-inspection.json").write_text(
        json.dumps(inspection, indent=2), encoding="utf-8"
    )
    # A new cache directory prevents a restored stale database from qualifying
    # a release. Scanner environment overrides are removed by run_stage().
    run_stage(
        "runtime-vulnerabilities",
        [
            str(tools["trivy"]),
            "rootfs",
            "--disable-telemetry",
            "--config",
            str(config),
            "--ignorefile",
            str(ignore),
            "--pkg-types",
            "library",
            "--list-all-pkgs",
            "--no-progress",
            "--cache-dir",
            str(work / "trivy-cache"),
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--output",
            str(work / "runtime-vulnerabilities.json"),
            str(runtime),
        ],
        root=root,
        work=work,
    )
    inventory = verify_runtime_coverage(
        runtime, sbom, work / "runtime-vulnerabilities.json", version
    )
    run_stage(
        "artifact-secrets",
        [
            str(tools["trivy"]),
            "fs",
            "--disable-telemetry",
            "--config",
            str(config),
            "--ignorefile",
            str(ignore),
            "--secret-config",
            str(root / "ci/secret-scan.yaml"),
            "--scanners",
            "secret",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--output",
            str(work / "artifact-secrets.json"),
            str(work / "inspection"),
        ],
        root=root,
        work=work,
    )
    secret_report = read_json(work / "artifact-secrets.json")
    if (
        secret_report.get("SchemaVersion") != 2
        or Path(secret_report.get("ArtifactName", "")).resolve() != (work / "inspection").resolve()
        or any(entry.get("Secrets") for entry in object_list(secret_report.get("Results")))
    ):
        raise ValueError("Artifact secret report is incomplete, mismatched or contains findings")
    artifacts = {}
    for path in sorted(directory.iterdir()):
        with path.open("rb") as stream:
            artifacts[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    with (directory / "SHA256SUMS").open("x", encoding="utf-8", newline="\n") as output:
        output.writelines(f"{digest}  {name}\n" for name, digest in artifacts.items())
    errors = release["check_release"](directory, tag=tag, commit=commit, root=root)
    if errors:
        raise ValueError("Final qualified artifact handoff validation failed")
    summary = {
        "status": "ARTIFACT_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL",
        "tag": tag,
        "sourceCommit": commit,
        "artifacts": artifacts,
        "scannerQualification": scanner,
        "packageReproducibility": reproduction,
        "verifiedRuntimeInventory": inventory,
        "tools": {name: scripts["install-ci-tool"]["tool_record"](root, name) for name in tools},
    }
    scripts["release-evidence"]["export_evidence"](
        root, work, directory, summary, started=started, finished=datetime.now(UTC)
    )
    (work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("dist"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                qualify_release(
                    args.directory,
                    tag=args.tag,
                    commit=args.commit,
                    root=Path(__file__).resolve().parents[1],
                ),
                indent=2,
            )
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"ERROR: Release qualification failed ({type(exc).__name__}): {exc}")
        raise SystemExit(1) from exc
