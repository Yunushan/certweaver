"""Scan exact tracked source and reconcile all declared Python lock inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

RESERVED = "__certweaver_lock_inventory__"
PYTHONS = ("3.11.18", "3.12.16", "3.13.18", "3.14.4")
PLATFORMS = {"linux": ("Linux", "posix"), "win32": ("Windows", "nt"), "darwin": ("Darwin", "posix")}
STAGES = (
    "output-preparation",
    "trusted-helpers",
    "checkout",
    "tool-acquisition",
    "lock-inventories",
    "scanner-qualification",
    "source-materialization",
    "dependency-scan",
    "dependency-inventory",
    "secret-scan",
    "secret-inventory",
    "database-freshness",
    "result-writing",
    "diagnostics",
    "complete",
)


class RunState:
    """Only fixed stage identifiers enter public diagnostics."""

    def __init__(self):
        self.stage = STAGES[0]
        self.owns_output = False

    def enter(self, stage):
        if stage not in STAGES:
            raise ValueError("Unknown source-security stage")
        self.stage = stage


class ScannerExit(ValueError):
    def __init__(self, code):
        super().__init__("Source security scanner returned a nonzero exit code")
        self.code = code


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def materialize_source(root, scan, commit, environment):
    def git(*arguments):
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=environment,
            capture_output=True,
            check=True,
            timeout=30,
        )
        require(len(result.stdout) <= 16 * 1024 * 1024, "Source object exceeds its size bound")
        return result.stdout

    listing = git("ls-tree", "-r", "-z", "--full-tree", "--long", commit).split(b"\0")
    source_hashes = {}
    total = 0
    for entry in [value for value in listing if value]:
        header, path = entry.split(b"\t", 1)
        mode, kind, identity, length = header.split()
        require(
            mode in {b"100644", b"100755"}
            and kind == b"blob"
            and re.fullmatch(rb"[a-f0-9]{40}|[a-f0-9]{64}", identity)
            and length.isdigit(),
            "Unsupported committed source object",
        )
        name, size = path.decode("utf-8"), int(length)
        source = root / name
        require(
            len(source_hashes) < 20000
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and Path(name).parts[0] != RESERVED
            and "\\" not in name
            and not source.is_symlink()
            and source.is_file()
            and source.resolve().is_relative_to(root),
            "Unsafe tracked source path",
        )
        total += size
        require(
            size <= 16 * 1024 * 1024 and total <= 128 * 1024 * 1024,
            "Tracked source scan exceeded its size bound",
        )
        payload = git("cat-file", "blob", identity.decode("ascii"))
        object_hash = hashlib.new("sha1" if len(identity) == 40 else "sha256")
        object_hash.update(b"blob " + str(size).encode("ascii") + b"\0" + payload)
        expected = hashlib.sha256(payload).hexdigest()
        require(
            len(payload) == size and object_hash.hexdigest().encode("ascii") == identity,
            "Committed source object identity mismatch",
        )
        require(
            source.stat().st_size == size and digest(source) == expected,
            "Working source bytes differ from the expected Git tree",
        )
        target = scan / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        source_hashes[name] = expected
    require(source_hashes, "Source commit has no tracked files")
    return source_hashes


def lock_inventories(root):
    installer = runpy.run_path(str(root / "scripts/install-python-deps.py"))
    groups = {}
    for profile in ("runtime", "build", "dev"):
        path = installer["lock_file"](root, profile)
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").replace("\\\n", " ").splitlines()
            if line.strip()
        ]
        requirements = [Requirement(line.split("--hash=", 1)[0].strip()) for line in lines]
        active = set()
        for python in PYTHONS:
            for platform, (system, os_name) in PLATFORMS.items():
                marker = default_environment()
                marker.update(
                    python_version=".".join(python.split(".")[:2]),
                    python_full_version=python,
                    sys_platform=platform,
                    platform_system=system,
                    os_name=os_name,
                    implementation_name="cpython",
                    implementation_version=python,
                    platform_python_implementation="CPython",
                    platform_machine="x86_64",
                    platform_release="",
                    platform_version="",
                    extra="",
                )
                expected = {}
                for index, requirement in enumerate(requirements):
                    if requirement.marker and not requirement.marker.evaluate(marker):
                        continue
                    active.add(index)
                    specifiers = list(requirement.specifier)
                    require(
                        len(specifiers) == 1 and specifiers[0].operator == "==",
                        "Source security requires exact declared versions",
                    )
                    name, version = canonicalize_name(requirement.name), specifiers[0].version
                    require(
                        name not in expected or expected[name] == version,
                        "Contradictory versions in a declared Python environment",
                    )
                    expected[name] = version
                require(expected, "A declared Python environment is empty")
                fingerprint = hashlib.sha256(
                    json.dumps(expected, sort_keys=True).encode()
                ).hexdigest()
                key = profile + "/" + fingerprint[:16] + "/requirements.txt"
                group = groups.setdefault(
                    key,
                    {
                        "profile": profile,
                        "packages": expected,
                        "lockSha256": digest(path),
                        "targets": [],
                    },
                )
                group["targets"].append({"python": python, "platform": platform})
        require(
            active == set(range(len(requirements))),
            "A lock marker was not covered by the declared source-security target matrix",
        )
    return groups


def reconcile(report, scan, inventories):
    require(
        type(report) is dict
        and report.get("SchemaVersion") == 2
        and report.get("ArtifactName") == str(scan)
        and report.get("ArtifactType") == "filesystem"
        and isinstance(report.get("Results"), list),
        "Invalid source dependency scan report",
    )
    found = {}
    for result in report["Results"]:
        require(
            type(result) is dict
            and (
                result.get("Vulnerabilities") is None
                or isinstance(result.get("Vulnerabilities"), list)
                and not result["Vulnerabilities"]
            ),
            "Source dependency scan contains blocking vulnerabilities or malformed results",
        )
        if result.get("Type") != "pip":
            continue
        target = str(result.get("Target", "")).replace("\\", "/")
        prefix = str(scan).replace("\\", "/") + "/"
        if target.startswith(prefix):
            target = target[len(prefix) :]
        require(target.startswith(RESERVED + "/"), "Unexpected Python scan input")
        key = target.removeprefix(RESERVED + "/")
        require(
            key in inventories and key not in found and isinstance(result.get("Packages"), list),
            "Missing, duplicate or unknown declared lock scan target",
        )
        packages = {}
        for package in result["Packages"]:
            require(
                type(package) is dict
                and isinstance(package.get("Name"), str)
                and isinstance(package.get("Version"), str),
                "Malformed dependency scan identity",
            )
            name = canonicalize_name(package["Name"])
            require(name not in packages, "Duplicate dependency scan identity")
            packages[name] = package["Version"]
        require(
            packages == inventories[key]["packages"],
            "Declared Python lock inventory is missing or differs from scanner coverage",
        )
        found[key] = packages
    require(set(found) == set(inventories), "Scanner omitted a declared Python lock environment")
    return found


def diagnostics(output, status, error=None, *, state=None, exception=None):
    """Retain actionable advisory IDs without source snippets or secret matches."""
    advisory_ids = set()
    report = output / "declared-dependencies.json"
    advisory_status = "UNAVAILABLE"
    try:
        require(not report.is_symlink() and report.is_file(), "No regular dependency report")
        with report.open("rb") as stream:
            payload = stream.read(32 * 1024 * 1024 + 1)
        require(len(payload) <= 32 * 1024 * 1024, "Dependency report exceeds diagnostic bound")
        data = json.loads(payload)
        require(type(data) is dict and isinstance(data.get("Results"), list), "Malformed report")
        for result in data["Results"]:
            require(type(result) is dict, "Malformed result")
            findings = result.get("Vulnerabilities")
            findings = [] if findings is None else findings
            require(isinstance(findings, list), "Malformed findings")
            for finding in findings:
                require(type(finding) is dict, "Malformed finding")
                identity = finding.get("VulnerabilityID", "")
                if isinstance(identity, str) and re.fullmatch(
                    r"CVE-[0-9]{4}-[0-9]{4,12}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", identity
                ):
                    advisory_ids.add(identity)
        advisory_status = "EXTRACTED"
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        advisory_ids.clear()  # An incomplete extraction must not look complete.
    stage = state.stage if state is not None and state.stage in STAGES else "UNKNOWN"
    failure_kind = (
        "SCANNER_NONZERO"
        if isinstance(exception, ScannerExit)
        else "PROCESS_TIMEOUT"
        if isinstance(exception, subprocess.TimeoutExpired)
        else "PROCESS_FAILURE"
        if isinstance(exception, subprocess.SubprocessError)
        else "FILESYSTEM_ERROR"
        if isinstance(exception, OSError)
        else "REJECTED_INPUT_OR_POLICY"
        if isinstance(exception, ValueError)
        else "FAILED"
        if error is not None
        else None
    )
    record = {
        "status": status,
        "stage": stage,
        "failureKind": failure_kind,
        "errorClass": error
        if error
        in {
            None,
            "OSError",
            "ValueError",
            "KeyError",
            "TypeError",
            "AttributeError",
            "ScannerExit",
            "TimeoutExpired",
            "CalledProcessError",
            "FileNotFoundError",
            "PermissionError",
            "FileExistsError",
        }
        else "OTHER",
        "scannerExitCode": exception.code
        if isinstance(exception, ScannerExit) and type(exception.code) is int
        else None,
        "blockingAdvisoryIds": sorted(advisory_ids),
        "advisoryExtraction": advisory_status,
        "scope": "Redacted job diagnostics only; no raw findings, source excerpts or secret values",
    }
    path = output / "diagnostics.json"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


def run_scan(tool, root, output, environment, label, arguments):
    require(label in {"declared-dependencies", "source-secrets"}, "Unknown scanner report")
    command = [
        str(tool),
        "fs",
        "--disable-telemetry",
        "--config",
        str(output / "trivy.yaml"),
        "--ignorefile",
        str(output / "empty.ignore"),
        "--format",
        "json",
        "--no-progress",
        "--exit-code",
        "1",
        "--output",
        str(output / (label + ".json")),
        *arguments,
    ]
    try:
        result = subprocess.run(
            command, cwd=root, env=environment, capture_output=True, timeout=600, check=False
        )
    except subprocess.TimeoutExpired as exc:
        (output / (label + ".log")).write_bytes((exc.stdout or b"") + b"\n" + (exc.stderr or b""))
        raise
    (output / (label + ".log")).write_bytes(result.stdout + b"\n" + result.stderr)
    if result.returncode:
        raise ScannerExit(result.returncode)
    path = output / (label + ".json")
    require(
        path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 32 * 1024 * 1024,
        "Source security report is missing or exceeds its size bound",
    )
    return json.loads(path.read_text(encoding="utf-8"))


def check(root, output, commit, *, state=None):
    state = RunState() if state is None else state
    state.enter("output-preparation")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    state.owns_output = True
    state.enter("trusted-helpers")
    functions = {
        name: runpy.run_path(str(root / "scripts" / (name + ".py")))
        for name in [
            "check-release",
            "build-package",
            "install-ci-tool",
            "check-secret-scanner",
            "release-evidence",
        ]
    }
    state.enter("checkout")
    functions["check-release"]["_checkout"](root, commit)
    env = functions["build-package"]["environment"]()
    env = {k: v for k, v in env.items() if not k.startswith(("TRIVY_", "SIGSTORE_", "COSIGN_"))}
    state.enter("tool-acquisition")
    tool = functions["install-ci-tool"]["install_tool"]("trivy", root)
    state.enter("lock-inventories")
    inventories = lock_inventories(root)
    started = datetime.now(UTC)
    state.enter("scanner-qualification")
    qualification = functions["check-secret-scanner"]["qualify_scanner"](str(tool))
    with tempfile.TemporaryDirectory(prefix="certweaver-source-security-") as temporary:
        scan = Path(temporary) / "scan"
        scan.mkdir(mode=0o700)
        state.enter("source-materialization")
        source_hashes = materialize_source(root, scan, commit, env)
        for name, inventory in inventories.items():
            target = scan / RESERVED / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "\n".join(f"{k}=={v}" for k, v in sorted(inventory["packages"].items())) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        config, ignore = output / "trivy.yaml", output / "empty.ignore"
        config.write_text("{}\n", encoding="utf-8")
        ignore.write_text("", encoding="utf-8")

        def run(label, arguments):
            return run_scan(tool, root, output, env, label, [*arguments, str(scan)])

        state.enter("dependency-scan")
        vulnerabilities = run(
            "declared-dependencies",
            [
                "--scanners",
                "vuln",
                "--pkg-types",
                "library",
                "--list-all-pkgs",
                "--cache-dir",
                str(output / "trivy-cache"),
                "--severity",
                "HIGH,CRITICAL",
            ],
        )
        state.enter("dependency-inventory")
        covered = reconcile(vulnerabilities, scan, inventories)
        state.enter("secret-scan")
        secrets = run(
            "source-secrets",
            [
                "--scanners",
                "secret",
                "--secret-config",
                str(root / "ci/secret-scan.yaml"),
                "--severity",
                "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            ],
        )
        state.enter("secret-inventory")
        require(
            type(secrets) is dict
            and secrets.get("SchemaVersion") == 2
            and secrets.get("ArtifactName") == str(scan)
            and secrets.get("ArtifactType") == "filesystem"
            and isinstance(secrets.get("Results") or [], list)
            and all(
                type(r) is dict
                and (
                    r.get("Secrets") is None
                    or isinstance(r.get("Secrets"), list)
                    and not r["Secrets"]
                )
                for r in secrets.get("Results") or []
            ),
            "Source secret scan contains findings or malformed coverage",
        )
    finished = datetime.now(UTC)
    state.enter("database-freshness")
    database = functions["release-evidence"]["database_record"](
        output, started=started, finished=finished
    )
    result = {
        "status": "SOURCE_SECURITY_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL",
        "sourceCommit": commit,
        "scope": (
            "Tracked-source secrets and declared Python runtime/build/dev lock vulnerabilities; "
            "not an installed inventory, complete SAST, OS/image scan or independent approval"
        ),
        "startedAt": started.isoformat(),
        "finishedAt": finished.isoformat(),
        "trackedSourceSha256": source_hashes,
        "declaredLockInventories": inventories,
        "reconciledEnvironments": len(covered),
        "scannerQualification": qualification,
        "database": database,
        "trivyExecutableSha256": digest(tool),
        "reports": {
            name: digest(output / (name + ".json"))
            for name in ["declared-dependencies", "source-secrets"]
        },
    }
    state.enter("result-writing")
    (output / "source-security-result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    state.enter("complete")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    state = RunState()
    try:
        result = check(
            Path(__file__).resolve().parents[1],
            args.output_dir.absolute(),
            args.commit,
            state=state,
        )
        state.enter("diagnostics")
        diagnostics(args.output_dir.absolute(), result["status"], state=state)
        print(
            "Exact tracked-source and all declared Python lock environments "
            "passed source security checks"
        )
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ) as exc:
        try:
            if state.owns_output and args.output_dir.is_dir() and not args.output_dir.is_symlink():
                diagnostics(
                    args.output_dir.absolute(),
                    "SOURCE_SECURITY_FAILED",
                    type(exc).__name__,
                    state=state,
                    exception=exc,
                )
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            pass  # A diagnostic error never converts the failed gate to success.
        stage = state.stage if state.stage in STAGES else "UNKNOWN"
        print("ERROR: Source security verification failed at stage " + stage)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
