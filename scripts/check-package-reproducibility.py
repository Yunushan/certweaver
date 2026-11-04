"""Require byte-identical package rebuilds from a clean clone and fresh locked env."""

from __future__ import annotations

import argparse
import json
import os
import runpy
import subprocess
import sys
import venv
from pathlib import Path

STATUS = "BYTE_IDENTICAL_PACKAGE_REBUILD_NOT_PRODUCTION_APPROVAL"


def reproduce(root: Path, *, commit: str) -> dict:
    root = root.resolve()
    builder = runpy.run_path(str(root / "scripts/build-package.py"))
    epoch = builder["source_epoch"](root, commit)
    tools = builder["build_tools"](root)
    work = root / ".certweaver/package-reproduction"
    if work.exists() or work.is_symlink() or not work.resolve().is_relative_to(root):
        raise ValueError("Package reproduction requires fresh protected work storage")
    work.mkdir(parents=True, mode=0o700)
    env = builder["environment"]()

    def stage(label: str, command: list[str], cwd: Path) -> None:
        result = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, timeout=600, check=False
        )
        log = work / (label + ".log")
        log.write_bytes(result.stdout + b"\n" + result.stderr)
        log.chmod(0o600)
        if result.returncode:
            raise ValueError(f"Package reproduction {label} failed")

    clone = work / "source"
    stage(
        "clone",
        ["git", "clone", "--no-hardlinks", "--no-checkout", "--", str(root), str(clone)],
        root,
    )
    stage(
        "checkout",
        ["git", "-c", "core.hooksPath=" + os.devnull, "checkout", "--detach", commit],
        clone,
    )
    isolated = work / "environment"
    venv.EnvBuilder(with_pip=False).create(isolated)
    python = isolated / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    stage(
        "locked-environment",
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--python",
            str(python),
            "install",
            "--no-input",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--index-url",
            "https://pypi.org/simple",
            "--require-hashes",
            "--only-binary=:all:",
            "-r",
            str(clone / "ci/python-build.lock"),
        ],
        root,
    )
    stage("rebuild", [str(python), "scripts/build-package.py", "--commit", commit], clone)
    record = verify_reproduction(root, clone, commit=commit, epoch=epoch, tools=tools)
    (work / "receipt.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def verify_reproduction(root: Path, clone: Path, *, commit: str, epoch: int, tools: dict) -> dict:
    builder = runpy.run_path(str(root / "scripts/build-package.py"))
    digest = builder["digest"]
    records = []
    for source in (root, clone):
        receipt_path = source / ".certweaver/package-build/receipt.json"
        digest(receipt_path)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (
            receipt.get("status") != builder["STATUS"]
            or receipt.get("sourceCommit") != commit
            or receipt.get("sourceDateEpoch") != epoch
            or receipt.get("buildTools") != tools
            or receipt.get("normalization", {}).get("payloadPreserved") is not True
            or receipt.get("wheelNormalization", {}).get("payloadPreserved") is not True
        ):
            raise ValueError(
                "Package build receipts have inconsistent identity, tools or normalization"
            )
        required = {
            "scripts/build-package.py",
            "scripts/install-python-deps.py",
            "ci/python-locks.json",
            "ci/python-build.lock",
            "ci/python-build.in",
            "pyproject.toml",
        }
        if set(receipt["policySha256"]) != required:
            raise ValueError("Package build policy inventory is incomplete")
        for name, expected in receipt["policySha256"].items():
            if (
                name
                not in {
                    "scripts/build-package.py",
                    "scripts/install-python-deps.py",
                    "ci/python-locks.json",
                    "ci/python-build.lock",
                    "ci/python-build.in",
                    "pyproject.toml",
                }
                or digest(source / name) != expected
            ):
                raise ValueError("Package build policy identity changed")
        paths = list((source / "dist").iterdir())
        actual = {path.name: digest(path) for path in paths}
        if actual != receipt["artifacts"] or len(actual) != 2:
            raise ValueError("Package build artifacts differ from their receipt")
        records.append((receipt, digest(receipt_path)))
    if records[0][0]["artifacts"] != records[1][0]["artifacts"]:
        raise ValueError("Clean independent package rebuild is not byte-identical")
    if records[0][0]["interpreter"] != records[1][0]["interpreter"]:
        raise ValueError("Package reconstruction used different interpreter/compression inputs")
    return {
        "schemaVersion": 1,
        "status": STATUS,
        "sourceCommit": commit,
        "sourceDateEpoch": epoch,
        "artifacts": records[0][0]["artifacts"],
        "buildReceiptSha256": records[0][1],
        "rebuildReceiptSha256": records[1][1],
        "buildTools": tools,
        "interpreter": records[0][0]["interpreter"],
        "policySha256": records[0][0]["policySha256"],
        "reproductionScriptSha256": digest(root / "scripts/check-package-reproducibility.py"),
        "freshSourceClone": True,
        "freshLockedEnvironment": True,
        "independentReviewerApproval": False,
    }


def qualified_build(root: Path, directory: Path, *, commit: str) -> dict:
    builder = runpy.run_path(str(root / "scripts/build-package.py"))
    digest = builder["digest"]
    paths = [
        root / ".certweaver/package-build/receipt.json",
        root / ".certweaver/package-reproduction/receipt.json",
    ]
    for path in paths:
        digest(path)
    build, repeated = (json.loads(path.read_text(encoding="utf-8")) for path in paths)
    if (
        repeated.get("status") != STATUS
        or build.get("status") != builder["STATUS"]
        or build.get("sourceCommit") != commit
        or repeated.get("sourceCommit") != commit
        or build.get("sourceDateEpoch") != builder["source_epoch"](root, commit)
        or repeated.get("sourceDateEpoch") != build["sourceDateEpoch"]
        or repeated.get("buildReceiptSha256") != digest(paths[0])
        or repeated.get("artifacts") != build.get("artifacts")
        or repeated.get("freshSourceClone") is not True
        or repeated.get("freshLockedEnvironment") is not True
        or repeated.get("buildTools") != builder["build_tools"](root)
        or build.get("buildTools") != repeated.get("buildTools")
        or build.get("interpreter") != builder["runtime_inputs"]()
        or repeated.get("interpreter") != build.get("interpreter")
        or repeated.get("independentReviewerApproval") is not False
        or build.get("policySha256")
        != {name: digest(root / name) for name in builder["POLICY_FILES"]}
        or repeated.get("policySha256") != build.get("policySha256")
        or build.get("normalization", {}).get("payloadPreserved") is not True
        or build.get("wheelNormalization", {}).get("payloadPreserved") is not True
        or len(build.get("artifacts", {})) != 2
    ):
        raise ValueError("Candidate lacks matching exact-source build and reproduction evidence")
    for name, expected in build["artifacts"].items():
        if Path(name).name != name or digest(directory / name) != expected:
            raise ValueError("Candidate package differs from the byte-identical rebuild")
    for name, expected in build["policySha256"].items():
        if name not in repeated["policySha256"] or digest(root / name) != expected:
            raise ValueError("Build policy changed after reproduction")
    if digest(root / "scripts/check-package-reproducibility.py") != repeated.get(
        "reproductionScriptSha256"
    ):
        raise ValueError("Package reproduction policy changed")
    return {
        "status": STATUS,
        "sourceCommit": commit,
        "sourceDateEpoch": build["sourceDateEpoch"],
        "artifacts": build["artifacts"],
        "freshSourceClone": True,
        "freshLockedEnvironment": True,
        "independentReviewerApproval": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(reproduce(Path(__file__).resolve().parents[1], commit=args.commit), indent=2)
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: Package reproduction failed ({type(exc).__name__})")
        raise SystemExit(1) from exc
