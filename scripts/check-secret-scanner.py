"""Qualify the actual artifact-secret scanner with clean and seeded archives.

Fixtures are generated in temporary storage and are never credentials used by
any service. Reports retain counts and exit codes, not fixture contents.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import runpy
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path


def qualify_scanner(executable: str) -> dict:
    expand = runpy.run_path(str(Path(__file__).with_name("expand-release-assets.py")))[
        "expand_release"
    ]
    # Resolve before changing any working directory, including relative tool paths.
    executable = str(Path(executable).resolve()) if Path(executable).is_file() else executable
    with tempfile.TemporaryDirectory(prefix="certweaver-secret-gate-") as temporary:
        root = Path(temporary)
        clean, seeded, expanded = (root / name for name in ("clean", "seeded", "expanded"))
        clean.mkdir()
        seeded.mkdir()
        config, ignore = root / "trivy.yaml", root / "empty.ignore"
        config.write_text("{}\n", encoding="utf-8")
        ignore.write_text("", encoding="utf-8")
        policy = Path(__file__).resolve().parents[1] / "ci/secret-scan.yaml"
        (clean / "README.txt").write_text(
            "Clean scanner qualification control.\n", encoding="utf-8"
        )
        # Split the header in source so the fixture generator is not itself a
        # literal private-key finding when the repository is scanned.
        fixture = (
            b"-----BEGIN "
            + b"PRIVATE KEY-----\n"
            + base64.b64encode(os.urandom(128))
            + b"\n-----END "
            + b"PRIVATE KEY-----\n"
        )
        for name in ("fixture.whl", "fixture.zip"):
            with zipfile.ZipFile(seeded / name, "w") as archive:
                archive.writestr("fixture.pem", fixture)
                archive.writestr("fixture.md", fixture)
        with tarfile.open(seeded / "fixture.tar.gz", "w:gz") as archive:
            member = tarfile.TarInfo("fixture.pem")
            member.size = len(fixture)
            archive.addfile(member, io.BytesIO(fixture))
            member = tarfile.TarInfo("fixture.md")
            member.size = len(fixture)
            archive.addfile(member, io.BytesIO(fixture))
        expand(seeded, expanded)
        observations = []
        for label, directory, expected_code, expected_count in (
            ("clean", clean, 0, 0),
            ("expanded-archives", expanded, 1, 6),
        ):
            report = root / f"{label}.json"
            result = subprocess.run(
                [
                    executable,
                    "fs",
                    "--disable-telemetry",
                    "--config",
                    str(config),
                    "--ignorefile",
                    str(ignore),
                    "--secret-config",
                    str(policy),
                    "--scanners",
                    "secret",
                    "--severity",
                    "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                    "--exit-code",
                    "1",
                    "--format",
                    "json",
                    "--output",
                    str(report),
                    str(directory),
                ],
                check=False,
                capture_output=True,
                timeout=90,
                cwd=root,
                env={k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")},
            )
            if not report.is_file() or report.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Scanner qualification produced no usable bounded report")
            data = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("Results") or [], list):
                raise ValueError("Malformed scanner qualification report")
            findings, paths = [], set()
            for item in data.get("Results") or []:
                if not isinstance(item, dict) or not isinstance(item.get("Secrets") or [], list):
                    raise ValueError("Malformed scanner qualification result")
                secrets = item.get("Secrets") or []
                if any(not isinstance(finding, dict) for finding in secrets):
                    raise ValueError("Malformed scanner finding")
                findings.extend(secrets)
                if secrets:
                    paths.add(
                        "/".join(str(item.get("Target", "")).replace("\\", "/").split("/")[-2:])
                    )
            expected_paths = (
                {
                    f"{name}.contents/{filename}"
                    for name in ("fixture.whl", "fixture.zip", "fixture.tar.gz")
                    for filename in ("fixture.pem", "fixture.md")
                }
                if expected_count
                else set()
            )
            if (
                result.returncode != expected_code
                or len(findings) != expected_count
                or paths != expected_paths
            ):
                raise ValueError(
                    f"Scanner qualification rejected {label}: exit={result.returncode}, "
                    f"findings={len(findings)}, distinctTargets={len(paths)}"
                )
            observations.append(
                {"case": label, "exitCode": result.returncode, "secretFindings": len(findings)}
            )
        return {
            "status": "SCANNER_QUALIFIED_WITH_SYNTHETIC_FIXTURES",
            "scope": "Scanner and archive-inspection behavior only; not production assurance",
            "observations": observations,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trivy", default="trivy", help="Trusted, independently installed Trivy binary"
    )
    args = parser.parse_args()
    try:
        print(json.dumps(qualify_scanner(args.trivy), indent=2))
        return 0
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        # Never echo scanner stdout/stderr or fixture report contents.
        print(f"ERROR: Secret scanner qualification failed ({type(exc).__name__})")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
