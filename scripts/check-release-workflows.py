"""Guard release dependency, privilege and handoff contracts.

This is local configuration verification, not evidence that hosted CI ran.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def load(path: Path) -> dict:
    # BaseLoader preserves the Actions key `on` and makes boolean comparisons
    # explicit instead of interpreting YAML 1.1's on/off as true/false.
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def github_required_checks_contract(ci: dict, security: dict, codeql: dict) -> list[str]:
    """Keep the names observed in main protection, with a blocking matrix aggregate."""
    errors = []
    package = ci.get("jobs", {}).get("installed-package", {})
    package_steps = package.get("steps", [])
    checkouts = [
        step for step in package_steps if step.get("uses", "").startswith("actions/checkout@")
    ]
    if (
        package.get("env")
        != {"PACKAGE_COMMIT": "${{ github.event.pull_request.head.sha || github.sha }}"}
        or len(checkouts) != 1
        or checkouts[0].get("with", {}).get("ref") != "${{ env.PACKAGE_COMMIT }}"
        or "if" in checkouts[0]
        or any("PACKAGE_COMMIT" in step.get("env", {}) for step in package_steps)
    ):
        errors.append("CI packages must check out the reviewed commit with no step override")
    steps = ci.get("jobs", {}).get("test", {}).get("steps", [])
    preparation = [
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Prepare private verification workspace"
    ]
    privileged = [i for i, step in enumerate(steps) if step.get("run", "").startswith("sudo ")]
    if (
        len(preparation) != 1
        or steps[preparation[0]]
        != {
            "name": "Prepare private verification workspace",
            "run": "install -d -m 0700 .certweaver .certweaver/tools",
        }
        or not privileged
        or preparation[0] >= min(privileged)
    ):
        errors.append(
            "Runner-owned private workspace and tool cache must precede privileged fixtures"
        )
    gate = ci.get("jobs", {}).get("required-ci", {})
    condition = "needs.test.result != 'success' || needs['installed-package'].result != 'success'"
    if (
        set(gate) != {"name", "needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"}
        or gate.get("name") != "CI / test"
        or gate.get("needs") != ["test", "installed-package"]
        or gate.get("if") != "always()"
        or gate.get("runs-on") != "ubuntu-latest"
        or gate.get("timeout-minutes") != "5"
        or gate.get("permissions") != {}
        or ci.get("defaults")
        or ci.get("env")
    ):
        errors.append("CI / test must be an unprivileged always-run aggregate of both matrices")
    steps = gate.get("steps", [])
    if steps != [
        {"name": "Reject any incomplete matrix", "if": condition, "run": "exit 1"},
        {"name": "Confirm required matrices", "run": 'echo "All CI matrices passed."'},
    ]:
        errors.append(
            "Required CI aggregate must reject any failed, cancelled, skipped or missing matrix"
        )
    if security.get("jobs", {}).get("scan", {}).get("name") != "Security / scan":
        errors.append("Security job name must match the protected Security / scan context")
    if codeql.get("jobs", {}).get("analyze", {}).get("name") != "CodeQL / Analyze Python":
        errors.append("CodeQL job name must match the protected CodeQL / Analyze Python context")
    return errors


def gitlab_release_contract(root: Path, document: dict) -> list[str]:
    errors = []
    sast = document.get("python-yaml-sast", {})
    expected_sast = {
        "stage": "security",
        "timeout": "20 minutes",
        "image": {
            "name": "registry.gitlab.com/security-products/semgrep:6.30.0@sha256:"
            "c412f7fa397fb934a2862c7156c88384c202e913873528ef6a2785786fd57e44",
            "entrypoint": [""],
        },
        "variables": {"GIT_STRATEGY": "clone", "GIT_DEPTH": "0"},
        "dependencies": [],
        "cache": [],
        "before_script": [],
        "script": [
            'python scripts/check-sast.py --commit "$CI_COMMIT_SHA" --output-dir .certweaver/sast'
        ],
        "artifacts": {
            "access": "maintainer",
            "when": "always",
            "expire_in": "7 days",
            "reports": {"sast": ".certweaver/sast/gl-sast-report.json"},
            "paths": [
                ".certweaver/sast/gl-sast-report.json",
                ".certweaver/sast/result.json",
                ".certweaver/sast/diagnostics.json",
            ],
        },
    }
    if sast != expected_sast:
        errors.append(
            "GitLab SAST requires an unconditional immutable analyzer, exact source, "
            "complete-report gate and restricted native/derived artifacts"
        )
    if document.get("stages") != ["test", "security", "package", "sign", "verify"]:
        errors.append("GitLab must preserve ordered quality/security/package/sign/verify stages")
    required = {"source-scan": "security", "sign-release": "sign", "verify-release": "verify"}
    for name, stage in required.items():
        job = document.get(name, {})
        if job.get("stage") != stage or job.get("allow_failure", "false") != "false":
            errors.append(f"GitLab requires a blocking {name} job in the correct stage")
        if job.get("when", "on_success") != "on_success" or job.get("after_script"):
            errors.append(f"GitLab {name} must not bypass failure or mutate outputs afterward")
    if document.get("default", {}).get("id_tokens") or document.get("default", {}).get(
        "after_script"
    ):
        errors.append(
            "GitLab defaults must not distribute signing identities or post-verification code"
        )
    for name, job in document.items():
        if isinstance(job, dict) and name != "sign-release" and job.get("id_tokens"):
            errors.append("Only the protected GitLab signing job may request ID tokens")
    source = document.get("source-scan", {})
    signer = document.get("sign-release", {})
    consumer = document.get("verify-release", {})
    build_setup = [
        "apt-get update",
        "apt-get install -y --no-install-recommends git",
        "python scripts/install-python-deps.py build --project",
    ]
    for name, job in [("source-scan", source), ("sign-release", signer)]:
        if (
            job.get("variables") != {"GIT_STRATEGY": "clone"}
            or job.get("dependencies") != []
            or job.get("cache") != []
            or "needs" in job
            or job.get("before_script") != build_setup
        ):
            errors.append(
                f"GitLab {name} requires fresh trusted source without incoming artifacts/cache"
            )
    if any(key in source for key in ["rules", "only", "except"]) or source.get("script") != [
        "python scripts/check-source-security.py "
        '--commit "$CI_COMMIT_SHA" --output-dir .certweaver/source-security'
    ]:
        errors.append(
            "GitLab source security must inspect exact source and all locks unconditionally"
        )
    if source.get("artifacts") != {
        "access": "maintainer",
        "when": "always",
        "expire_in": "7 days",
        "paths": [
            ".certweaver/source-security/source-security-result.json",
            ".certweaver/source-security/diagnostics.json",
        ],
    }:
        errors.append("GitLab source scan must retain only redacted derived diagnostics")
    rule = (
        '$CI_SERVER_URL == "https://gitlab.com" && $CI_PIPELINE_SOURCE == "push" && '
        '$CI_COMMIT_REF_PROTECTED == "true" && '
        "$CI_COMMIT_TAG =~ /^v[0-9]+\\.[0-9]+\\.[0-9]+$/"
    )
    for name, job in [("sign-release", signer), ("verify-release", consumer)]:
        rules = job.get("rules", [])
        if len(rules) != 1 or set(rules[0]) != {"if"} or " ".join(rules[0]["if"].split()) != rule:
            errors.append(f"GitLab {name} must be restricted to protected GitLab.com push tags")
    if (
        signer.get("id_tokens") != {"SIGSTORE_ID_TOKEN": {"aud": "sigstore"}}
        or signer.get("environment") != {"name": "release"}
        or signer.get("interruptible") != "false"
        or signer.get("resource_group") != "release-signing"
    ):
        errors.append(
            "GitLab signing requires its scoped token, release environment and serialization"
        )
    expected_script = [
        "python scripts/gitlab-release.py context",
        'python scripts/build-package.py --commit "$CI_COMMIT_SHA"',
        'python scripts/check-package-reproducibility.py --commit "$CI_COMMIT_SHA"',
        "python scripts/check-wheel.py dist/*.whl",
        "git archive --format=tar.gz --prefix=certweaver-${CI_COMMIT_TAG}/ "
        + "-o dist/certweaver-${CI_COMMIT_TAG}.tar.gz HEAD",
        "git archive --format=zip --prefix=certweaver-${CI_COMMIT_TAG}/ "
        + "-o dist/certweaver-${CI_COMMIT_TAG}.zip HEAD",
        'python scripts/qualify-release.py dist --tag "$CI_COMMIT_TAG" --commit "$CI_COMMIT_SHA"',
        'python scripts/release-evidence.py dist --tag "$CI_COMMIT_TAG" --commit "$CI_COMMIT_SHA"',
        "python scripts/install-ci-tool.py cosign",
        "python scripts/gitlab-release.py sign --cosign .certweaver/tools/cosign "
        + "--output .certweaver/gitlab-signing-verification.json",
    ]
    if signer.get("script") != expected_script:
        errors.append(
            "GitLab signing must rebuild/qualify its own candidate before signing and verifying"
        )
    if signer.get("artifacts") != {
        "access": "maintainer",
        "when": "on_success",
        "expire_in": "7 days",
        "paths": [
            "dist/",
            "release-evidence/qualification.json",
            "release-evidence/gitlab-provenance.json",
            "release-evidence/gitlab-provenance.sigstore.json",
        ],
    }:
        errors.append(
            "GitLab signed handoff must contain exactly the artifacts and signed evidence"
        )
    if (
        consumer.get("variables") != {"GIT_STRATEGY": "empty"}
        or consumer.get("cache") != []
        or consumer.get("needs") != [{"job": "sign-release", "artifacts": "true"}]
        or "dependencies" in consumer
        or consumer.get("before_script") != build_setup[:2]
        or consumer.get("artifacts")
        != {
            "access": "maintainer",
            "when": "on_success",
            "expire_in": "7 days",
            "paths": ["release-intake/verified.json"],
        }
    ):
        errors.append(
            "GitLab consumer needs only signed data and an isolated trusted verifier checkout"
        )
    try:
        canonical = (root / "ci/gitlab-consumer-bootstrap.py").read_text(encoding="utf-8")
        expected = "python -I - <<'CERTWEAVER_BOOTSTRAP'\n" + canonical + "CERTWEAVER_BOOTSTRAP\n"
        if consumer.get("script") != [expected]:
            errors.append(
                "GitLab consumer inline bootstrap differs from the reviewed canonical source"
            )
    except OSError:
        errors.append("GitLab consumer canonical bootstrap is missing")
    return errors


def check_workflows(root: Path) -> list[str]:
    errors: list[str] = []
    directory = root / ".github/workflows"
    release = load(directory / "release.yml")
    jobs = release["jobs"]
    if release.get("permissions") != {"contents": "read"}:
        errors.append("Release workflow must default to contents:read only")
    for name, filename in {
        "quality": "ci.yml",
        "security": "security.yml",
        "codeql": "codeql.yml",
    }.items():
        job = jobs.get(name, {})
        if job.get("uses") != f"./.github/workflows/{filename}":
            errors.append(f"Release {name} must reuse the same-commit {filename}")
        workflow = load(directory / filename)
        if "workflow_call" not in workflow.get("on", {}):
            errors.append(f"{filename} must be callable by the release workflow")
        for child_name, child in workflow["jobs"].items():
            required_ci = name == "quality" and child_name == "required-ci"
            if ("if" in child and not required_ci) or child.get(
                "continue-on-error", "false"
            ) != "false":
                errors.append(f"{filename} cannot skip/allow failure of a required job")
            for step in child.get("steps", []):
                if step.get("continue-on-error", "false") != "false":
                    errors.append(f"{filename} cannot allow failed verification steps")
        steps = [s for child in workflow["jobs"].values() for s in child.get("steps", [])]
        required_actions = {
            "security": ("gitleaks/gitleaks-action@", "aquasecurity/trivy-action@"),
            "codeql": ("github/codeql-action/init@", "github/codeql-action/analyze@"),
        }.get(name, ())
        for action in required_actions:
            matching = [s for s in steps if s.get("uses", "").startswith(action)]
            if not matching or any("if" in s for s in matching):
                errors.append(f"{filename} requires unconditional {action} verification")
        if name == "quality":
            for prefix in (
                "pytest ",
                "python scripts/check-coverage.py",
                "python scripts/check-adapter-acquisition.py",
                "python scripts/check-cluster-health.py",
                "python scripts/check-managed-strategy.py",
                'sudo -n "$(command -v python)" scripts/check-snapshot-config.py',
                'sudo -n "$(command -v python)" scripts/check-snapshot-reconcile.py',
                'sudo -n "$(command -v python)" scripts/check-snapshot-api.py',
                'sudo -n "$(command -v python)" scripts/check-kubeconfig-export.py',
                'sudo -n "$(command -v python)" scripts/check-cluster-versions.py',
                'sudo -n "$(command -v python)" scripts/check-adapter-download.py',
                'sudo -n "$(command -v python)" scripts/check-container-configuration.py',
                'sudo -n "$(command -v python)" scripts/check-application-installation.py',
                'python scripts/check-controller-preflight.py',
                'sudo -n "$(command -v python)" scripts/check-git-acquisition.py',
                'sudo -n "$(command -v python)" scripts/check-chart-acquisition.py',
                "python scripts/install-ci-tool.py helm",
                "python scripts/check-platform-baseline.py --helm .certweaver/tools/helm",
                "ansible-lint ",
                "python scripts/check-wheel.py",
            ):
                matching = [s for s in steps if s.get("run", "").startswith(prefix)]
                if not matching or any("if" in s for s in matching):
                    errors.append(f"Quality workflow requires unconditional {prefix} verification")
        if name == "security":
            for step in steps:
                if step.get("uses", "").startswith("aquasecurity/trivy-action@") and (
                    step.get("with", {}).get("exit-code") != "1"
                ):
                    errors.append("Source vulnerability scan must fail on blocking findings")
    for name, job in jobs.items():
        if "if" in job or job.get("continue-on-error", "false") != "false":
            errors.append(f"Release job {name} cannot bypass success dependencies")
        if name != "publish" and any(
            job.get("permissions", {}).get(p) == "write"
            for p in ("contents", "id-token", "attestations")
        ):
            errors.append(f"Non-publisher {name} has release/signing write privileges")
    build, publish = jobs.get("build", {}), jobs.get("publish", {})
    if not {"quality", "security", "codeql"} <= set(build.get("needs", [])):
        errors.append("Build must require quality, security and CodeQL success")
    if "build" not in publish.get("needs", []):
        errors.append("Publication must require successful qualified build")
    if publish.get("environment") != "release":
        errors.append("Publication must use the release environment")
    build_steps, publish_steps = build.get("steps", []), publish.get("steps", [])
    ci = load(directory / "ci.yml")
    errors.extend(
        github_required_checks_contract(
            ci, load(directory / "security.yml"), load(directory / "codeql.yml")
        )
    )
    for name, profile in (("test", "dev --editable"), ("installed-package", "build")):
        steps = ci["jobs"][name]["steps"]
        if not any(
            step.get("run") == f"python scripts/install-python-deps.py {profile}"
            and "if" not in step
            for step in steps
        ):
            errors.append(f"CI {name} must install the source-bound Python hash locks")
        for step in steps:
            command = step.get("run", "")
            if re.search(r"\bpip install\b", command):
                errors.append("CI cannot resolve Python dependencies outside the locked installer")
            if ("python -m build" in command and "--no-isolation" not in command) or (
                "pip wheel" in command and "--no-build-isolation" not in command
            ):
                errors.append("CI package builds cannot resolve unpinned build dependencies")
    if not any(
        step.get("run") == "python scripts/install-python-deps.py build --project"
        and "if" not in step
        for step in build_steps
    ):
        errors.append("Release build must install the source-bound Python hash locks")
    if any(
        step.get("run") == "python -m build" or "pip install" in step.get("run", "")
        for step in build_steps
    ):
        errors.append("Release build cannot bypass locked Python/build dependencies")
    for steps, variable in (
        (ci["jobs"]["installed-package"]["steps"], "$PACKAGE_COMMIT"),
        (build_steps, "$GITHUB_SHA"),
    ):
        positions = []
        for script in ("build-package.py", "check-package-reproducibility.py"):
            matches = [
                i
                for i, step in enumerate(steps)
                if step.get("run") == f'python scripts/{script} --commit "{variable}"'
                and "if" not in step
                and step.get("continue-on-error", "false") == "false"
            ]
            if len(matches) != 1:
                errors.append(
                    "Package qualification requires unconditional exact-source build "
                    "and reproduction"
                )
            else:
                positions.append(matches[0])
        if len(positions) == 2 and positions != sorted(positions):
            errors.append("Package reproduction must follow the exact-source build")
    for workflow in directory.glob("*.yml"):
        document = load(workflow)
        for job in document["jobs"].values():
            for step in job.get("steps", []):
                action = step.get("uses", "")
                if action and not re.fullmatch(r"[A-Za-z0-9_./-]+@[a-f0-9]{40}", action):
                    errors.append(f"Unpinned action in {workflow.name}: {action}")
    qualification = [
        (i, step)
        for i, step in enumerate(build_steps)
        if step.get("run", "").startswith("python scripts/qualify-release.py dist")
    ]
    uploads = [
        i
        for i, step in enumerate(build_steps)
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    if (
        len(qualification) != 1
        or "if" in qualification[0][1]
        or qualification[0][1].get("continue-on-error", "false") != "false"
        or '--commit "$GITHUB_SHA"' not in qualification[0][1].get("run", "")
        or not uploads
        or any(i <= qualification[0][0] for i in uploads)
    ):
        errors.append("Shared artifact qualification must succeed before candidate upload")
    for step in build_steps:
        action = step.get("uses", "")
        if action.startswith("softprops/action-gh-release@") or (
            action.startswith("anchore/sbom-action@")
            and step.get("with", {}).get("upload-release-assets", "true") != "false"
        ):
            errors.append("Build cannot publish release assets before qualification")
    if len(uploads) != 1 or build_steps[uploads[0]].get("with", {}).get("path", "").split() != [
        "dist/*",
        "release-evidence/qualification.json",
    ]:
        errors.append(
            "Candidate handoff must retain only artifacts and derived qualification evidence"
        )
    downloads = [
        s for s in publish_steps if s.get("uses", "").startswith("actions/download-artifact@")
    ]
    if (
        len(downloads) != 1
        or downloads[0].get("with", {}).get("artifact-ids")
        != ("${{ needs.build.outputs.artifact-id }}")
        or downloads[0].get("with", {}).get("digest-mismatch") != "error"
        or downloads[0].get("with", {}).get("path") != ".certweaver/release-handoff"
    ):
        errors.append(
            "Publisher must download the exact build artifact ID and reject digest mismatch"
        )
    markers = []
    for step in publish_steps:
        if "if" in step or step.get("continue-on-error", "false") != "false":
            errors.append(
                "Publisher steps cannot skip/allow failed handoff or provenance verification"
            )
        action, command = step.get("uses", ""), step.get("run", "")
        if "scripts/check-release.py" in command:
            if not command.startswith('python "$GITHUB_WORKSPACE/scripts/check-release.py" dist '):
                errors.append("Handoff verification must execute the trusted checkout script")
            if step.get("working-directory") != ".certweaver/release-handoff":
                errors.append("Handoff verification must inspect the isolated candidate directory")
            if '--commit "$GITHUB_SHA"' not in command:
                errors.append("Handoff verification must bind the expected source commit")
            markers.append("handoff")
        if "scripts/release-evidence.py" in command:
            if not command.startswith(
                'python "$GITHUB_WORKSPACE/scripts/release-evidence.py" dist '
            ):
                errors.append("Evidence verification must execute the trusted checkout script")
            if step.get("working-directory") != ".certweaver/release-handoff":
                errors.append("Evidence verification must inspect the isolated candidate directory")
            if '--commit "$GITHUB_SHA"' not in command or '--tag "$RELEASE_TAG"' not in command:
                errors.append("Evidence verification must bind the expected tag and source commit")
            markers.append("evidence")
        if action.startswith("actions/attest-build-provenance@"):
            if step.get("with", {}).get("subject-path", "").split() != [
                ".certweaver/release-handoff/dist/*",
                ".certweaver/release-handoff/release-evidence/qualification.json",
            ]:
                errors.append("Provenance must bind artifacts and derived qualification evidence")
            markers.append("attest")
        if "gh attestation verify" in command:
            if step.get("working-directory") != ".certweaver/release-handoff":
                errors.append("Provenance verification must inspect the isolated handoff")
            if not all(
                flag in command for flag in ("--repo", "--signer-workflow", "--source-digest")
            ):
                errors.append(
                    "Provenance verification must constrain repository, signer and source"
                )
            markers.append("verify")
            if "for artifact in dist/* release-evidence/qualification.json; do" not in command:
                errors.append("Provenance verification must include qualification evidence")
        if action.startswith("softprops/action-gh-release@"):
            if step.get("with", {}).get("files", "").split() != [
                ".certweaver/release-handoff/dist/*"
            ]:
                errors.append("Public release assets must exclude qualification evidence and logs")
            markers.append("publish")
    if markers != ["handoff", "evidence", "attest", "verify", "publish"]:
        errors.append(
            "Required order: handoff, evidence verification, attestation, verification, publication"
        )
    gitlab = load(root / ".gitlab-ci.yml")
    for name in ("lint-test", "secret-scan", "package"):
        job = gitlab[name]
        if job.get("allow_failure", "false") != "false" or job.get("when") == "always":
            errors.append(f"GitLab {name} cannot bypass failed gates")
    if "needs" in gitlab["package"]:
        errors.append("GitLab package must retain all prior-stage dependencies")
    package = gitlab["package"]
    for command in (
        "python scripts/check-adapter-acquisition.py",
        "python scripts/check-cluster-health.py --output-dir .certweaver/cluster-health-check",
        "python scripts/check-managed-strategy.py --output-dir .certweaver/managed-strategy-check",
        "python scripts/check-snapshot-config.py --output-dir .certweaver/snapshot-config-check",
        "python scripts/check-snapshot-reconcile.py "
        "--output-dir .certweaver/snapshot-reconcile-check",
        "python scripts/check-snapshot-api.py --output-dir .certweaver/snapshot-api-check",
        "python scripts/check-kubeconfig-export.py "
        "--output-dir .certweaver/kubeconfig-export-check",
        "python scripts/check-cluster-versions.py --output-dir .certweaver/cluster-versions-check",
        "python scripts/check-adapter-download.py --output-dir .certweaver/adapter-download-check",
        "python scripts/check-container-configuration.py "
        "--output-dir .certweaver/container-configuration-check",
        "python scripts/check-controller-preflight.py "
        "--output-dir .certweaver/controller-preflight-check",
        "python scripts/check-git-acquisition.py --output-dir .certweaver/git-acquisition-check",
        "python scripts/install-ci-tool.py helm",
        "python scripts/check-platform-baseline.py --helm .certweaver/tools/helm "
        "--output-dir .certweaver/platform-baseline-check",
        "python scripts/check-chart-acquisition.py --helm .certweaver/tools/helm "
        "--output-dir .certweaver/chart-acquisition-check",
    ):
        if command not in gitlab["lint-test"].get("script", []):
            errors.append(f"GitLab requires adapter acquisition verification: {command}")
    if "python scripts/install-python-deps.py dev --editable" not in gitlab["default"].get(
        "before_script", []
    ):
        errors.append("GitLab tests require the source-bound Python development lock")
    if "python scripts/install-python-deps.py build --project" not in package.get(
        "before_script", []
    ):
        errors.append("GitLab packaging requires the source-bound Python build lock")
    if any(
        "pip install" in command or command == "python -m build"
        for job in (gitlab["lint-test"], package)
        for command in [*job.get("before_script", []), *job.get("script", [])]
    ):
        errors.append("GitLab cannot resolve unpinned Python/build dependencies")
    for job in (gitlab["lint-test"], package):
        script = job.get("script", [])
        expected = [
            f'python scripts/{name} --commit "$CI_COMMIT_SHA"'
            for name in ("build-package.py", "check-package-reproducibility.py")
        ]
        if any(command not in script for command in expected) or (
            all(command in script for command in expected)
            and script.index(expected[0]) >= script.index(expected[1])
        ):
            errors.append(
                "GitLab requires the ordered exact-source build and independent reproduction"
            )
    if any("pip install" in command for command in gitlab["default"].get("before_script", [])):
        errors.append("GitLab default setup cannot bypass Python locks")
    if not any(
        command.startswith("python scripts/qualify-release.py dist")
        and '--commit "$CI_COMMIT_SHA"' in command
        for command in package.get("script", [])
    ):
        errors.append("GitLab package must run full shared artifact qualification")
    artifacts = package.get("artifacts", {})
    if artifacts.get("when") != "on_success" or artifacts.get("access") != "maintainer":
        errors.append(
            "GitLab candidate artifacts require successful qualification and restricted access"
        )
    if artifacts.get("paths") != ["dist/", "release-evidence/qualification.json"] or not any(
        command
        == (
            "python scripts/release-evidence.py dist "
            '--tag "$CI_COMMIT_TAG" --commit "$CI_COMMIT_SHA"'
        )
        for command in package.get("script", [])
    ):
        errors.append(
            "GitLab must verify and retain derived qualification evidence without raw logs"
        )
    errors.extend(gitlab_release_contract(root, gitlab))
    return errors


if __name__ == "__main__":
    failures = check_workflows(Path(__file__).resolve().parents[1])
    for failure in failures:
        print(f"ERROR: {failure}")
    if not failures:
        print("Release workflow dependency, privilege, artifact and provenance contracts passed")
    raise SystemExit(1 if failures else 0)
