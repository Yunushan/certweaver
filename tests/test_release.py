from __future__ import annotations

import hashlib
import io
import json
import runpy
import shutil
import subprocess
import tarfile
import zipfile

import pytest
import yaml

from certweaver.registry import project_root

release_tools = runpy.run_path(str(project_root() / "scripts/check-release.py"))
workflow_tools = runpy.run_path(str(project_root() / "scripts/check-release-workflows.py"))
COMMIT = "a" * 40
TAG = "v0.1.0"


@pytest.fixture(autouse=True)
def fixture_checkout(monkeypatch):
    # Artifact fixtures are logic inputs, not a claim about this dirty checkout.
    monkeypatch.setitem(release_tools["check_release"].__globals__, "_checkout", lambda *_: None)


@pytest.mark.parametrize(
    "head,status,code", [("b" * 40, "", 0), (COMMIT, " M file", 0), (COMMIT, "", 1)]
)
def test_dirty_wrong_or_unreadable_checkout_is_rejected(monkeypatch, head, status, code):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, code, head if command[1] == "rev-parse" else status
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError, match="clean checkout"):
        release_tools["_checkout"](project_root(), COMMIT)


def test_clean_expected_checkout_is_accepted(monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, COMMIT if command[1] == "rev-parse" else "")

    monkeypatch.setattr(subprocess, "run", run)
    assert release_tools["_checkout"](project_root(), COMMIT) is None


def checksums(directory):
    names = sorted(p for p in directory.iterdir() if p.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in names),
        encoding="utf-8",
    )


def artifacts(tmp_path):
    output = tmp_path / "dist"
    output.mkdir()
    metadata = b"Metadata-Version: 2.4\nName: certweaver\nVersion: 0.1.0\n"
    with zipfile.ZipFile(output / "certweaver-0.1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("certweaver-0.1.0.dist-info/METADATA", metadata)
    with tarfile.open(output / "certweaver-0.1.0.tar.gz", "w:gz") as archive:
        info = tarfile.TarInfo("certweaver-0.1.0/PKG-INFO")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    with tarfile.open(
        output / "certweaver-v0.1.0.tar.gz", "w:gz", pax_headers={"comment": COMMIT}
    ) as archive:
        archive.addfile(tarfile.TarInfo("certweaver-v0.1.0/README.md"), io.BytesIO(b""))
    with zipfile.ZipFile(output / "certweaver-v0.1.0.zip", "w") as archive:
        archive.writestr("certweaver-v0.1.0/README.md", b"fixture")
        archive.comment = COMMIT.encode()
    (output / "certweaver-v0.1.0.sbom.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"name": "certweaver", "type": "library"}],
            }
        ),
        encoding="utf-8",
    )
    checksums(output)
    return output


def test_release_handoff_accepts_complete_consistent_fixture(tmp_path):
    assert (
        release_tools["check_release"](
            artifacts(tmp_path), tag=TAG, commit=COMMIT, root=project_root()
        )
        == []
    )


@pytest.mark.parametrize(
    "change",
    [
        "tag",
        "commit",
        "tamper",
        "extra",
        "missing",
        "empty",
        "duplicate-hash",
        "missing-hash",
        "escape-hash",
        "bad-hash",
        "package-version",
        "zip-commit",
        "tar-commit",
        "zip-prefix",
        "tar-prefix",
        "empty-sbom",
        "invalid-sbom",
        "metadata-duplicate",
        "corrupt-wheel",
    ],
)
def test_release_handoff_rejects_invalid_artifacts(tmp_path, change):
    directory = artifacts(tmp_path)
    tag, commit = TAG, COMMIT
    wheel = directory / "certweaver-0.1.0-py3-none-any.whl"
    manifest = directory / "SHA256SUMS"
    if change == "tag":
        tag = "v9.9.9"
    elif change == "commit":
        commit = "main"
    elif change == "tamper":
        wheel.write_bytes(b"changed after checksum")
    elif change == "extra":
        (directory / "operator.env").write_text("must not publish")
    elif change == "missing":
        wheel.unlink()
    elif change == "empty":
        wheel.write_bytes(b"")
    elif change == "duplicate-hash":
        manifest.write_text(manifest.read_text() * 2)
    elif change == "missing-hash":
        manifest.write_text("\n".join(manifest.read_text().splitlines()[1:]))
    elif change == "escape-hash":
        manifest.write_text("a" * 64 + "  ../outside\n")
    elif change == "bad-hash":
        manifest.write_text("not a checksum\n")
    elif change in {"package-version", "metadata-duplicate"}:
        metadata = b"Name: certweaver\nVersion: 0.1.0\n"
        metadata += b"Version: 0.1.0\n" if change == "metadata-duplicate" else b"Version: 9.9.9\n"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("certweaver-0.1.0.dist-info/METADATA", metadata)
        checksums(directory)
    elif change in {"zip-commit", "zip-prefix"}:
        with zipfile.ZipFile(directory / "certweaver-v0.1.0.zip", "w") as archive:
            archive.writestr(
                "wrong/README" if change == "zip-prefix" else "certweaver-v0.1.0/README", "fixture"
            )
            archive.comment = ("b" * 40 if change == "zip-commit" else COMMIT).encode()
        checksums(directory)
    elif change in {"tar-commit", "tar-prefix"}:
        with tarfile.open(
            directory / "certweaver-v0.1.0.tar.gz",
            "w:gz",
            pax_headers={"comment": "b" * 40 if change == "tar-commit" else COMMIT},
        ) as archive:
            archive.addfile(
                tarfile.TarInfo(
                    "certweaver-v0.1.0evil/README"
                    if change == "tar-prefix"
                    else "certweaver-v0.1.0/README"
                ),
                io.BytesIO(b""),
            )
        checksums(directory)
    elif change in {"empty-sbom", "invalid-sbom"}:
        (directory / "certweaver-v0.1.0.sbom.cdx.json").write_text(
            "{}" if change == "empty-sbom" else "bad"
        )
        checksums(directory)
    elif change == "corrupt-wheel":
        wheel.write_bytes(b"not a zip archive")
        checksums(directory)
    assert release_tools["check_release"](directory, tag=tag, commit=commit, root=project_root())


def test_release_workflows_obey_dependency_and_privilege_contracts():
    assert workflow_tools["check_workflows"](project_root()) == []


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "name",
        "test-dependency",
        "package-dependency",
        "always",
        "allowed-failure",
        "step-allowed-failure",
        "successful-exit",
        "weakened-condition",
        "matrix",
        "token",
        "shell",
        "security-name",
        "codeql-name",
    ],
)
def test_required_check_contexts_and_aggregate_cannot_be_bypassed(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github/workflows", tmp_path / ".github/workflows")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    (tmp_path / "ci").mkdir()
    shutil.copyfile(
        root / "ci/gitlab-consumer-bootstrap.py", tmp_path / "ci/gitlab-consumer-bootstrap.py"
    )
    assert workflow_tools["check_workflows"](tmp_path) == []
    path = tmp_path / ".github/workflows/ci.yml"
    document = workflow_tools["load"](path)
    gate = document["jobs"]["required-ci"]
    if change == "missing":
        del document["jobs"]["required-ci"]
    elif change == "name":
        gate["name"] = "different name"
    elif change.endswith("-dependency"):
        gate["needs"].remove("test" if change == "test-dependency" else "installed-package")
    elif change == "always":
        del gate["if"]
    elif change == "allowed-failure":
        gate["continue-on-error"] = True
    elif change == "step-allowed-failure":
        gate["steps"][0]["continue-on-error"] = True
    elif change == "successful-exit":
        gate["steps"][0]["run"] = "exit 0"
    elif change == "weakened-condition":
        gate["steps"][0]["if"] = gate["steps"][0]["if"].replace(" || ", " && ")
    elif change == "matrix":
        gate["strategy"] = {"matrix": {"variant": ["a", "b"]}}
    elif change == "token":
        gate["permissions"] = {"contents": "write"}
    elif change == "shell":
        document["defaults"] = {"run": {"shell": "bash {0} || true"}}
    else:
        path = tmp_path / (
            ".github/workflows/security.yml"
            if change == "security-name"
            else ".github/workflows/codeql.yml"
        )
        document = workflow_tools["load"](path)
        document["jobs"]["scan" if change == "security-name" else "analyze"]["name"] = (
            "different name"
        )
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert workflow_tools["check_workflows"](tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        "missing-security",
        "missing-quality",
        "missing-codeql",
        "publish-no-build",
        "build-write",
        "global-write",
        "always-publish",
        "allow-build-failure",
        "early-sbom-upload",
        "artifact-name",
        "ignore-digest",
        "skip-handoff",
        "skip-provenance",
        "wrong-source",
        "qualification-conditional",
        "qualification-allowed-failure",
        "qualification-removed",
        "qualification-source",
        "upload-before-qualification",
        "gitlab-qualification-removed",
        "gitlab-public-artifacts",
        "missing-codeql-scan",
        "gitlab-allow-failure",
        "gitlab-skip-security",
        "evidence-not-retained",
        "evidence-verification-removed",
        "evidence-wrong-source",
        "evidence-not-attested",
        "evidence-provenance-skipped",
        "evidence-published",
        "gitlab-evidence-not-retained",
        "gitlab-evidence-not-verified",
        "handoff-overwrites-checkout",
        "handoff-untrusted-script",
        "evidence-untrusted-script",
        "evidence-wrong-directory",
        "unlocked-ci-deps",
        "isolated-build-resolution",
        "unlocked-release-deps",
        "conditional-lock-install",
        "gitlab-unlocked-dev",
        "gitlab-unlocked-build",
        "reproduction-removed",
        "reproduction-skipped",
        "reproduction-nonblocking",
        "reproduction-wrong-source",
        "gitlab-reproduction-removed",
        "adapter-download-removed",
        "adapter-download-conditional",
        "adapter-inventory-removed",
        "gitlab-adapter-download-removed",
        "container-gate-removed",
        "container-gate-conditional",
        "gitlab-container-gate-removed",
        "git-gate-removed",
        "git-gate-conditional",
        "gitlab-git-gate-removed",
        "chart-gate-removed",
        "chart-gate-conditional",
        "gitlab-chart-gate-removed",
        "helm-installer-removed",
        "health-gate-removed",
        "health-gate-conditional",
        "gitlab-health-gate-removed",
        "version-gate-removed",
        "version-gate-conditional",
        "gitlab-version-gate-removed",
        "export-gate-removed",
        "export-gate-conditional",
        "gitlab-export-gate-removed",
    ],
)
def test_broken_workflow_cannot_pass_release_contract(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github/workflows", tmp_path / ".github/workflows")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    (tmp_path / "ci").mkdir()
    shutil.copyfile(
        root / "ci/gitlab-consumer-bootstrap.py", tmp_path / "ci/gitlab-consumer-bootstrap.py"
    )
    assert workflow_tools["check_workflows"](tmp_path) == []
    path = tmp_path / ".github/workflows/release.yml"
    document = workflow_tools["load"](path)
    jobs = document["jobs"]
    build, publish = jobs["build"], jobs["publish"]
    if change.startswith("missing-") and change != "missing-codeql-scan":
        build["needs"].remove(change.removeprefix("missing-"))
    elif change == "publish-no-build":
        publish["needs"] = []
    elif change == "build-write":
        build["permissions"]["contents"] = "write"
    elif change == "global-write":
        document["permissions"]["contents"] = "write"
    elif change == "always-publish":
        publish["if"] = "always()"
    elif change == "allow-build-failure":
        build["continue-on-error"] = "true"
    if change == "early-sbom-upload":
        build["steps"].append(
            {
                "uses": "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
                "with": {"upload-release-assets": "true"},
            }
        )
    if change == "evidence-not-retained":
        next(s for s in build["steps"] if s.get("id") == "upload")["with"]["path"] = "dist/*"
    if change == "unlocked-release-deps":
        next(s for s in build["steps"] if "install-python-deps.py" in s.get("run", ""))["run"] = (
            "pip install . build"
        )
    reproduction = next(
        s for s in build["steps"] if "check-package-reproducibility.py" in s.get("run", "")
    )
    if change == "reproduction-removed":
        build["steps"].remove(reproduction)
    elif change == "reproduction-skipped":
        reproduction["if"] = "false"
    elif change == "reproduction-nonblocking":
        reproduction["continue-on-error"] = "true"
    elif change == "reproduction-wrong-source":
        reproduction["run"] = reproduction["run"].replace("$GITHUB_SHA", "main")
    if change == "evidence-verification-removed":
        publish["steps"] = [
            s for s in publish["steps"] if "scripts/release-evidence.py" not in s.get("run", "")
        ]
    qualification = next(
        step for step in build["steps"] if "qualify-release.py dist" in step.get("run", "")
    )
    if change == "qualification-conditional":
        qualification["if"] = "false"
    elif change == "qualification-allowed-failure":
        qualification["continue-on-error"] = "true"
    elif change == "qualification-removed":
        build["steps"].remove(qualification)
    elif change == "qualification-source":
        qualification["run"] = qualification["run"].replace("$GITHUB_SHA", "main")
    elif change == "upload-before-qualification":
        build["steps"].remove(qualification)
        build["steps"].append(qualification)
    for step in publish["steps"]:
        if (
            "scripts/release-evidence.py" in step.get("run", "")
            and change == "evidence-wrong-source"
        ):
            step["run"] = step["run"].replace("$GITHUB_SHA", "main")
        if (
            step.get("uses", "").startswith("actions/attest-build-provenance@")
            and change == "evidence-not-attested"
        ):
            step["with"]["subject-path"] = "dist/*"
        if (
            "gh attestation verify" in step.get("run", "")
            and change == "evidence-provenance-skipped"
        ):
            step["run"] = step["run"].replace(" release-evidence/qualification.json;", ";")
        if (
            step.get("uses", "").startswith("softprops/action-gh-release@")
            and change == "evidence-published"
        ):
            step["with"]["files"] = "dist/* release-evidence/*"
        if step.get("uses", "").startswith("actions/download-artifact@"):
            if change == "handoff-overwrites-checkout":
                step["with"]["path"] = "."
            if change == "artifact-name":
                step["with"].pop("artifact-ids")
            if change == "ignore-digest":
                step["with"]["digest-mismatch"] = "warn"
        if "scripts/check-release.py" in step.get("run", ""):
            if change == "handoff-untrusted-script":
                step["run"] = step["run"].replace(
                    '"$GITHUB_WORKSPACE/scripts/check-release.py"', "scripts/check-release.py"
                )
            if change == "skip-handoff":
                step["if"] = "false"
            if change == "wrong-source":
                step["run"] = step["run"].replace("$GITHUB_SHA", "main")
        if "scripts/release-evidence.py" in step.get("run", ""):
            if change == "evidence-untrusted-script":
                step["run"] = step["run"].replace(
                    '"$GITHUB_WORKSPACE/scripts/release-evidence.py"', "scripts/release-evidence.py"
                )
            elif change == "evidence-wrong-directory":
                step["working-directory"] = "."
        if "gh attestation verify" in step.get("run", "") and change == "skip-provenance":
            step["run"] = "echo skipped"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    if (
        change.startswith(
            (
                "container-",
                "git-gate-",
                "chart-gate-",
                "health-gate-",
                "version-gate-",
                "export-gate-",
            )
        )
        or change == "helm-installer-removed"
    ):
        path = tmp_path / ".github/workflows/ci.yml"
        ci = workflow_tools["load"](path)
        steps = ci["jobs"]["test"]["steps"]
        script = (
            "check-kubeconfig-export.py"
            if change.startswith("export-gate-")
            else "check-cluster-versions.py"
            if change.startswith("version-gate-")
            else "check-cluster-health.py"
            if change.startswith("health-gate-")
            else "check-git-acquisition.py"
            if change.startswith("git-gate-")
            else "check-chart-acquisition.py"
            if change.startswith("chart-gate-")
            else "install-ci-tool.py helm"
            if change == "helm-installer-removed"
            else "check-container-configuration.py"
        )
        if change.endswith("-conditional"):
            next(s for s in steps if script in s.get("run", ""))["if"] = "false"
        else:
            ci["jobs"]["test"]["steps"] = [s for s in steps if script not in s.get("run", "")]
        path.write_text(yaml.safe_dump(ci), encoding="utf-8")
    if change.startswith("adapter-"):
        path = tmp_path / ".github/workflows/ci.yml"
        ci = workflow_tools["load"](path)
        script = (
            "check-adapter-acquisition.py"
            if change == "adapter-inventory-removed"
            else "check-adapter-download.py"
        )
        steps = ci["jobs"]["test"]["steps"]
        if change == "adapter-download-conditional":
            next(s for s in steps if script in s.get("run", ""))["if"] = "false"
        else:
            ci["jobs"]["test"]["steps"] = [s for s in steps if script not in s.get("run", "")]
        path.write_text(yaml.safe_dump(ci), encoding="utf-8")
    if change in {"unlocked-ci-deps", "isolated-build-resolution", "conditional-lock-install"}:
        path = tmp_path / ".github/workflows/ci.yml"
        ci = workflow_tools["load"](path)
        if change == "isolated-build-resolution":
            next(
                s
                for s in ci["jobs"]["installed-package"]["steps"]
                if s.get("run", "").startswith("python scripts/build-package.py ")
            )["run"] = "python -m build"
        else:
            step = next(
                s
                for s in ci["jobs"]["test"]["steps"]
                if "install-python-deps.py" in s.get("run", "")
            )
            if change == "unlocked-ci-deps":
                step["run"] = "pip install -e '.[dev]'"
            else:
                step["if"] = "false"
        path.write_text(yaml.safe_dump(ci), encoding="utf-8")
    if change == "missing-codeql-scan":
        path = tmp_path / ".github/workflows/codeql.yml"
        codeql = workflow_tools["load"](path)
        codeql["jobs"]["analyze"]["steps"] = [
            s
            for s in codeql["jobs"]["analyze"]["steps"]
            if not s.get("uses", "").startswith("github/codeql-action/analyze@")
        ]
        path.write_text(yaml.safe_dump(codeql), encoding="utf-8")
    if change.startswith("gitlab-"):
        path = tmp_path / ".gitlab-ci.yml"
        gitlab = workflow_tools["load"](path)
        if change == "gitlab-allow-failure":
            gitlab["secret-scan"]["allow_failure"] = "true"
        elif change == "gitlab-qualification-removed":
            gitlab["package"]["script"] = [
                c for c in gitlab["package"]["script"] if "qualify-release.py" not in c
            ]
        elif change == "gitlab-public-artifacts":
            gitlab["package"]["artifacts"]["access"] = "all"
        elif change == "gitlab-evidence-not-retained":
            gitlab["package"]["artifacts"]["paths"] = ["dist/"]
        elif change == "gitlab-evidence-not-verified":
            gitlab["package"]["script"] = [
                s for s in gitlab["package"]["script"] if "release-evidence.py" not in s
            ]
        elif change == "gitlab-unlocked-dev":
            gitlab["default"]["before_script"][0] = "pip install -e '.[dev]'"
        elif change == "gitlab-unlocked-build":
            gitlab["package"]["before_script"][-1] = "pip install . build"
        elif change == "gitlab-reproduction-removed":
            gitlab["package"]["script"] = [
                s
                for s in gitlab["package"]["script"]
                if "check-package-reproducibility.py" not in s
            ]
        elif change == "gitlab-adapter-download-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-adapter-download.py" not in s
            ]
        elif change == "gitlab-container-gate-removed":
            gitlab["lint-test"]["script"] = [
                s
                for s in gitlab["lint-test"]["script"]
                if "check-container-configuration.py" not in s
            ]
        elif change == "gitlab-git-gate-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-git-acquisition.py" not in s
            ]
        elif change == "gitlab-chart-gate-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-chart-acquisition.py" not in s
            ]
        elif change == "gitlab-health-gate-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-cluster-health.py" not in s
            ]
        elif change == "gitlab-export-gate-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-kubeconfig-export.py" not in s
            ]
        elif change == "gitlab-version-gate-removed":
            gitlab["lint-test"]["script"] = [
                s for s in gitlab["lint-test"]["script"] if "check-cluster-versions.py" not in s
            ]
        else:
            gitlab["package"]["needs"] = ["lint-test"]
        path.write_text(yaml.safe_dump(gitlab), encoding="utf-8")
    assert workflow_tools["check_workflows"](tmp_path)
