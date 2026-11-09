from __future__ import annotations

import hashlib
import io
import json
import runpy
import tarfile

import pytest

from certweaver.registry import project_root

installer = runpy.run_path(str(project_root() / "scripts/install-ci-tool.py"))


def fixture_tool(tmp_path, *, kind="regular"):
    archive = tmp_path / "fixture.tar.gz"
    content = b"fixture executable; never run"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("trivy")
        if kind == "link":
            member.type, member.linkname = tarfile.SYMTYPE, "/outside"
            bundle.addfile(member)
        else:
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
            if kind == "duplicate":
                bundle.addfile(member, io.BytesIO(content))
    record = {
        "repository": "aquasecurity/trivy",
        "member": "trivy",
        "version": "v0.76.1",
        "url": "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/fixture.tar.gz",
        "archiveSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "executableSha256": hashlib.sha256(content).hexdigest(),
    }
    (tmp_path / "ci").mkdir()
    manifest = {"schemaVersion": 1, "platform": "linux-amd64", "tools": {"trivy": record}}
    (tmp_path / "ci/tools.lock.json").write_text(json.dumps(manifest), encoding="utf-8")
    return archive, manifest


@pytest.fixture(autouse=True)
def simulated_supported_platform(monkeypatch):
    monkeypatch.setattr(installer["platform"], "system", lambda: "Linux")
    monkeypatch.setattr(installer["platform"], "machine", lambda: "x86_64")


def test_offline_and_cached_tools_need_both_pins(tmp_path):
    archive, _ = fixture_tool(tmp_path)
    target = installer["install_tool"]("trivy", tmp_path, archive=archive)
    assert target.read_bytes() == b"fixture executable; never run"
    initial = json.loads(target.with_name("trivy.receipt.json").read_text())
    assert initial["verificationMode"] == "OFFLINE_ARCHIVE" and initial["archiveVerifiedThisRun"]
    archive.unlink()
    assert installer["install_tool"]("trivy", tmp_path) == target
    receipt = json.loads(target.with_name("trivy.receipt.json").read_text())
    assert receipt["status"] == "LOCKED_CI_TOOL_VERIFIED"
    assert receipt["verificationMode"] == "CACHED_EXECUTABLE"
    assert receipt["archiveVerifiedThisRun"] is False
    target.write_bytes(b"tampered cache")
    with pytest.raises(ValueError, match="unexpected type or digest"):
        installer["install_tool"]("trivy", tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        "archive",
        "binary-pin",
        "link",
        "duplicate",
        "url",
        "digest-format",
        "version",
        "platform",
        "architecture",
    ],
)
def test_invalid_tool_acquisition_is_rejected(tmp_path, monkeypatch, change):
    archive, manifest = fixture_tool(tmp_path, kind=change)
    record = manifest["tools"]["trivy"]
    if change == "archive":
        archive.write_bytes(b"replaced download")
    elif change == "binary-pin":
        record["executableSha256"] = "0" * 64
    elif change == "url":
        record["url"] = "https://untrusted.invalid/tool.tar.gz"
    elif change == "digest-format":
        record["archiveSha256"] = "invalid"
    elif change == "version":
        record["version"] = "latest"
    elif change == "platform":
        monkeypatch.setattr(installer["platform"], "system", lambda: "Windows")
    elif change == "architecture":
        monkeypatch.setattr(installer["platform"], "machine", lambda: "arm64")
    (tmp_path / "ci/tools.lock.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        installer["install_tool"]("trivy", tmp_path, archive=archive)
    assert not (tmp_path / ".certweaver/tools/trivy").exists()


def test_plaintext_redirect_is_never_followed():
    with pytest.raises(ValueError, match="HTTPS"):
        installer["HTTPSRedirects"]().redirect_request(
            None, None, 302, "redirect", {}, "http://untrusted.invalid/archive"
        )


def test_checked_in_tool_lock_has_supported_sources_and_hashes():
    for name in ("syft", "trivy", "helm", "cosign", "kube-apiserver", "etcd"):
        assert installer["tool_record"](project_root(), name)["member"] == (
            "linux-amd64/helm"
            if name == "helm"
            else "etcd-v3.6.8-linux-amd64/etcd"
            if name == "etcd"
            else name
        )


@pytest.mark.parametrize("name", ["kube-apiserver", "etcd"])
@pytest.mark.parametrize(
    "change",
    [None, "url", "query", "member", "format", "version", "archive-pin", "binary-pin", "empty"],
)
def test_control_plane_tools_require_exact_sources_members_and_both_pins(tmp_path, name, change):
    content = b"synthetic control-plane binary; never executed"
    payload = tmp_path / "payload"
    version = "v1.36.5" if name == "kube-apiserver" else "v3.6.8"
    member = name if name == "kube-apiserver" else f"etcd-{version}-linux-amd64/etcd"
    if name == "kube-apiserver":
        payload.write_bytes(content)
        url = f"https://dl.k8s.io/release/{version}/bin/linux/amd64/kube-apiserver"
    else:
        with tarfile.open(payload, "w:gz") as archive:
            item = tarfile.TarInfo(member)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
        url = f"https://github.com/etcd-io/etcd/releases/download/{version}/etcd-{version}-linux-amd64.tar.gz"
    record = {
        "repository": installer["REPOSITORIES"][name],
        "version": version,
        "member": member,
        "url": url,
        "format": "raw" if name == "kube-apiserver" else "tar.gz",
        "archiveSha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
        "executableSha256": hashlib.sha256(content).hexdigest(),
    }
    if change == "url":
        record["url"] = "https://untrusted.invalid/control-plane"
    elif change == "query":
        record["url"] += "?unapproved=true"
    elif change == "member":
        record["member"] = "unapproved"
    elif change == "format":
        record["format"] = "tar.gz" if name == "kube-apiserver" else "raw"
    elif change == "version":
        record["version"] = "latest"
    elif change == "archive-pin":
        record["archiveSha256"] = "0" * 64
    elif change == "binary-pin":
        record["executableSha256"] = "0" * 64
    elif change == "empty":
        payload.write_bytes(b"")
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci/tools.lock.json").write_text(
        json.dumps({"schemaVersion": 1, "platform": "linux-amd64", "tools": {name: record}}),
        encoding="utf-8",
    )
    if change is not None:
        with pytest.raises((ValueError, tarfile.TarError)):
            installer["install_tool"](name, tmp_path, archive=payload)
        assert not (tmp_path / ".certweaver/tools" / name).exists()
    else:
        target = installer["install_tool"](name, tmp_path, archive=payload)
        assert target.read_bytes() == content
        assert installer["install_tool"](name, tmp_path) == target
        target.write_bytes(b"tampered cache")
        with pytest.raises(ValueError, match="unexpected type or digest"):
            installer["install_tool"](name, tmp_path)


@pytest.mark.parametrize("change", [None, "format", "source", "digest", "bound", "empty"])
def test_raw_cosign_payload_preserves_pins_and_limits(tmp_path, monkeypatch, change):
    payload = tmp_path / "cosign-linux-amd64"
    content = b"synthetic raw executable; never executed"
    payload.write_bytes(content if change != "empty" else b"")
    checksum = hashlib.sha256(payload.read_bytes()).hexdigest()
    record = {
        "repository": "sigstore/cosign",
        "member": "cosign",
        "format": "raw",
        "version": "v3.1.4",
        "archiveSha256": checksum,
        "executableSha256": checksum,
        "url": "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64",
    }
    if change == "format":
        record["format"] = "tar.gz"
    elif change == "source":
        record["url"] += ".unapproved"
    elif change == "digest":
        record["executableSha256"] = "0" * 64
    elif change == "bound":
        monkeypatch.setitem(installer["install_tool"].__globals__, "MAX_EXECUTABLE_BYTES", 3)
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci/tools.lock.json").write_text(
        json.dumps({"schemaVersion": 1, "platform": "linux-amd64", "tools": {"cosign": record}}),
        encoding="utf-8",
    )
    if change is not None:
        with pytest.raises(ValueError):
            installer["install_tool"]("cosign", tmp_path, archive=payload)
        assert not (tmp_path / ".certweaver/tools/cosign").exists()
    else:
        installed = installer["install_tool"]("cosign", tmp_path, archive=payload)
        assert installed.read_bytes() == content
        receipt = json.loads(installed.with_name("cosign.receipt.json").read_text())
        assert receipt["archiveVerifiedThisRun"] and receipt["format"] == "raw"
        assert installer["install_tool"]("cosign", tmp_path) == installed


def test_executable_size_bound_is_enforced_before_installation(tmp_path, monkeypatch):
    archive, _ = fixture_tool(tmp_path)
    monkeypatch.setitem(installer["install_tool"].__globals__, "MAX_EXECUTABLE_BYTES", 5)
    with pytest.raises(ValueError, match="bounded regular executable"):
        installer["install_tool"]("trivy", tmp_path, archive=archive)
    assert not (tmp_path / ".certweaver/tools/trivy").exists()


@pytest.mark.parametrize("change", ["valid", "source", "member"])
def test_helm_tool_uses_its_exact_release_path_and_nested_executable(tmp_path, change):
    archive, manifest = fixture_tool(tmp_path)
    content = b"synthetic Helm executable; never run"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("linux-amd64/helm")
        member.size = len(content)
        bundle.addfile(member, io.BytesIO(content))
    record = {
        "repository": "helm/helm",
        "version": "v3.21.2",
        "url": "https://get.helm.sh/helm-v3.21.2-linux-amd64.tar.gz",
        "member": "linux-amd64/helm",
        "archiveSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "executableSha256": hashlib.sha256(content).hexdigest(),
    }
    if change == "source":
        record["url"] = "https://github.com/helm/helm/releases/download/v3.21.2/fixture.tar.gz"
    elif change == "member":
        record["member"] = "helm"
    manifest["tools"] = {"helm": record}
    (tmp_path / "ci/tools.lock.json").write_text(json.dumps(manifest))
    if change == "valid":
        assert installer["install_tool"]("helm", tmp_path, archive=archive).read_bytes() == content
    else:
        with pytest.raises(ValueError):
            installer["install_tool"]("helm", tmp_path, archive=archive)
        assert not (tmp_path / ".certweaver/tools/helm").exists()
