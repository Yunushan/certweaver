"""Private credential destinations and source export contracts; no real credentials."""

import hashlib
import os
import runpy
import shutil

import pytest
import yaml

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root
from certweaver.render import execution_plan, inventory_from_config

tools = runpy.run_path(str(project_root() / "roles/cluster_addons/files/protect-kubeconfig"))
export_tools = runpy.run_path(str(project_root() / "scripts/check-kubeconfig-export.py"))
endpoint_tools = runpy.run_path(str(project_root() / "scripts/check-operator-endpoint.py"))


@pytest.mark.parametrize("mode", ["rke2-ha", "k3s-ha", "existing-kubernetes"])
def test_explicit_export_binds_name_destination_and_privileged_plan(mode):
    filename = (
        "config/certweaver.example.yml" if mode == "rke2-ha" else f"examples/configs/{mode}.yml"
    )
    config = load_config(project_root() / filename)
    config["spec"]["platform"].update(fetchKubeconfig=True, kubeconfigOutput="~/private/kubeconfig")
    assert validate_config(config).ok
    variables = inventory_from_config(config)["all"]["vars"]
    assert variables["certweaver_deployment_name"] == config["metadata"]["name"]
    assert variables["certweaver_fetch_kubeconfig"] is True
    assert variables["certweaver_local_kubeconfig_path"] == "~/private/kubeconfig"
    plan = "\n".join(execution_plan(config))
    export_line = next(line for line in plan.splitlines() if line.startswith("Export "))
    assert "administrative kubeconfig" in export_line and "0600" in export_line
    assert "sanitized" not in export_line


@pytest.mark.parametrize("mode", ["standalone", "docker", "raw", "windows"])
def test_export_is_not_silently_accepted_for_non_kubernetes_modes(mode):
    config = load_config(project_root() / f"examples/configs/{mode}.yml")
    config["spec"]["platform"]["fetchKubeconfig"] = True
    assert any("Kubeconfig export requires" in e for e in validate_config(config).errors)


@pytest.mark.parametrize(
    "path",
    [
        "relative",
        "/tmp/../secret",
        "/tmp/./secret",
        "/tmp//secret",
        "/tmp/",
        "~other/secret",
        "C:\\private",
        "/tmp/{{bad}}",
        "/tmp/\nsecret",
        "/tmp/\0secret",
    ],
)
def test_destination_config_requires_a_literal_controller_file_path(path):
    config = load_config(project_root() / "config/certweaver.example.yml")
    config["spec"]["platform"].update(fetchKubeconfig=True, kubeconfigOutput=path)
    assert any("kubeconfigOutput" in e for e in validate_config(config).errors)


@pytest.mark.skipif(os.name != "posix", reason="Private POSIX controller filesystem contract")
def test_controller_destination_is_read_only_in_preflight_and_private_when_prepared(tmp_path):
    target = tmp_path / "new" / "profile" / "kubeconfig"
    first = tools["destination"](str(target))
    assert not first["parentReady"] and not target.parent.exists()
    ready = tools["destination"](str(target), create=True)
    assert ready["changed"] and target.parent.stat().st_mode & 0o777 == 0o700
    assert not target.exists()
    assert not tools["destination"](str(target), create=True)["changed"]
    payload = b"synthetic-private-credential\n{{ 7*7 }}\n"
    target.write_bytes(payload)
    target.chmod(0o600)
    assert tools["destination"](str(target), expected=hashlib.sha256(payload).hexdigest())[
        "parentReady"
    ]
    with pytest.raises(ValueError, match="bytes differ"):
        tools["destination"](str(target), expected="0" * 64)
    assert target.read_bytes() == payload


@pytest.mark.skipif(os.name != "posix", reason="Private POSIX controller filesystem contract")
@pytest.mark.parametrize(
    "change",
    [
        "parent-link",
        "file-link",
        "hardlink",
        "public-parent",
        "writable-ancestor",
        "public-file",
        "directory",
        "oversize",
    ],
)
def test_unsafe_controller_destinations_are_rejected_without_changing_other_files(tmp_path, change):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    target = parent / "kubeconfig"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"original unrelated file")
    sentinel.chmod(0o600)
    if change == "parent-link":
        parent.rmdir()
        parent.symlink_to(tmp_path, target_is_directory=True)
    elif change == "file-link":
        target.symlink_to(sentinel)
    elif change == "hardlink":
        os.link(sentinel, target)
    elif change == "public-parent":
        parent.chmod(0o755)
    elif change == "writable-ancestor":
        tmp_path.chmod(0o777)
    elif change == "directory":
        target.mkdir()
    else:
        target.write_bytes(b"x" * (tools["MAX_BYTES"] + 1) if change == "oversize" else b"private")
        target.chmod(0o600 if change == "oversize" else 0o644)
    try:
        with pytest.raises((OSError, ValueError)):
            tools["destination"](str(target), create=True)
        assert sentinel.read_bytes() == b"original unrelated file"
    finally:
        tmp_path.chmod(0o700)


def test_helper_errors_never_echo_supplied_values(capsys):
    canary = "synthetic-private-path-canary"
    assert tools["main"](["check", canary]) == 1
    assert canary not in capsys.readouterr().out
    with pytest.raises(ValueError):
        tools["destination"]("relative/credential")


@pytest.mark.parametrize(
    "change",
    [
        "preflight-order",
        "preflight-opt-in",
        "export-opt-in",
        "raw-fetch",
        "logging",
        "diff",
        "check-mode",
        "child-logging",
        "debug",
        "controller-escalation",
        "controller-connection",
        "source-link",
        "source-mode",
        "transfer-digest",
        "publish-content",
        "publish-destination",
        "publish-mode",
        "publish-link",
        "unsafe-writes",
        "backup",
        "rotation",
        "final-digest",
        "credential-cleanup",
    ],
)
def test_export_contract_rejects_guard_regressions(tmp_path, change):
    role = tmp_path / "roles/cluster_addons"
    shutil.copytree(project_root() / "roles/cluster_addons", role)
    guard = export_tools["guard"]
    guard(tmp_path)
    main_path = role / "tasks/main.yml"
    pre_path = role / "tasks/_kubeconfig_preflight.yml"
    export_path = role / "tasks/_export_kubeconfig.yml"
    main = yaml.safe_load(main_path.read_text())
    pre = yaml.safe_load(pre_path.read_text())
    export = yaml.safe_load(export_path.read_text())
    block = export[0]
    tasks = block["block"]
    publish = tasks[5]["ansible.builtin.copy"]
    if change == "preflight-order":
        main[0], main[1] = main[1], main[0]
    elif change == "preflight-opt-in":
        main[0]["when"] = True
    elif change == "export-opt-in":
        next(t for t in main if t.get("ansible.builtin.include_tasks") == "_export_kubeconfig.yml")[
            "when"
        ] = True
    elif change == "raw-fetch":
        main.append({"ansible.builtin.fetch": {"src": "/credential"}})
    elif change in {"logging", "diff", "check-mode"}:
        block[{"logging": "no_log", "diff": "diff", "check-mode": "when"}[change]] = (
            change != "logging"
        )
    elif change == "child-logging":
        tasks[3]["no_log"] = False
    elif change == "debug":
        pre[0]["ansible.builtin.assert"]["that"].pop()
    elif change == "controller-escalation":
        tasks[5]["become"] = True
    elif change == "controller-connection":
        tasks[5]["vars"]["ansible_connection"] = "ssh"
    elif change == "source-link":
        tasks[1]["ansible.builtin.stat"]["follow"] = True
    elif change == "source-mode":
        tasks[2]["ansible.builtin.assert"]["that"].pop(4)
    elif change == "transfer-digest":
        tasks[4]["ansible.builtin.assert"]["that"][-1] = "true"
    elif change == "final-digest":
        tasks[6]["ansible.builtin.command"]["argv"][-1] = "0" * 64
    elif change == "credential-cleanup":
        block["always"][0]["ansible.builtin.set_fact"]["cacheable"] = True
    else:
        field, value = {
            "publish-content": ("content", "wrong bytes"),
            "publish-destination": ("dest", "/tmp/unprotected"),
            "publish-mode": ("mode", "0644"),
            "publish-link": ("follow", True),
            "unsafe-writes": ("unsafe_writes", True),
            "backup": ("backup", True),
            "rotation": ("force", False),
        }[change]
        publish[field] = value
    for path, document in [(main_path, main), (pre_path, pre), (export_path, export)]:
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises((ValueError, KeyError, IndexError)):
        guard(tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        "ordering",
        "mode",
        "direct-copy",
        "logging",
        "child-logging",
        "diff",
        "check-mode",
        "debug",
        "raw-context",
        "live-file-update",
        "other-cluster",
        "tls-bypass",
        "proxy",
        "public-mode",
        "unsafe-write",
        "backup",
        "postcheck",
        "cleanup",
        "source-alias",
    ],
)
def test_operator_preparation_guard_rejects_targeting_and_publication_regressions(tmp_path, change):
    role = tmp_path / "roles/cluster_addons"
    shutil.copytree(project_root() / "roles/cluster_addons", role)
    guard = endpoint_tools["guard"]
    guard(tmp_path)
    main_path = role / "tasks/main.yml"
    path = role / "tasks/_configure_operator_endpoint.yml"
    main = yaml.safe_load(main_path.read_text())
    document = yaml.safe_load(path.read_text())
    block = document[1]
    tasks = block["block"]
    include = next(
        t
        for t in main
        if t.get("ansible.builtin.include_tasks") == "_configure_operator_endpoint.yml"
    )
    views = [t for t in tasks if "context" in t["name"] and t["name"].startswith("Inspect")]
    update = next(t for t in tasks if t["name"].startswith("Set the selected"))
    policy = next(t for t in tasks if t["name"].startswith("Require one selected"))
    if change == "ordering":
        main.remove(include)
        main.append(include)
    elif change == "mode":
        include["when"] = True
    elif change == "direct-copy":
        next(t for t in main if t["name"] == "Copy cluster kubeconfig into the operator path")[
            "when"
        ].pop(0)
    elif change in {"logging", "diff", "check-mode"}:
        block[{"logging": "no_log", "diff": "diff", "check-mode": "when"}[change]] = (
            change != "logging"
        )
    elif change == "child-logging":
        update["no_log"] = False
    elif change == "debug":
        document[0]["ansible.builtin.assert"]["that"].pop()
    elif change == "raw-context":
        views[0]["ansible.builtin.command"]["argv"].append("--raw")
    elif change == "live-file-update":
        update["ansible.builtin.command"]["argv"][1] = (
            "--kubeconfig={{ certweaver_kubeconfig_path }}"
        )
    elif change == "other-cluster":
        update["ansible.builtin.command"]["argv"][4] = "unselected"
    elif change in {"tls-bypass", "proxy"}:
        policy["ansible.builtin.assert"]["that"].pop(3 if change == "tls-bypass" else 4)
    elif change == "postcheck":
        tasks[-2]["ansible.builtin.assert"]["that"].pop()
    elif change == "cleanup":
        block["always"][0]["when"] = False
    elif change == "source-alias":
        next(t for t in tasks if t["name"].startswith("Require an absent"))[
            "ansible.builtin.assert"
        ]["that"].pop()
    else:
        field, value = {
            "public-mode": ("mode", "0644"),
            "unsafe-write": ("unsafe_writes", True),
            "backup": ("backup", True),
        }[change]
        tasks[-1]["ansible.builtin.copy"][field] = value
    main_path.write_text(yaml.safe_dump(main), encoding="utf-8")
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises((ValueError, KeyError, IndexError, StopIteration)):
        guard(tmp_path)


def test_named_configuration_comparison_preserves_every_field_and_ignores_only_entry_order():
    first = {
        "clusters": [
            {"name": "b", "cluster": {"server": "https://b", "ca": "same"}},
            {"name": "a", "cluster": {"server": "https://a"}},
        ],
        "users": [{"name": "admin", "user": {"token": "synthetic"}}],
        "current-context": "selected",
        "extra": {"preserve": True},
    }
    reordered = {**first, "clusters": list(reversed(first["clusters"]))}
    normalize = endpoint_tools["configuration_by_name"]
    assert normalize(first) == normalize(reordered)
    assert first["clusters"][0]["name"] == "b"
    assert normalize(first)["extra"] == {"preserve": True}


@pytest.mark.parametrize("key", ["clusters", "contexts", "users"])
def test_named_configuration_comparison_rejects_duplicate_names(key):
    with pytest.raises(ValueError, match="Duplicate"):
        endpoint_tools["configuration_by_name"](
            {key: [{"name": "duplicate"}, {"name": "duplicate"}]}
        )


@pytest.mark.parametrize("field", ["trust", "credential"])
def test_named_configuration_comparison_does_not_hide_security_field_changes(field):
    before = {
        "clusters": [{"name": "same", "cluster": {"certificate-authority-data": "original"}}],
        "users": [{"name": "same", "user": {"token": "original"}}],
    }
    after = yaml.safe_load(yaml.safe_dump(before))
    if field == "trust":
        after["clusters"][0]["cluster"]["certificate-authority-data"] = "changed"
    else:
        after["users"][0]["user"]["token"] = "changed"
    normalize = endpoint_tools["configuration_by_name"]
    assert normalize(before) != normalize(after)
