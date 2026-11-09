from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from certweaver import cli, controller
from certweaver.errors import ConfigurationError
from certweaver.registry import project_root


def configuration():
    return {"spec": {"mode": "windows", "platform": {"nodes": [{"name": "target"}]}}}


def output(python):
    return {
        "schemaVersion": 1,
        "python": str(python),
        "platform": "linux",
        "available": {"winrm": True, "ntlm": True, "kerberos": False, "credssp": False},
    }


@pytest.mark.parametrize("method", ["ntlm", "basic", "plaintext", "ssl", "certificate"])
def test_probe_selects_ansible_reported_python_and_preserves_environment(
    tmp_path, monkeypatch, method
):
    python = tmp_path / "controller environment" / "python"
    python.parent.mkdir()
    python.touch()
    data = configuration()
    data["spec"]["platform"]["nodes"][0]["winrmTransport"] = method
    environment = {"ANSIBLE_CONFIG": "/reviewed/ansible.cfg", "PATH": "/controller/bin"}
    calls = []

    def run(command, **kwargs):
        assert kwargs["env"] is environment and kwargs["timeout"] == 20
        assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["stderr"] is subprocess.DEVNULL
        assert kwargs["check"] is False
        calls.append(command)
        text = (
            f"ansible-playbook [core 2.21.5]\n  python version = 3.14.4 (build) [GCC] ({python})\n"
            if len(calls) == 1
            else json.dumps(output(python))
        )
        kwargs["stdout"].write(text.encode())
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(controller.subprocess, "run", run)
    report = controller.probe_windows_controller(data, "/selected/ansible-playbook", environment)
    assert calls[0] == ["/selected/ansible-playbook", "--version"]
    assert calls[1] == [str(python), "-I", "-c", controller._PROBE]
    assert str(python) != sys.executable
    assert report == {"Ansible controller Python": str(python), "WinRM methods": method}


def test_authentication_selection_preserves_declared_fallback_requirements():
    data = configuration()
    data["spec"]["platform"]["nodes"] = [
        {"winrmTransport": "kerberos, ntlm"},
        {"connection": "ansible.builtin.winrm", "winrmTransport": "credssp"},
        {"connection": "ssh", "winrmTransport": "ignored-custom-method"},
    ]
    original = copy.deepcopy(data)
    assert controller.windows_auth_methods(data) == ("credssp", "kerberos", "ntlm")
    assert data == original
    data["spec"]["mode"] = "raw"
    assert controller.windows_auth_methods(data) == ()


@pytest.mark.parametrize("value", ["", "ntlm,", "kerberos,,ntlm", "unknown", "NTLM"])
def test_unknown_or_empty_authentication_methods_fail_without_running_tools(monkeypatch, value):
    data = configuration()
    data["spec"]["platform"]["nodes"][0]["winrmTransport"] = value
    monkeypatch.setattr(controller.subprocess, "run", lambda *a, **kw: pytest.fail("Tool executed"))
    with pytest.raises(ConfigurationError, match="Unsupported WinRM"):
        controller.probe_windows_controller(data, "/unused", {})


def test_other_modes_and_connections_do_not_probe_winrm(monkeypatch):
    monkeypatch.setattr(controller.subprocess, "run", lambda *a, **kw: pytest.fail("Tool executed"))
    data = configuration()
    data["spec"]["platform"]["nodes"][0]["connection"] = "ssh"
    assert controller.probe_windows_controller(data, "/unused", {}) == {}
    data["spec"]["mode"] = "raw"
    assert controller.probe_windows_controller(data, "/unused", {}) == {}


@pytest.mark.parametrize(
    "text",
    [
        "private-canary",
        "python version = 3.14.4 (relative/python)",
        "python version = 3.14.4 (/nonexistent/certweaver/python)",
        "python version = 3.14.4 (/invalid\x1b/python)",
        "python version = 3.14.4 (/invalid\x7f/python)",
        "python version = 3.14.4 (/invalid\n/python)",
    ],
)
def test_unusable_interpreter_reports_fail_without_reflecting_output(text):
    with pytest.raises(ConfigurationError) as error:
        controller._interpreter(text)
    assert "private-canary" not in str(error.value)


def test_ambiguous_interpreter_reports_fail_even_when_both_paths_exist():
    text = f"python version = 3.14.4 ({sys.executable})\n" * 2
    with pytest.raises(ConfigurationError, match="unambiguous"):
        controller._interpreter(text)


@pytest.mark.parametrize("failure", ["exit", "empty", "large", "encoding", "os-error", "timeout"])
def test_probe_process_failures_are_bounded_and_sanitized(monkeypatch, failure):
    def run(command, **kwargs):
        if failure == "os-error":
            raise OSError("private-canary")
        if failure == "timeout":
            raise subprocess.TimeoutExpired("private-canary", 20)
        raw = (
            b""
            if failure == "empty"
            else b"x" * (controller._LIMIT + 1)
            if failure == "large"
            else b"\xff"
            if failure == "encoding"
            else b"private-canary"
        )
        kwargs["stdout"].write(raw)
        return subprocess.CompletedProcess(command, 1 if failure == "exit" else 0)

    monkeypatch.setattr(controller.subprocess, "run", run)
    with pytest.raises(ConfigurationError) as error:
        controller._capture(["/synthetic"], {}, "version")
    assert "private-canary" not in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        "bad-json",
        "list",
        "schema-bool",
        "schema-version",
        "extra",
        "missing",
        "python",
        "platform",
        "flags-list",
        "flags-extra",
        "flag-string",
        "duplicate",
    ],
)
def test_malformed_or_wrong_runtime_probe_cannot_pass(monkeypatch, change):
    python = Path(sys.executable)
    record = output(python)
    if change == "schema-bool":
        record["schemaVersion"] = True
    elif change == "schema-version":
        record["schemaVersion"] = 2
    elif change == "extra":
        record["extra"] = "private-canary"
    elif change == "missing":
        record.pop("available")
    elif change == "python":
        record["python"] = "/other/python"
    elif change == "platform":
        record["platform"] = "win32"
    elif change == "flags-list":
        record["available"] = []
    elif change == "flags-extra":
        record["available"]["other"] = True
    elif change == "flag-string":
        record["available"]["winrm"] = "true"
    raw = (
        "private-canary"
        if change == "bad-json"
        else "[]"
        if change == "list"
        else '{"schemaVersion":1,"schemaVersion":1}'
        if change == "duplicate"
        else json.dumps(record)
    )
    responses = iter([f"python version = 3.14.4 ({python})\n", raw])
    monkeypatch.setattr(controller, "_capture", lambda *a: next(responses))
    with pytest.raises(ConfigurationError) as error:
        controller.probe_windows_controller(configuration(), "/synthetic", {})
    assert "private-canary" not in str(error.value)


@pytest.mark.parametrize("missing", ["winrm", "ntlm", "kerberos", "credssp"])
def test_missing_libraries_in_selected_controller_fail_without_using_cli_environment(
    monkeypatch, missing
):
    python = Path(sys.executable)
    record = output(python)
    method = "ntlm" if missing == "winrm" else missing
    record["available"][missing] = False
    data = configuration()
    data["spec"]["platform"]["nodes"][0]["winrmTransport"] = method
    responses = iter([f"python version = 3.14.4 ({python})\n", json.dumps(record)])
    monkeypatch.setattr(controller, "_capture", lambda *a: next(responses))
    with pytest.raises(
        ConfigurationError, match="missing " + ("pywinrm" if missing == "winrm" else missing)
    ):
        controller.probe_windows_controller(data, "/synthetic", {})


def cli_config(tmp_path):
    data = cli.load_config(project_root() / "examples/configs/windows.yml")
    data.pop("__source_path__")
    data["spec"]["adapters"]["enabled"] = ["posh-acme"]
    data["spec"]["adapters"]["versions"]["posh_acme"] = "4.2.1"
    path = tmp_path / "windows.yml"
    path.write_text(yaml.safe_dump(data))
    return path


@pytest.mark.parametrize("command", ["doctor", "deploy"])
def test_cli_rejects_missing_controller_dependencies_before_inventory_or_target_execution(
    tmp_path, monkeypatch, capsys, command
):
    config = cli_config(tmp_path)
    inventory = tmp_path / "inventory.yml"
    inventory.write_text("protected-existing-inventory\n")
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/selected/ansible-playbook")

    def probe(*args):
        raise ConfigurationError("Ansible controller is missing pywinrm")

    monkeypatch.setattr(cli, "probe_windows_controller", probe)
    monkeypatch.setattr(
        cli.subprocess, "run", lambda *a, **kw: pytest.fail("Target command executed")
    )
    args = [command, "-c", str(config)] + (
        ["-i", str(inventory), "--check"] if command == "deploy" else []
    )
    monkeypatch.setattr(sys, "argv", ["certweaver", *args])
    with pytest.raises(SystemExit) as status:
        cli.main()
    assert status.value.code == 2
    assert inventory.read_text() == "protected-existing-inventory\n"
    captured = capsys.readouterr()
    assert "missing pywinrm" in captured.out + captured.err


def test_windows_deploy_uses_the_exact_executable_and_environment_that_passed_preflight(
    tmp_path, monkeypatch
):
    config = cli_config(tmp_path)
    inventory = tmp_path / "inventory.yml"
    selected = str(tmp_path / "selected-ansible-playbook")
    observations = []
    monkeypatch.setattr(cli.shutil, "which", lambda _: selected)

    def probe(data, executable, environment):
        assert not inventory.exists() and executable == selected
        observations.append(environment)
        return {"Ansible controller Python": "/selected/python", "WinRM methods": "ntlm"}

    def run(command, *, check, env):
        assert command[0] == selected and inventory.is_file()
        assert observations == [env] and observations[0] is env and check is False
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli, "probe_windows_controller", probe)
    monkeypatch.setattr(cli.subprocess, "run", run)
    args = cli.build_parser().parse_args(
        ["deploy", "-c", str(config), "-i", str(inventory), "--check"]
    )
    assert cli.command_deploy(args) == 0


def test_doctor_reports_the_verified_controller_interpreter(tmp_path, monkeypatch, capsys):
    config = cli_config(tmp_path)
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/selected/ansible-playbook")
    monkeypatch.setattr(
        cli,
        "probe_windows_controller",
        lambda *a: {"Ansible controller Python": "/selected/python", "WinRM methods": "ntlm"},
    )
    assert cli.command_doctor(cli.build_parser().parse_args(["doctor", "-c", str(config)])) == 0
    assert "/selected/python" in capsys.readouterr().out
