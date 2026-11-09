"""Read-only dependency checks in the selected Ansible controller's interpreter."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from .errors import ConfigurationError

_LIMIT = 64 * 1024
_AUTH = {"ntlm", "kerberos", "credssp", "basic", "plaintext", "ssl", "certificate"}
_PROBE = """
import json, sys
available = dict(winrm=False, ntlm=False, kerberos=False, credssp=False)
try:
    from ansible.plugins.connection import winrm as connection
    from winrm import transport
    available.update(winrm=connection.HAS_WINRM is True,
                     ntlm=transport.HAVE_NTLM is True,
                     kerberos=transport.HAVE_KERBEROS is True,
                     credssp=transport.HAVE_CREDSSP is True)
except Exception:
    pass
print(json.dumps(dict(schemaVersion=1, python=sys.executable,
                     platform=sys.platform, available=available)))
"""


def windows_auth_methods(config: dict) -> tuple[str, ...]:
    """Require every explicitly selected WinRM method; never silently fall back."""
    methods = set()
    if config["spec"]["mode"] == "windows":
        for node in config["spec"]["platform"]["nodes"]:
            if node.get("connection", "winrm") not in {"winrm", "ansible.builtin.winrm"}:
                continue
            selected = [name.strip() for name in node.get("winrmTransport", "ntlm").split(",")]
            if not selected or any(name not in _AUTH for name in selected):
                raise ConfigurationError(
                    "Unsupported WinRM authentication method in deployment nodes"
                )
            methods.update(selected)
    return tuple(sorted(methods))


def _capture(command: list[str], environment: dict[str, str], label: str) -> str:
    # Keep diagnostic output out of memory until it has passed a size bound;
    # never reflect third-party stderr or exception text into operator output.
    try:
        with tempfile.TemporaryFile() as stream:
            result = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=20,
            )
            stream.seek(0)
            output = stream.read(_LIMIT + 1)
        if result.returncode or not output or len(output) > _LIMIT:
            raise ConfigurationError(f"Ansible controller {label} returned unusable output")
        return output.decode("utf-8")
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise ConfigurationError(
            f"Cannot inspect Ansible controller {label}; verify the selected Ansible environment"
        ) from None


def _interpreter(version: str) -> Path:
    matches = re.findall(r"^\s*python version = .+ \(([^\r\n]+)\)\s*$", version, re.MULTILINE)
    if len(matches) != 1:
        raise ConfigurationError("Ansible must report one unambiguous controller Python path")
    value = matches[0]
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigurationError("Ansible reported an invalid controller Python path")
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ConfigurationError(
            "Ansible controller Python is unavailable here; "
            "run CertWeaver in its controller environment"
        )
    # Preserve the venv executable spelling. Resolving its symlink to the base
    # interpreter would discard that environment's installed dependencies.
    return path


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate probe key")
        result[key] = value
    return result


def probe_windows_controller(
    config: dict, executable: str, environment: dict[str, str]
) -> dict[str, str]:
    """Inspect libraries locally, with no inventory, credentials or host contact."""
    methods = windows_auth_methods(config)
    if not methods:
        return {}
    python = _interpreter(_capture([executable, "--version"], environment, "version"))
    raw = _capture([str(python), "-I", "-c", _PROBE], environment, "library probe")
    try:
        report = json.loads(raw, object_pairs_hook=_unique)
        available = report["available"]
        if (
            type(report["schemaVersion"]) is not int
            or report["schemaVersion"] != 1
            or set(report) != {"schemaVersion", "python", "platform", "available"}
            or report["python"] != str(python)
            or report["platform"] != "linux"
            or not isinstance(available, dict)
            or set(available) != {"winrm", "ntlm", "kerberos", "credssp"}
            or any(type(value) is not bool for value in available.values())
        ):
            raise ValueError("Invalid controller probe")
    except (ValueError, KeyError, TypeError):
        raise ConfigurationError(
            "Cannot verify the selected controller runtime; "
            "Windows targets require a Linux Ansible controller"
        ) from None
    missing = ["pywinrm"] if not available["winrm"] else []
    missing.extend(method for method in methods if method in available and not available[method])
    if missing:
        raise ConfigurationError(
            "Ansible controller is missing "
            + ", ".join(missing)
            + "; install the source-bound dev profile in its reported Python environment. "
            "Kerberos/CredSSP also need their reviewed optional prerequisites."
        )
    return {"Ansible controller Python": str(python), "WinRM methods": ", ".join(methods)}
