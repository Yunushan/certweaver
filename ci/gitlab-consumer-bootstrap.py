"""Inline in GitLab CI: downloaded artifacts are data, never verification code.

The workflow guard compares this canonical source with the exact inline block.
GitLab executes that block from its compiled pipeline, with GIT_STRATEGY=empty.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse


def main():
    commit = os.environ.get("CI_COMMIT_SHA", "")
    project = os.environ.get("CI_PROJECT_PATH", "")
    source_url = os.environ.get("CI_REPOSITORY_URL", "")
    parsed = urlparse(source_url)
    if (
        not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit)
        or os.environ.get("CI_SERVER_URL") != "https://gitlab.com"
        or parsed.scheme != "https"
        or parsed.hostname != "gitlab.com"
        or parsed.port
        or parsed.path != "/" + project + ".git"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid trusted consumer source context")
    candidate = Path(os.environ["CI_PROJECT_DIR"]).absolute()
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError("Invalid candidate data directory")
    with tempfile.TemporaryDirectory(prefix="certweaver-gitlab-consumer-", dir="/tmp") as temporary:
        work = Path(temporary)
        home, source, environment = work / "home", work / "source", work / "environment"
        home.mkdir(mode=0o700)
        clean = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "PIP_CONFIG_FILE": "/dev/null",
            "PYTHONNOUSERSITE": "1",
        }

        def run(arguments, cwd=work):
            result = subprocess.run(
                arguments, cwd=cwd, env=clean, capture_output=True, timeout=600, check=False
            )
            if result.returncode:
                # Clone arguments can contain the ephemeral job token. Never
                # forward commands, stderr or arbitrary data to the CI trace.
                raise ValueError("Trusted consumer bootstrap stage failed")

        run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--no-checkout",
                "--no-recurse-submodules",
                source_url,
                str(source),
            ]
        )
        run(["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", commit], source)
        run([sys.executable, "-I", "-m", "venv", str(environment)])
        python = str(environment / "bin/python")
        run(
            [python, "-I", str(source / "scripts/install-python-deps.py"), "build", "--project"],
            source,
        )
        run([python, "-I", str(source / "scripts/install-ci-tool.py"), "cosign"], source)
        output = candidate / "release-intake"
        output.mkdir(mode=0o700, exist_ok=False)
        run(
            [
                python,
                "-I",
                str(source / "scripts/gitlab-release.py"),
                "verify",
                str(candidate),
                "--cosign",
                str(source / ".certweaver/tools/cosign"),
                "--project-url",
                os.environ["CI_PROJECT_URL"],
                "--project-id",
                os.environ["CI_PROJECT_ID"],
                "--tag",
                os.environ["CI_COMMIT_TAG"],
                "--commit",
                commit,
                "--output",
                str(output / "verified.json"),
            ],
            source,
        )
    print(
        "Independent consumer process verified GitLab release intake; "
        "production approval not inferred"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("ERROR: Trusted GitLab consumer bootstrap failed (" + type(exc).__name__ + ")")
        raise SystemExit(1) from exc
