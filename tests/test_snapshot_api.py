from __future__ import annotations

import json
import runpy
import shutil
import subprocess

import pytest
import yaml

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/check-snapshot-api.py"))


@pytest.mark.parametrize("change", [None, "rke2-patch", "k3s-patch", "api-source", "etcd-source"])
def test_real_api_fixture_matches_the_selected_patch_and_reviewed_sources(tmp_path, change):
    root = project_root()
    for directory in ["scripts", "ci", "config"]:
        shutil.copytree(root / directory, tmp_path / directory)
    if change in {"rke2-patch", "k3s-patch"}:
        path = tmp_path / "config/versions.yml"
        record = yaml.safe_load(path.read_text(encoding="utf-8"))
        record[change.split("-")[0]] = "v1.35.0+fixture"
        path.write_text(yaml.safe_dump(record), encoding="utf-8")
    elif change in {"api-source", "etcd-source"}:
        path = tmp_path / "ci/tools.lock.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["tools"]["kube-apiserver" if change == "api-source" else "etcd"]["url"] = (
            "https://untrusted.invalid/binary"
        )
        path.write_text(json.dumps(record), encoding="utf-8")
    if change is None:
        assert set(tools["guard"](tmp_path)) == {"kube-apiserver", "etcd"}
    else:
        with pytest.raises(ValueError):
            tools["guard"](tmp_path)


@pytest.mark.parametrize("state", ["finished", "running", "timeout"])
def test_owned_process_cleanup_handles_finished_graceful_and_forced_exit(state):
    class Process:
        returncode = 0 if state == "finished" else None
        terminated = False
        killed = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            if state == "timeout" and not self.killed:
                raise subprocess.TimeoutExpired("owned-fixture", timeout)
            self.returncode = 0

        def kill(self):
            self.killed = True

    process = Process()
    tools["stop_process"](process)
    assert process.poll() == 0
    assert process.terminated == (state != "finished")
    assert process.killed == (state == "timeout")


@pytest.mark.parametrize("change", ["github-missing", "github-conditional", "gitlab-missing"])
def test_real_api_gate_is_required_in_both_ci_providers(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github", tmp_path / ".github")
    shutil.copytree(root / "ci", tmp_path / "ci")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    workflows = runpy.run_path(str(root / "scripts/check-release-workflows.py"))
    assert workflows["check_workflows"](tmp_path) == []
    if change.startswith("github"):
        path = tmp_path / ".github/workflows/ci.yml"
        document = workflows["load"](path)
        steps = document["jobs"]["test"]["steps"]
        selected = next(s for s in steps if "check-snapshot-api.py" in s.get("run", ""))
        if change == "github-missing":
            steps.remove(selected)
        else:
            selected["if"] = "false"
    else:
        path = tmp_path / ".gitlab-ci.yml"
        document = workflows["load"](path)
        document["lint-test"]["script"] = [
            s for s in document["lint-test"]["script"] if "check-snapshot-api.py" not in s
        ]
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert any("check-snapshot-api.py" in e for e in workflows["check_workflows"](tmp_path))
