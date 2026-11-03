"""Verify and render the five pinned add-on charts without contacting a cluster."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import tempfile
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

from certweaver.config import load_config, validate_config
from certweaver.render import inventory_from_config


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def template_arguments(task, variables, root):
    """Translate only the deployed chart flags; reject an unhandled change."""
    environment = Environment(undefined=StrictUndefined)
    environment.filters["bool"] = bool
    argv = [
        environment.from_string(str(v)).render(**variables)
        for v in task["ansible.builtin.command"]["argv"]
    ]
    require(argv[1:3] == ["upgrade", "--install"], "Expected a managed chart installation")
    args = ["template", argv[3], argv[4]]
    index = 5
    while index < len(argv):
        flag = argv[index]
        if flag in {"--create-namespace", "--wait"}:
            index += 1
        elif flag == "--timeout":
            index += 2
        elif flag in {"--namespace", "--set", "--values"}:
            require(index + 1 < len(argv), "Chart flag is missing a value")
            value = argv[index + 1]
            if flag == "--values":
                require(value.startswith("/etc/certweaver/kubernetes/"), "Unexpected values source")
                value = str(root / value.removeprefix("/etc/certweaver/"))
            args.extend([flag, value])
            index += 2
        else:
            raise ValueError("Unhandled deployed chart flag: " + flag)
    return args


def inspect_rendered(key, documents):
    require(documents and all(isinstance(d, dict) for d in documents), "Invalid rendered resources")
    forbidden = {
        "extensions/v1beta1",
        "apps/v1beta1",
        "apps/v1beta2",
        "policy/v1beta1",
        "networking.k8s.io/v1beta1",
        "apiextensions.k8s.io/v1beta1",
    }
    require(all(d.get("apiVersion") not in forbidden for d in documents), "Retired API rendered")
    if key == "certManager":
        controller = next(
            d
            for d in documents
            if d["kind"] == "Deployment" and d["metadata"]["name"] == "cert-manager"
        )
        pod = controller["spec"]["template"]["spec"]
        controller_flags = [
            arg for arg in pod["containers"][0]["args"] if arg.startswith("--controllers=")
        ]
        # This exact pinned chart renders the negative selection without '*'.
        # Require its observed value once, so a later override cannot re-enable approval.
        require(
            controller_flags == ["--controllers=-certificaterequests-approver"],
            "Automatic CertificateRequest approval was not disabled",
        )
        require(pod.get("priorityClassName") == "system-cluster-critical", "Priority class lost")
        require(
            not any(
                "serviceaccounts/token" in rule.get("resources", [])
                and "create" in rule.get("verbs", [])
                for d in documents
                if d["kind"] == "Role"
                for rule in d.get("rules", [])
            ),
            "Unexpected controller token-creation Role",
        )
    elif key == "approverPolicy":
        require(any(d["kind"] == "Service" for d in documents), "Approver metrics service missing")
    elif key == "trustManager":
        webhook = next(d for d in documents if d["kind"] == "ValidatingWebhookConfiguration")
        require(all(w["timeoutSeconds"] == 10 for w in webhook["webhooks"]), "Webhook timeout lost")
        deployment = next(d for d in documents if d["kind"] == "Deployment")
        require(
            all(
                container.get("securityContext", {}).get("seccompProfile")
                == {"type": "RuntimeDefault"}
                for container in deployment["spec"]["template"]["spec"]["containers"]
            ),
            "Trust-manager seccomp profile lost",
        )
    elif key == "csiDriver":
        require(any(d["kind"] == "DaemonSet" for d in documents), "CSI node DaemonSet missing")
    elif key == "traefik":
        service = next(
            d for d in documents if d["kind"] == "Service" and d["metadata"]["name"] == "traefik"
        )
        require(service["spec"]["type"] == "NodePort", "Traefik is not a NodePort service")
        require(
            {p["nodePort"] for p in service["spec"]["ports"]} == {30080, 30443},
            "NodePort binding changed",
        )
        deployment = next(d for d in documents if d["kind"] == "Deployment")
        require(deployment["spec"]["replicas"] == 3, "Traefik replica count changed")
    require(
        not any(d["kind"] in {"ServiceMonitor", "PodMonitor"} for d in documents),
        "Fresh-cluster baseline requires an uninstalled monitoring operator",
    )


def verify(root, output, helm, charts, native):
    installer = runpy.run_path(str(root / "scripts/install-ci-tool.py"))
    tool = installer["tool_record"](root, "helm")
    require(
        helm.is_file() and not helm.is_symlink() and digest(helm) == tool["executableSha256"],
        "Helm executable differs from the pinned client",
    )
    config = load_config(root / "config/certweaver.example.yml")
    require(validate_config(config).ok, "Baseline example is invalid")
    versions = yaml.safe_load((root / "config/versions.yml").read_text(encoding="utf-8"))
    require(config["spec"]["versions"] == versions, "Example and baseline versions differ")
    variables = inventory_from_config(config)["all"]["vars"]
    release = versions["rke2"].split("+", 1)[0].removeprefix("v")
    require(re.fullmatch(r"1\.\d+\.\d+", release), "Noncanonical Kubernetes target")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HELM_", "KUBE"))}
    env.update(
        HELM_CONFIG_HOME=str(native / "config"),
        HELM_CACHE_HOME=str(native / "cache"),
        HELM_DATA_HOME=str(native / "data"),
        HELM_PLUGINS=str(native / "plugins"),
        KUBECONFIG="/dev/null",
    )
    (native / "plugins").mkdir()
    tasks = yaml.safe_load(
        (root / "roles/cluster_addons/tasks/main.yml").read_text(encoding="utf-8")
    )
    results = []
    for key, name, task_name, folder in [
        ("certManager", "cert-manager", "Install cert-manager", "cert-manager"),
        (
            "approverPolicy",
            "cert-manager-approver-policy",
            "Install approver-policy",
            "approver-policy",
        ),
        ("trustManager", "trust-manager", "Install trust-manager", "trust-manager"),
        ("csiDriver", "cert-manager-csi-driver", "Install cert-manager CSI Driver", "csi-driver"),
        ("traefik", "traefik", "Install Traefik without independent ACME resolver", "traefik"),
    ]:
        version = versions["traefikChart" if key == "traefik" else key]
        expected = versions["chartChecksums"][key].removeprefix("sha256:")
        require(re.fullmatch(r"[a-f0-9]{64}", expected), "Missing chart archive digest")
        destination = output / key
        destination.mkdir()
        if charts:
            matches = list(charts.rglob(name + "-" + version + ".tgz"))
            require(len(matches) == 1, "Expected one exact local chart archive: " + key)
            archive = matches[0]
        else:
            source = "oci://quay.io/jetstack/charts/" + name
            args = [
                str(helm),
                "pull",
                source,
                "--version",
                version,
                "--destination",
                str(destination),
            ]
            if key == "traefik":
                args = [
                    str(helm),
                    "pull",
                    "traefik",
                    "--version",
                    version,
                    "--repo",
                    "https://traefik.github.io/charts",
                    "--destination",
                    str(destination),
                ]
            pulled = subprocess.run(args, capture_output=True, env=env, timeout=180)
            (destination / "acquisition.log").write_bytes(pulled.stdout + b"\n" + pulled.stderr)
            require(pulled.returncode == 0, "Exact chart acquisition failed: " + key)
            matches = list(destination.glob("*.tgz"))
            require(len(matches) == 1, "Chart acquisition returned an ambiguous archive")
            archive = matches[0]
        require(
            archive.is_file() and not archive.is_symlink() and digest(archive) == expected,
            "Chart archive digest mismatch: " + key,
        )
        metadata = subprocess.run(
            [str(helm), "show", "chart", str(archive)], capture_output=True, env=env, timeout=30
        )
        require(metadata.returncode == 0, "Chart metadata inspection failed")
        chart = yaml.safe_load(metadata.stdout)
        require(chart["name"] == name and chart["version"] == version, "Chart metadata differs")
        (destination / "Chart.yaml").write_bytes(metadata.stdout)
        selected = dict(variables, certweaver_chart_archive_path=str(archive))
        task = next(t for t in tasks if t["name"] == task_name)
        args = template_arguments(task, selected, root)
        # Helm's offline default capabilities do not include this GVK even
        # when --kube-version is set. Declare the target's stable native API;
        # the cert-manager API is supplied by the preceding managed chart.
        args.extend(
            [
                "--kube-version",
                release,
                "--include-crds",
                "--api-versions",
                "cert-manager.io/v1",
                "--api-versions",
                "policy/v1/PodDisruptionBudget",
            ]
        )
        rendered = subprocess.run([str(helm), *args], env=env, capture_output=True, timeout=60)
        (destination / "render.log").write_bytes(rendered.stderr)
        require(rendered.returncode == 0, "Helm values/template validation failed: " + key)
        documents = [d for d in yaml.safe_load_all(rendered.stdout) if d is not None]
        inspect_rendered(key, documents)
        (destination / "rendered.yaml").write_bytes(rendered.stdout)
        results.append(
            {
                "key": key,
                "version": version,
                "archiveSha256": expected,
                "resources": len(documents),
                "renderedSha256": hashlib.sha256(rendered.stdout).hexdigest(),
                "deployedFlagTranslation": args,
                "valuesFile": "kubernetes/" + folder + "/values.yaml",
            }
        )
    record = {
        "scope": (
            "Offline exact-chart schema/render checks only; no API admission, running workload, "
            "image/publisher approval, issuance or supported-platform acceptance"
        ),
        "kubernetesVersion": release,
        "declaredOfflineCapabilities": ["cert-manager.io/v1", "policy/v1/PodDisruptionBudget"],
        "helmExecutableSha256": digest(helm),
        "clusterContacted": False,
        "charts": results,
    }
    (output / "platform-baseline-result.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Five exact chart archives and deployed values rendered successfully for Kubernetes "
        + release
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument(
        "--chart-dir", type=Path, help="Use pre-acquired archives; omit to acquire exact pins"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.output_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="certweaver-platform-baseline-") as temporary:
        verify(
            root,
            args.output_dir.resolve(),
            args.helm.resolve(),
            args.chart_dir.resolve() if args.chart_dir else None,
            Path(temporary),
        )


if __name__ == "__main__":
    main()
