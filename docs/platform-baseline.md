# Managed platform baseline — observed 2026-11-03

The examples now select RKE2 **v1.36.5+rke2r1**, K3s **v1.36.5+k3s1** and
cert-manager **v1.21.3**. These replace the Kubernetes 1.33 / cert-manager 1.20.2
example combination. The two distribution identities were the official stable
channel selections when checked; neither was a draft or prerelease. They were
published on 2026-09-30. Cert-manager 1.21.3 was published on 2026-10-23.
These are dated upstream observations, not organizational production approval.

The [cert-manager support table](https://cert-manager.io/docs/releases/) lists
Kubernetes 1.33–1.36 as supported and tested for cert-manager 1.21. Its 1.20
line covers 1.32–1.35. The examples therefore advance both distribution and
cert-manager together. The unchanged approver-policy 0.26.0, trust-manager
0.23.0, CSI Driver 0.15.0 and Traefik chart 41.0.0 have passed offline chart
schema/template checks with the new Kubernetes target. This does not establish
their complete supported-platform matrix, image safety or running behavior.

Sources: [RKE2 stable channel](https://update.rke2.io/v1-release/channels),
[K3s stable channel](https://update.k3s.io/v1-release/channels),
[RKE2 release](https://github.com/rancher/rke2/releases/tag/v1.36.5%2Brke2r1),
[K3s release](https://github.com/k3s-io/k3s/releases/tag/v1.36.5%2Bk3s1),
[cert-manager release](https://github.com/cert-manager/cert-manager/releases/tag/v1.21.3).

## Acquisition identities

The managed installer URLs now select `install.sh` from the exact configured
distribution release tag on the official GitHub repository. Ansible still
requires its separately configured SHA-256 before executing it. The release
tag is not a substitute for the checksum. Existing private configurations must
review the new script source and matching digest before applying an upgrade.
Ansible does not fall back to a floating installer URL after a mismatch.

| Input | SHA-256 observed on 2026-11-03 |
| --- | --- |
| RKE2 tagged installer | `42983c86d1da64a92061d83afb57630cedd69241989f1b0673f3db6c3d92ee6b` |
| K3s tagged installer | `46177d4c99440b4c0311b67233823a8e8a2fc09693f6c89af1a7161e152fbfad` |
| cert-manager 1.21.3 chart archive | `9ec67938b2981d8b333af61b3fcf53e26b4f6f5deb7ccda3de4ea116bb373a17` |
| RKE2 Linux amd64 release archive | `4fdbe8a8a32517fbcb6e80c71ca393b96828fbb87685102d9058b51527f9278d` |
| K3s Linux amd64 release executable | `d73847bcd3c5fccef0115b372e2f9a91f3032dc84bbf71518a4617565294d313` |

The two distribution artifacts matched both their publisher checksum manifests
and release-asset digest metadata. Their extracted/copied executables reported
the selected full version identities when run unprivileged with `--version`
only. This probe did not execute either installer, start a server, pull images
or validate another architecture. Installer-transitive downloads, RPM/image
provenance, upstream signatures, trust-root acceptance and current advisory
disposition still require review for the actual deployment profile.

## Ingress ownership

RKE2 1.36 defaults to bundled Traefik on new clusters. CertWeaver's default
profile installs its own separately managed Traefik chart, with NodePorts
30080/30443 behind the managed load balancer. With
`spec.rke2.disablePackagedIngress: true`, rendering now explicitly selects
`ingress-controller: [none]` and disables `rke2-ingress-nginx`, `rke2-traefik`
and `rke2-traefik-crd`. The validator rejects enabling managed Traefik while
allowing RKE2's packaged ingress. K3s continues to disable its packaged Traefik
and ServiceLB in the managed role.

**Existing clusters require an ingress migration plan before applying these
settings.** RKE2's disable operation actively removes packaged resources. In
particular, a packaged Traefik CRD removal can affect existing custom resources.
Inventory controller releases, CRDs, IngressClasses, annotations, certificates,
ports and traffic first; back up affected resources, establish ownership,
validate a staged cutover and recovery, and obtain the deployment authority's
acceptance. Setting the flag is not a migration procedure. A profile retaining
packaged ingress must disable CertWeaver's separate Traefik and supply/review
its own traffic and ownership configuration.

See the [RKE2 server configuration](https://docs.rke2.io/reference/server_config),
[packaged component removal semantics](https://docs.rke2.io/install/packaged_components)
and [official ingress migration guide](https://docs.rke2.io/reference/ingress_migration).

## Existing version transitions

Do not apply the new 1.36 examples directly to a 1.33 cluster. The implemented
numeric transition gate rejects a skipped minor and every downgrade. Select
reviewed intermediate releases and qualify the sequence **1.33 → 1.34 → 1.35 →
1.36**, including each distribution's release notes and component/version skew.
The new example pins do not approve the intermediate versions or this sequence.

Review the [cert-manager 1.20-to-1.21 upgrade changes](https://cert-manager.io/docs/releases/upgrading/upgrading-1.20-1.21/)
before the Kubernetes 1.36 transition. They include removal of the controller's
default ServiceAccount token-creation Role, reduced aggregate ACME Order and
Challenge permissions, and removal of obsolete metrics override fields. Review
issuer authentication and scrape configuration for your profile; use dedicated
ServiceAccounts and explicit least-privilege RBAC where required. Do not restore
the old aggregate permissions just to make an existing workflow pass.

## Repeatable offline compatibility gate

After installing the locked development dependencies and pinned Helm client:

```sh
python scripts/install-ci-tool.py helm
python scripts/check-platform-baseline.py \
  --helm .certweaver/tools/helm \
  --output-dir .certweaver/platform-baseline-check
```

The check acquires the five literal versions, verifies each chart archive
digest and name/version, and renders the repository values with the actual
deployment flags for the pinned Kubernetes target. `--chart-dir PATH` instead
uses pre-acquired archives, with the same mandatory digest/metadata checks.
The output directory must be new. Private Helm state, an empty plugins directory
and `/dev/null` kubeconfig prevent local plugins or kubeconfig from participating.
No server-side operation or API discovery is requested. Schema errors, unknown
deployment flags and failed rendered invariants stop the check; there is no
schema-validation bypass or warn-only success path.

The render explicitly declares `policy/v1/PodDisruptionBudget` and
`cert-manager.io/v1` as expected target capabilities. Helm's offline defaults
do not discover these from a server, and `--kube-version` alone does not populate
the full API capability set. These declarations represent the intended platform
and preceding cert-manager installation; they do not prove API availability.

The gate checks disabled automatic CertificateRequest approval, cert-manager
priority class and absence of its removed token-creation Role; trust-manager's
webhook timeout/seccomp setting; the CSI node DaemonSet; and Traefik's three
replicas and exact NodePorts. It also rejects several retired API versions and
monitoring CRs that require an uninstalled operator on a fresh cluster. This
list is not a complete Kubernetes API compatibility or security assessment.

The actual renders exposed and corrected rejected values in all five chart
profiles: cert-manager's priority-class path, approver-policy metrics nesting,
trust-manager timeout/security-context paths, unsupported CSI replica/log-format
values, and Traefik global settings. GitHub and GitLab CI now require this gate.
Hosted execution, API admission, CRD/webhook behavior, real installation,
idempotence, issuance/renewal, upgrades, load, failures and restore remain open.
None of these local observations awards enterprise assurance points.
