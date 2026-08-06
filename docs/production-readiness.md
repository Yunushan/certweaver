# Production readiness scorecard

This scorecard defines what "production mature" means for CertWeaver. It is a
repo-level and configuration-level checklist, not a substitute for a live
staging deployment, security review, or change advisory decision.

## Current repository score

| Area | Score | Evidence |
|---|---:|---|
| HA topology | 14/15 | Three RKE2 server/etcd nodes, odd quorum, VIP, HAProxy, Keepalived, and co-located port-collision validation. |
| Host hardening | 14/15 | SELinux, firewalld, swap disablement, minimum host capacity checks, kernel modules, Kubernetes sysctls, audit policy, secrets encryption, and required `protectKernelDefaults` are modeled. A formal CIS-profile validation remains environment-specific. |
| Network exposure | 14/15 | Management CIDRs are required for production and cannot be `0.0.0.0/0` or `::/0`; ingress CIDRs are separate. |
| Certificate control plane | 14/14 | cert-manager, approver-policy, trust-manager, HA values, NetworkPolicies, disabled automatic approval, and ACME ownership conflict validation are the default. |
| Version and supply-chain control | 12/12 | Versions and privileged installer scripts are checksum-verified; GitHub Actions are immutable SHA-pinned; releases build a wheel, SBOM, checksums, and provenance attestation; Renovate is release-aged. |
| Backup and recovery | 10/10 | Scheduled etcd snapshots and S3-compatible off-host replication are required for production RKE2; restore evidence is tracked in the generated evidence bundle. |
| CI and static validation | 10/10 | Ruff, pytest, yamllint, ansible-lint, schema validation, Trivy, Gitleaks, and CodeQL are configured. |
| Evidence automation | 5/5 | `certweaver score` reports repo-local maturity and `certweaver evidence` writes a sanitized evidence bundle skeleton. |
| Documentation and limitations | 4/4 | Architecture, firewall, security model, operations, publishing, air-gap notes, scorecard, and tested boundaries are documented. |

Repository maturity target after this pass: **97/100 before live staging
evidence**, with the remaining 3 points intentionally reserved for
environment-specific proof.

Run these local commands before staging:

```bash
certweaver score
certweaver evidence -c certweaver.yml -o .certweaver/evidence
```

On the staging control-plane host, collect the machine-readable portion and then
complete the disruptive or externally sourced checks in the generated bundle:

```bash
bash .certweaver/evidence/live-checks.sh .certweaver/evidence
# Add the exact artifacts listed in required-live-evidence.md.
certweaver evidence-verify -c certweaver.yml -e .certweaver/evidence
certweaver score -c certweaver.yml -e .certweaver/evidence
```

For the protected GitHub Actions workflow, stage the redacted manual artifacts
listed in `required-live-evidence.md` on the self-hosted runner under
`/var/lib/certweaver/staging-evidence/manual` before dispatching
`Staging Evidence`. The workflow copies that directory into the generated
bundle, rejects symlinks and paths outside the protected evidence root, and
then runs the same verifier. Do not place kubeconfigs, tokens, private keys, or
credential values in that directory.

The verification command requires every listed artifact to be non-empty, binds
the bundle to the configuration SHA-256, rejects private key or credential
material, rejects placeholders, and requires a timezone-aware `status: pass`
attestation with an operator, environment, and source for each control. Keep raw kubeconfigs,
tokens, private hostnames, and secret values outside the committed bundle.

For repeatable hosted acceptance, configure a protected GitHub `staging`
environment with a self-hosted Linux runner labeled
`self-hosted`, `linux`, `certweaver-staging`, set its `CERTWEAVER_NODES`
environment secret to the three SSH targets, and dispatch the
`Staging Evidence` workflow. The runner must have the staging kubeconfig and
passwordless read-only commands required by `live-checks.sh`; disruptive
failover, restore, scan, upgrade, and incident artifacts remain deliberate
operator steps.

## Required evidence for 100/100

To claim 100/100 for a specific deployment, attach evidence for every item
below. Keep secrets, tokens, kubeconfigs, and private hostnames out of the
report.

| Control | Required evidence |
|---|---|
| RKE2 HA install | `kubectl get nodes -o wide`, RKE2 server service status from all three nodes, and etcd member health. |
| VIP failover | Demonstrate active VIP owner migration after stopping HAProxy or Keepalived on the current owner. |
| Backup and restore | Restore from an etcd snapshot in staging using the matching RKE2 token. |
| Certificate issuance | Successful CertificateRequest through the approved issuer path, with approver-policy enforcing policy. |
| Trust distribution | trust-manager Bundle reconciliation and expected target ConfigMaps/Secrets. |
| Network controls | Firewalld rich rules and an external port scan from management and non-management networks. |
| Host hardening | SELinux enforcing, swap disabled, chrony synchronized, audit logs written, and CIS/sysctl profile decision recorded. |
| Secret handling | RKE2 token, Keepalived auth, DNS credentials, CA keys, unseal material, and backup keys stored in approved systems. |
| Upgrade rehearsal | Staging upgrade of RKE2, Helm charts, and adapters using pinned versions. |
| Incident readiness | Documented CA key compromise, certificate revocation, cluster restore, and credential rotation procedure. |

## Default stack verdict

The compact default stack, `Rocky Linux 9 + three RKE2 server nodes + HAProxy +
Keepalived`, is a strong production baseline for a small on-premises cluster.
The highest-maturity profile separates duties further:

1. Three dedicated RKE2 control-plane/etcd nodes.
2. Two dedicated HAProxy/Keepalived nodes or an enterprise ADC.
3. Three or more worker nodes for general workloads.
4. Dedicated PKI/trust workloads isolated with labels, taints, and admission
   policy.

The compact profile remains valid when hardware is limited, but the separated
profile is the cleaner enterprise target.
