# Production readiness scorecard

This scorecard defines what "production mature" means for CertWeaver. It is a
repo-level and configuration-level checklist, not a substitute for a live
staging deployment, security review, or change advisory decision.

## Current repository score

| Area | Score | Evidence |
|---|---:|---|
| HA topology | 14/15 | Three RKE2 server/etcd nodes, odd quorum, VIP, HAProxy, Keepalived, and co-located port-collision validation. |
| Host hardening | 13/15 | SELinux, firewalld, swap disablement, minimum host capacity checks, kernel modules, Kubernetes sysctls, audit policy, and secrets encryption are modeled. CIS `protectKernelDefaults` remains an operator-gated step. |
| Network exposure | 14/15 | Management CIDRs are required for production and cannot be `0.0.0.0/0` or `::/0`; ingress CIDRs are separate. |
| Certificate control plane | 13/15 | cert-manager, approver-policy, trust-manager, HA values, NetworkPolicies, and disabled automatic approval are the default. Issuer CA ceremony remains external. |
| Version and supply-chain control | 10/12 | Versions are pinned, Helm checksums are supported, GitHub Actions are scanned, Renovate is grouped and release-aged. Installer script checksums are still operator-supplied. |
| Backup and recovery | 8/10 | etcd snapshots are required for production RKE2 and operational restore guidance is documented. Live restore evidence is external. |
| CI and static validation | 10/10 | Ruff, pytest, yamllint, ansible-lint, schema validation, Trivy, Gitleaks, and CodeQL are configured. |
| Documentation and limitations | 8/8 | Architecture, firewall, security model, operations, publishing, air-gap notes, and tested boundaries are documented. |

Repository maturity target after this pass: **90/100 before live staging
evidence**, with the remaining 10 points intentionally reserved for
environment-specific proof.

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
