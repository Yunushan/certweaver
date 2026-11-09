# Production readiness scorecard

This scorecard defines what "production mature" means for CertWeaver. It is a
repo-level and configuration-level checklist, not a substitute for a live
staging deployment, security review, or change advisory decision.

For a broader future enterprise qualification, see the
[100-control enterprise readiness framework](enterprise-production-readiness.md).
That framework has a separate assessment, evidence contract, and definition of
100/100. The existing CLI and score below continue to implement this earlier rubric.

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
| Evidence automation | 5/5 | `certweaver evidence` generates a pending review; `certweaver score --evidence` verifies reviewer identity, freshness, artifact integrity, and configuration/implementation binding. |
| Documentation and limitations | 4/4 | Architecture, firewall, security model, operations, publishing, air-gap notes, scorecard, and tested boundaries are documented. |

Repository maturity baseline: **97/100 before live staging
evidence**, with the remaining 3 points intentionally reserved for
environment-specific proof.

The repository score is a declared engineering baseline. It does not execute CI
or establish that a deployed cluster is healthy. A score of 100 is available
only for the production `rke2-ha` profile after every live control below has
reviewed evidence. Generating the evidence template earns no additional points.

Run these local commands before staging:

```bash
certweaver score
certweaver evidence -c certweaver.yml -o .certweaver/evidence
```

Use a new, empty output directory for each change. Evidence generation refuses
to overwrite an existing bundle so that a previous review cannot be erased by
rerunning the command.

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

## Completing and checking a review

The generated `review.json` binds the review to the configuration and to the
Python implementation and deployment resources by SHA-256. Collect staging
artifacts inside the bundle, review their contents against every required
control, and complete these fields:

- `reviewedBy`: the responsible reviewer's identity.
- `reviewedAt`: the time of the completed review, including its UTC offset.
- Each control's `status`: `passed` only after its evidence has been reviewed.
- Each control's `observedAt`: the time the live check was performed, including
  its UTC offset, at or before the review time.
- Each control's `artifacts`: one or more objects containing a bundle-relative
  `path` and the file's hexadecimal `sha256` digest.

For example, a reviewed artifact entry has this shape:

```json
{"path": "live/nodes.txt", "sha256": "<64 hexadecimal SHA-256 characters>"}
```

Compute each digest after sanitizing the artifact. Keep credentials, private
keys, kubeconfigs, and unredacted infrastructure details out of committed
evidence. The collector and the evidence template do not perform failover,
restore, upgrades, or incident exercises automatically; those require an
operator following the approved staging procedure.

Check the completed bundle with:

```bash
certweaver score -c certweaver.yml --evidence .certweaver/evidence
```

This command exits `0` and reports `100/100` only when all ten controls pass the
review gate. It exits `2` for missing, failed, malformed, stale, or mismatched
evidence. Reviews and observations expire after 30 days. Artifact files must be
nonempty, remain inside the bundle, and match their hashes. A configuration or
implementation change requires a fresh bundle and review.

The checker establishes evidence integrity and review completeness. The named
human reviewer remains responsible for determining whether each artifact
actually demonstrates the required behavior. A passing gate is not an
independent security certification.

## Default stack verdict

The compact default stack, `Rocky Linux 9 + three RKE2 server nodes + HAProxy +
Keepalived`, is a strong production baseline for a small on-premises cluster.
The highest-maturity profile separates duties further:

1. Three dedicated RKE2 control-plane/etcd nodes.
2. Two dedicated HAProxy/Keepalived nodes or an enterprise ADC.
3. Three or more worker nodes for general workloads.
4. Dedicated PKI/trust workloads isolated with labels, taints, and admission
   policy.

The automated HA deployment currently implements the compact IPv4 profile with
co-located HAProxy and Keepalived. The separated profile is an architectural
target that requires a separately managed load balancer and a reviewed
deployment design; the CLI rejects unsupported managed topologies.
