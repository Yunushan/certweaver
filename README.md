# CertWeaver

**Composable, vendor-neutral PKI and certificate automation for Kubernetes, Linux, Docker/Podman, and Windows.**

CertWeaver is a 0BSD-licensed orchestration project for deploying highly available certificate-management foundations and selecting among twenty open-source PKI/certificate automation integrations through one declarative configuration.

> Project status: `v0.1.0` reference implementation. Review, test, and adapt it in a non-production environment before production use. "Supported" means that CertWeaver provides an adapter, validation rules, documentation, and an installation path; it does not replace each upstream project's own compatibility, security, or support policy.

See the [20-adapter installation matrix, profile inputs and live checks](docs/adapter-installation.md)
for the exact single-host, multi-host, raw, Docker, K3s, RKE2 and Windows contracts.

The [enterprise readiness evaluator](docs/enterprise-evaluator.md) provides
separate `enterprise-init` and `enterprise-score` commands for the 100-control
framework. It requires an independently configured organizational approval
integration to accept maturity credit; the standalone CLI cannot authenticate
release approvals. The existing `score` command retains the earlier rubric.
See the [current verification results and remaining enterprise work](docs/enterprise-readiness-status.md).

## Default enterprise topology

The default profile builds one HA RKE2 cluster from three Rocky Linux 9 nodes. `cert-manager`, `approver-policy`, and `trust-manager` run inside the cluster. HAProxy and Keepalived run on all three nodes and expose one floating VIP.

```text
                         DNS: pki-api.example.internal
                                      |
                         VIP 10.20.30.50 (VRRP)
                                      |
             +------------------------+------------------------+
             |                        |                        |
      rke2-01 / Rocky 9        rke2-02 / Rocky 9        rke2-03 / Rocky 9
      RKE2 server+etcd         RKE2 server+etcd         RKE2 server+etcd
      HAProxy+Keepalived       HAProxy+Keepalived       HAProxy+Keepalived
             |                        |                        |
             +---------------- one RKE2 cluster ---------------+
                                      |
             cert-manager + approver-policy + trust-manager
                                      |
            Public ACME CA and/or internal step-ca/OpenBao/EJBCA
```

Because RKE2 already listens on `6443` and `9345` on every co-located server, the default VIP endpoints use:

| Service | VIP frontend | Node backend |
|---|---:|---:|
| Kubernetes API | `8443` | `6443` |
| RKE2 registration/supervisor | `9346` | `9345` |
| HTTP ingress | `80` | `30080` |
| HTTPS ingress | `443` | `30443` |

The ports are fully configurable. A dedicated external load balancer may use the conventional `6443`/`9345` ports instead.

## Twenty adapters

CertWeaver's registry covers all requested tools:

1. cert-manager
2. Smallstep step-ca
3. OpenBao PKI
4. acme.sh
5. Certbot
6. EJBCA Community
7. lego
8. Dogtag PKI
9. FreeIPA + certmonger
10. CFSSL
11. trust-manager
12. cert-manager CSI Driver
13. dehydrated
14. win-acme
15. Posh-ACME
16. SPIRE / SPIFFE
17. Boulder
18. Caddy Automatic HTTPS
19. Traefik ACME Resolver
20. Lemur

Run `certweaver matrix` for target and maturity details. Boulder is intentionally guarded as lab/test-only, and Lemur is marked legacy/maintenance-risk. Several entries are complementary components rather than interchangeable certificate managers.

## Deployment modes

Ready-to-edit examples are under [`examples/configs`](examples/configs). Each profile uses the same schema and CLI.

- `rke2-ha` — default, three or more RKE2 server/etcd nodes and one VIP.
- `k3s-ha` — lightweight HA Kubernetes with the same VIP pattern.
- `existing-kubernetes` — install only cluster add-ons into an existing cluster.
- `standalone` — install selected Linux/PKI clients or servers without Kubernetes.
- `docker` — run container-capable adapters with Docker Compose or Podman.
- `raw` — execute explicit host installers with no cluster lifecycle management.
- `windows` — install win-acme and/or Posh-ACME on Windows hosts.

## Quick start

Requirements on the operator workstation: Python 3.11+, Ansible Core 2.16+, SSH access with sudo, and three clean Rocky Linux 9 hosts.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ansible-galaxy collection install -r collections/requirements.yml

cp config/certweaver.example.yml certweaver.yml
mkdir -p secrets
openssl rand -hex 32 > secrets/rke2-token
openssl rand -hex 4  > secrets/keepalived-auth
chmod 600 secrets/*

# Create the S3 snapshot credentials file described in docs/operations.md.
# It is required by the production RKE2 profile and remains ignored by Git.

# Edit node addresses, interface and VIP first.
certweaver validate -c certweaver.yml
certweaver plan -c certweaver.yml
certweaver render-inventory -c certweaver.yml -o .certweaver/inventory.yml
certweaver deploy -c certweaver.yml
```

Issuer provisioning requires an operator-reviewed manifest with a real email
address and DNS/HTTP solver or internal CA configuration. Keep the reserved
`addons.issuers.*.enabled` flags false; managed issuer creation is not implemented
and validation rejects enabling those flags. Adapt the examples under
`kubernetes/issuers` and apply the reviewed manifest after the platform is healthy.

## Security defaults

- No plaintext cluster token or DNS API secret is committed.
- Three-node embedded-etcd quorum is enforced for the production HA profile.
- cert-manager uses pinned OCI Helm charts, HA replicas, PodDisruptionBudgets, NetworkPolicies, and disabled automatic approval.
- approver-policy is installed before issuance policies are enabled.
- Keepalived uses unicast peers and a file-sourced auth secret.
- RKE2 secrets encryption, audit logging, etcd snapshots, SELinux, and firewalld are enabled/configurable.
- API and registration ports are restricted to configured management CIDRs; ingress CIDRs are separate.
- The project rejects conflicting co-located HAProxy ports (`6443` and `9345`).
- Lab-only and legacy adapters require explicit acknowledgement.

Read [the security model](docs/security-model.md), [firewall matrix](docs/firewall.md), [production readiness scorecard](docs/production-readiness.md), and [production operations guide](docs/operations.md) before deployment.

## Common commands

```bash
certweaver validate -c certweaver.yml
certweaver matrix
certweaver staging-init -o .certweaver/staging/assessment-01
certweaver score
certweaver evidence -c certweaver.yml -o .certweaver/evidence
# After collecting and reviewing staging artifacts in the bundle:
certweaver score -c certweaver.yml --evidence .certweaver/evidence
certweaver plan -c certweaver.yml
certweaver doctor -c certweaver.yml
certweaver render-inventory -c certweaver.yml
certweaver deploy -c certweaver.yml --check
make test
make lint
./scripts/validate-all.sh
```

## Repository publishing

The repository includes GitHub Actions, GitLab CI, issue templates, release jobs, Renovate configuration, security policy, contribution guide, and a 0BSD license. See [publishing instructions](docs/publishing.md).

Built wheels include the registry, schema, playbooks, roles, and deployment
templates. The CLI can resolve these resources when invoked outside a source
checkout. Ansible deployment requires a supported POSIX control environment and installed
Ansible collections. `certweaver doctor` checks the required controller-side
secret files before deployment.

## Validation status

The repository includes unit, schema, YAML, Ansible lint, secret scan, vulnerability scan, CodeQL coverage, and local evidence-bundle generation. See the [v0.1.0 validation report](docs/test-report.md) for the exact tested boundary.

For a detailed future enterprise qualification goal, use the
[100-control enterprise readiness framework](docs/enterprise-production-readiness.md)
and its [ready-to-copy goal prompt](docs/enterprise-production-readiness-goal.txt).
Use the [staging inputs and approval checklist](docs/staging-qualification.md)
to generate a private six-file input package and inspect its configuration,
inventory, assignments, objectives and execution boundaries without deployment.
It includes a fixed 100-point catalogue, mandatory release gates, evidence and
review rules, and a blank assessment/schema. This is a separate rubric from the
current CLI score; no enterprise score is implied by the existing 97/100 baseline.

The legacy repository rubric starts at **97/100**. Its ten-control evidence
assessment can report 100 under that rubric; enterprise production approval
requires the separate 100-control framework and authenticated review above.
The legacy evidence assessment returns a failing exit status while
evidence is incomplete, stale, changed, or tied to another configuration or
implementation. See the [scorecard](docs/production-readiness.md) for the review
format and the limits of automated evidence checking.

## Important limitations

CertWeaver cannot honestly guarantee every upstream product works in every topology. Windows-only clients cannot run on Rocky Linux, Boulder is not a general enterprise internal CA, and some full CA products require organization-specific ceremony, HSM, database, DNS, identity, and audit decisions. The adapter matrix makes these boundaries explicit instead of hiding them.

The name **CertWeaver** was selected for this reference implementation; perform your own organization, domain, and trademark review before public branding.

## License

CertWeaver is licensed under the [0BSD License](LICENSE). Integrated third-party projects keep their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
