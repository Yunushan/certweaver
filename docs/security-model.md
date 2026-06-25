# Security model

## Protected assets

CA signing keys, ACME account keys, RKE2 join/encryption token, Kubernetes service-account credentials, TLS private keys, DNS API credentials, database credentials, audit logs, and backups are sensitive.

## Default controls

- SELinux remains enforcing.
- firewalld is configured rather than disabled.
- swap is disabled for Kubernetes nodes.
- RKE2 secrets encryption and audit policy are enabled.
- etcd snapshots are scheduled and the cluster token is treated as a restore dependency.
- certificate requests require approver-policy authorization.
- cert-manager components use HA replica counts, PDBs, resource requests/limits, and NetworkPolicies.
- secret material is referenced from files and excluded from Git.
- adapters that are unsuitable as default production infrastructure are guarded.

## Required operator decisions

Choose root/intermediate CA topology, offline ceremony, HSM/KMS integration, key algorithms, validity periods, revocation/OCSP/CRL policy, audit retention, RBAC, backup encryption, DNS provider permissions, disaster recovery, and incident response. No generic installer can safely decide these for an organization.
