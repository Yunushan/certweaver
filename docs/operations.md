# Production operations

- Test rolling RKE2 and cert-manager upgrades in staging.
- Keep all versions pinned and review upstream security notices before changes.
- Wait for the configured release-age window before adopting routine upstream releases unless a security advisory requires faster action.
- Configure an encrypted, access-controlled S3-compatible destination for RKE2 snapshots. The deployment requires an ignored controller-side environment file containing the documented `etcd-s3-*` keys; keep the RKE2 token, CA databases/configuration, and unseal/recovery material in approved encrypted systems.
- Alert on certificate expiry, failed CertificateRequests, ACME Orders/Challenges, webhook errors, unavailable replicas, and snapshot failures.
- Exercise VIP failover and single-node loss at least quarterly.
- Verify restore procedures rather than only checking backup job success.
- Rotate DNS API credentials and minimize their zone permissions.
- Never share a public wildcard certificate/private key across unrelated trust zones unless a documented risk decision requires it.
- Keep a sanitized evidence bundle for every production change: config hash, pinned versions, CI run, deployment plan, smoke test output, failover test, and restore-test reference.
- Do not claim a deployment is 100/100 production ready until the scorecard in `docs/production-readiness.md` has live staging evidence.
- Use `certweaver deploy` for production configurations; deployment always enables strict validation and refuses missing secret files, floating versions, invalid checksums, and mutable container images.
- For Docker or Podman adapter images, provide a complete image reference ending in `@sha256:<digest>` through the adapter option or Compose environment variable. A tag alone is not production evidence.

Before deploying the default RKE2 profile, create `secrets/etcd-s3.env` outside Git with the S3 configuration accepted by RKE2, for example:

```text
etcd-s3-endpoint=https://object-store.example.internal
etcd-s3-access-key=REDACTED
etcd-s3-secret-key=REDACTED
etcd-s3-bucket=certweaver-rke2-snapshots
etcd-s3-folder=production
etcd-s3-region=us-east-1
etcd-s3-retention=28
etcd-s3-skip-ssl-verify=false
etcd-s3-insecure=false
```

CertWeaver creates a `kube-system` Secret of type
`etcd.k3s.cattle.io/s3-config-secret`, references it from RKE2, and removes
the transient file from the bootstrap node after reconciliation. Install a
Prometheus Operator before enabling the default certificate alert rules.
