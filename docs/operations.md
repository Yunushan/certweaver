# Production operations

- Test rolling RKE2 and cert-manager upgrades in staging.
- Keep all versions pinned and review upstream security notices before changes.
- Back up etcd snapshots, the RKE2 token, CA databases/configuration, and required unseal/recovery material through approved encrypted systems.
- Alert on certificate expiry, failed CertificateRequests, ACME Orders/Challenges, webhook errors, unavailable replicas, and snapshot failures.
- Exercise VIP failover and single-node loss at least quarterly.
- Verify restore procedures rather than only checking backup job success.
- Rotate DNS API credentials and minimize their zone permissions.
- Never share a public wildcard certificate/private key across unrelated trust zones unless a documented risk decision requires it.
