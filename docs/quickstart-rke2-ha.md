# RKE2 HA quick start

The examples target a fresh cluster. Review the dated
[platform baseline and ingress ownership contract](platform-baseline.md) first.
An existing 1.33 cluster needs reviewed sequential minor upgrades and an ingress
migration plan; the new example is not a direct upgrade instruction.

1. Provision three clean Rocky Linux 9 hosts with static addresses, synchronized time, forward/reverse DNS, and distinct failure domains where possible.
2. Reserve a fourth address as the floating VIP; it must be unused and in a network where VRRP/unicast failover is allowed.
3. Copy `config/certweaver.example.yml`, replace addresses, DNS names, SSH user, interface names, management CIDRs, and ingress CIDRs.
4. Generate the RKE2 token, Keepalived auth, and S3 snapshot configuration files under `secrets/`, relative to the copied YAML. Follow `docs/operations.md` for the S3 file format and the operator-approved SELinux prerequisite.
5. Run `certweaver validate`, `certweaver doctor`, `certweaver plan`, then `certweaver deploy`.
6. Install Prometheus Operator, enable `addons.monitoring.prometheusRules`, and reconcile add-ons. Review and apply an issuer manifest with the intended solver or internal CA settings; reserved issuer automation flags remain false.
7. Verify nodes, off-host snapshots, restore, HA failover, webhook availability, approval policies, alert delivery, and certificate issuance in staging. Collect and review the evidence bundle before production approval.

Use an Ansible Vault/SOPS-backed workflow instead of ordinary local secret files in CI.
