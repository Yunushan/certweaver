# RKE2 HA quick start

1. Provision three clean Rocky Linux 9 hosts with static addresses, synchronized time, forward/reverse DNS, and distinct failure domains where possible.
2. Reserve a fourth address as the floating VIP; it must be unused and in a network where VRRP/unicast failover is allowed.
3. Copy `config/certweaver.example.yml`, replace addresses, DNS names, SSH user, interface names, management CIDRs, and ingress CIDRs.
4. Generate the RKE2 token and Keepalived auth files under `secrets/`.
5. Run `certweaver validate`, `certweaver plan`, then `certweaver deploy`.
6. Verify nodes, etcd snapshots, HA failover, webhook availability, policies, and certificate issuance in staging before production.

Use an Ansible Vault/SOPS-backed workflow instead of ordinary local secret files in CI.
