# Security policy

## Reporting

Do not open public issues for suspected vulnerabilities. Use the private security-reporting feature of the hosting platform or contact the maintainers through the security address configured by the deploying organization.

## Supported versions

Until the first stable release, only the newest tagged CertWeaver release receives security fixes.

## Secret handling

CertWeaver deliberately references secret files or Ansible Vault values. Never place live secrets in `certweaver.yml`, inventory, CI variables printed to logs, or Git history. Production operators should integrate Ansible Vault, SOPS, an HSM, a secrets manager, or an equivalent approved system.

## Repository controls

Production repositories should require protected branches, mandatory review,
passing CI/security checks, signed release tags, private vulnerability reporting,
and restricted workflow permissions. Treat these hosting settings as deployment
controls; they cannot be fully represented by files in this repository.

## Threat boundary

The operator workstation and its SSH/WinRM credentials are privileged. Compromise of the workstation, CI runner, RKE2 server nodes, or CA signing systems may expose keys and cluster credentials. Review `docs/security-model.md` before production deployment.
