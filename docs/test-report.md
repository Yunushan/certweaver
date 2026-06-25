# Validation report for v0.1.0

Validated in the repository build environment on 2026-06-24:

- Python unit tests for configuration validation, the 20-entry registry, inventory rendering, and all example profiles.
- Ruff static checks.
- yamllint for configuration, examples, Kubernetes values, playbooks, roles, and CI files.
- ansible-lint production profile for all playbooks and roles.
- Declarative validation for RKE2 HA, K3s HA, existing Kubernetes, standalone, container, raw, Windows, and guarded-risk examples.

Not claimed by this report:

- A live three-node Rocky Linux/RKE2 installation.
- Helm rendering against every upstream chart version.
- End-to-end issuance through every one of the 20 independent upstream products.
- Organization-specific HSM, CA ceremony, DNS provider, identity, database, or disaster-recovery validation.

Run staging and failure-injection tests before production. CI installs the required Ansible collections; offline local lint may report collection-discovery warnings when those collections have not yet been installed.
