# Validation report for v0.1.0

Validated in the repository build environment on 2026-07-31:

- Python unit and CLI tests for configuration validation, deployment command construction, the 20-entry registry, inventory rendering, evidence bundles, and all example profiles, with an 80% enforced coverage floor.
- Ruff static checks.
- yamllint for configuration, examples, Kubernetes values, playbooks, roles, and CI files.
- ansible-lint production profile for all playbooks and roles.
- GitHub Actions security automation for Gitleaks, Trivy SARIF upload, CodeQL, immutable action SHA pins, and a release workflow that emits a wheel, SBOM, checksums, and provenance attestation.
- Local production maturity score and evidence-bundle generation.
- Wheel packaging build with `python -m build --wheel`.
- Production validation that requires verified RKE2/K3s installer checksums, kernel-default protection, and RKE2 off-host S3 snapshot replication.
- Declarative validation for RKE2 HA, K3s HA, existing Kubernetes, standalone, container, raw, Windows, and guarded-risk examples.

Not claimed by this report:

- A live three-node Rocky Linux/RKE2 installation.
- Helm rendering against every upstream chart version.
- End-to-end issuance through every one of the 20 independent upstream products.
- Organization-specific HSM, CA ceremony, DNS provider, identity, database, or disaster-recovery validation.

Run staging and failure-injection tests before production. CI installs the required Ansible collections; offline local lint may report collection-discovery warnings when those collections have not yet been installed.
