# Validation report for v0.1.0

**Enterprise follow-up, 2026-11-03:** See the [current enterprise execution
status](enterprise-readiness-status.md) for the newer full-suite, coverage,
Ansible and package results and the distinct 100-control assessment boundary.
The validation record below retains its original date and scope.

Validated locally on **2026-10-26**. The source snapshot used for Linux validation
was checked byte-for-byte against the working checkout. Linux checks ran in
native temporary storage because Windows-mounted WSL files caused excessive
I/O delays; this changed the validation location, not the source under test.

| Check | Observed result |
|---|---|
| Full Windows suite, Python 3.12.14 | **97 passed, 1 skipped**; **91.55%** coverage, above the enforced 80% floor. The skipped Bash collector test requires POSIX. |
| Full Linux suite, Python 3.14.4 | **98 passed**; **91.55%** coverage, including the Bash collector failure-propagation test. |
| Ruff | Passed for `src`, `tests`, `setup.py`, and `scripts/check-wheel.py`. |
| yamllint | Passed for configuration, examples, inventories, Kubernetes assets, playbooks, roles, collections, and CI YAML. |
| ansible-lint | The **production** profile passed with **zero findings**, processing 84 files. Runtime: ansible-core 2.21.5 and ansible-lint 26.10.1. |
| Ansible syntax | Passed for all seven playbooks, using inventories from all seven deployment modes, plus the upgrade playbook: eight syntax-check invocations. |
| Configuration examples | The default configuration and all eight example configurations validated. Missing example secret files produced the expected warnings. |
| Distribution builds | Source distribution and wheel built successfully. The default build also exercises a wheel built from the source distribution. |
| Installed wheel | All **107 allowlisted deployment assets** matched source hashes. Version, matrix, score, validation, plan, inventory, and evidence commands passed outside the checkout. A stubbed deployment verified bundled Ansible paths without connecting to hosts. |
| Packaging confidentiality regression | Both archive formats excluded adjacent ignored secret fixtures; their complete member lists and contents were inspected. |
| Python dependency audit | No known vulnerabilities were reported for the 64 installed Linux runtime and validation dependencies at audit time. |
| Pending evidence gate | The generated pending bundle reported **97/100** and exited **2**, listing all ten outstanding live controls. |
| CI action references | All ten distinct pinned action definitions resolved successfully from upstream. Workflow input names were checked against their action metadata. Three nonexistent commit pins were replaced with commits resolved from the official release tags. |

The validated Ansible collection versions are pinned in
`collections/requirements.yml`: `ansible.posix` 2.2.2, `community.general`
13.5.0, `ansible.windows` 3.9.2, and `community.windows` 3.3.0. Their downloaded
archives were checked against Galaxy's published SHA-256 values before local
installation. Each collection's declared minimum Ansible version is compatible
with the repository's supported Ansible constraints.

The fixes covered by these checks include malformed-config handling,
production version/checksum requirements, correct upgrade reconciliation,
version-specific Helm extraction, hard-fault Keepalived health checks, secret
diff suppression, portable wheel resources, packaging allowlisting, and the
reviewed-evidence gate. Fresh-cluster examples no longer require an uninstalled
Prometheus Operator. Unsupported managed issuer flags fail validation instead
of silently performing no work.

Local command output is retained under the ignored `.certweaver` directory:

- `pytest-windows.xml`, `pytest-native.xml`, and `pytest-native.log`.
- `ansible-lint-native.log`, `ansible-syntax-native.log`, and
  `validate-examples-native.log`.
- `package-build-final.log` and `wheel-smoke-final.log`.
- `dependency-audit-linux.json` and `evidence-assessment-final.txt`.
- `ci-pin-verification-final.json` and `ci-pin-resolved-tags.json`.

The CI reference check found and corrected invalid pins for
`aquasecurity/trivy-action`, `github/codeql-action`, and
`softprops/action-gh-release`. The replacements were resolved from the
upstream `v0.36.0`, `v4`, and `v3` tags respectively, and each referenced
action definition was fetched and parsed successfully. YAML lint and whitespace
checks passed after this workflow-only correction. Resolving an action and
checking its input schema does not establish that its remote workflow run passed.

## What remains for 100/100

The repository baseline remains **97/100**. No live deployment was available
for this validation. The final three points require reviewed artifacts for
every control in [the scorecard](production-readiness.md): HA installation,
VIP failover, backup/restore, approved issuance and policy enforcement, trust
distribution, network exposure, host hardening, secret handling, upgrades,
and incident response.

Before those exercises, supply an actual production-profile deployment
configuration and staging hosts, approved token/auth/S3 credentials, an
operator-approved SELinux HAProxy policy, a reviewed issuer configuration,
and an installed monitoring operator with working alert delivery. The sample
configuration's three secret files are absent; no placeholder credentials
were created or treated as evidence.

Run the configured CI and security workflows on the proposed commit before
release. Gitleaks, Trivy, CodeQL, the full CI Python matrix, release SBOMs,
attestations, and publication are configured but **were not executed remotely
in this local validation**. This report also does not establish compatibility
with every upstream Helm chart or end-to-end operation of all twenty adapters.
Organization-specific HSM, CA ceremony, DNS, identity, database, and recovery
decisions still need their own reviewed staging evidence.

After reviewing all ten controls, complete `review.json` with the responsible
reviewer, timezone-aware review and observation times, and artifact paths and
hashes. `certweaver score -c CONFIG --evidence DIRECTORY` exits 0 at 100/100 only
when the integrity and review-completeness gate passes. The named reviewer is
responsible for the truth and sufficiency of the evidence; the checker cannot
establish those facts from arbitrary file contents.
