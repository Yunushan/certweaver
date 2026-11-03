# Publishing to GitHub and GitLab

See [release qualification and publication gates](release-gates.md) for the
current job dependencies, permission boundaries, archive inspection, artifact
handoff/provenance checks, local verification and remaining hosted qualification.

The local jobs preserve the required `main` check names. `CI / test` aggregates
both complete test/package matrices and fails if either matrix does not succeed;
`Security / scan` and `CodeQL / Analyze Python` retain their protected contexts.
The separate CodeQL/Trivy security-service checks also remain required. See the
[protected-check contract](release-gates.md#protected-check-names-and-matrix-completion).
Security and CodeQL were initially observed disabled for inactivity on
2026-11-03. After the user explicitly approved activation, both were enabled
and independently confirmed `active` by the public API. Successful exact-candidate
hosted execution is still needed before publication; enabling the schedules
does not publish or qualify the local candidate.

GitHub and GitLab use `scripts/qualify-release.py` for the common artifact checks.
The current tool lock requires a Linux/amd64 qualification runner. GitLab's
Maintainer-only candidate artifact setting requires GitLab 18.4 or later;
project job-token visibility and protected-tag settings need separate verification.
Candidate handoffs also retain a derived qualification record that binds the
artifact and policy hashes, scanner/tool identities and vulnerability database
freshness. GitHub verifies and attests this record before publication; only
`dist/*` becomes release assets. The record omits raw logs and secret match
contents. Original evidence still needs separately approved protected retention;
GitHub candidate artifact visibility follows repository permissions.

The [GitLab.com signed-candidate policy](gitlab-release.md) additionally defines
source/lock scanning, authenticated protected job claims and an isolated consumer
checkout. It awaits actual project/protection/runner qualification and independent
hosted signing/intake proof. GitLab stops at verified candidate artifacts; its
durable versioned publication destination/policy remains to be selected.

GitHub's canonical repository is
[Yunushan/certweaver](https://github.com/Yunushan/certweaver).
The local code-owner mapping follows the existing
[readiness PR #7](https://github.com/Yunushan/certweaver/pull/7).
Verify the responsible reviewers and effective hosting protections before
merging; repository ownership does not establish independent deployment assurance.

Prepare changes on a review branch and use the existing pull-request process.
Reconcile an existing readiness PR before updating or superseding it; preserve
its history and explain intentionally replaced code and verification paths.
Do not publish a synthetic verification commit as an approved release or reuse
another commit's green checks as exact-candidate evidence. Repository-local
patches and test fixtures remain distinct from the final reviewed commit.

After review, merge through the hosting policy and identify the exact approved
`main` commit. The signed `vX.Y.Z` release tag must match both version metadata
and that intended commit. Its release workflow must rerun the required quality,
security, build, artifact qualification and provenance checks at the tagged
subject before publication. Never move an existing release tag. The configured
release environment, signer/tag protections and authorized release decision
remain external acceptance requirements.

An optional GitLab mirror needs an independently approved project, remote,
access policy and release destination. It must preserve the reviewed source
identity and must not bypass the canonical review or release process.

Enable protected branches, mandatory reviews, secret scanning, dependency updates, private vulnerability reporting, signed tags, and CI variables appropriate to each platform. Never put deployment secrets into repository variables that are exposed to untrusted pull/merge request pipelines.

The default repository uses Renovate instead of Dependabot so updates can be
release-aged, grouped, and rate limited. Keep the dependency dashboard enabled
and merge only after CI and security scans are green.

Ansible collections are pinned to the versions exercised by repository
validation. Update their pins as a reviewed dependency change and rerun the
production-profile lint and all playbook syntax checks before release.

Build and smoke-test the distribution before tagging:

```bash
python scripts/install-python-deps.py build
python scripts/build-package.py --commit "$EXPECTED_COMMIT"
python scripts/check-package-reproducibility.py --commit "$EXPECTED_COMMIT"
python scripts/check-wheel.py dist/*.whl
```

See [Python dependency locks](python-dependencies.md) for the source-bound runtime,
build and development profiles, regeneration and required review. CI and the
candidate runtime qualifier enforce exact hashes; generic library metadata ranges
do not substitute for that qualified installation path.
`EXPECTED_COMMIT` is the full intended source commit; the checkout and build
outputs must be fresh. The [package reproduction contract](reproducible-packages.md)
documents metadata normalization, the second locked environment and the required
byte-identical comparison before release qualification.

The wheel includes the schema, adapter registry, pinned version configuration,
Ansible playbooks and roles, Kubernetes values, container configuration, example
profiles, and collection requirements. Installed commands resolve these bundled
resources without requiring a source checkout. The smoke test installs the wheel
into a temporary directory, compares every deployment resource with its source
hash, and exercises the CLI from outside the repository. Its deployment check
uses a stub and does not contact hosts.

CI also rebuilds a wheel from the source distribution and runs the same smoke
test. Python 3.11 uses Ansible Core 2.19; Python 3.12 and later use Core 2.21.
Native Windows can run configuration and evidence commands; use a Linux control
environment for Ansible deployment.

Release tags must match both the package metadata and module version, for
example `v0.1.0`. The GitHub release job rejects a mismatched tag before publishing
artifacts. Release artifacts include the wheel, source distribution, repository
archives, SBOM, checksums, and provenance attestation. HIGH or CRITICAL Trivy
findings fail the security workflow and must be resolved before release.
