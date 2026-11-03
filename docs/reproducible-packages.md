# Exact-source package builds and reproduction

**Native snapshot follow-up, 2026-11-03:** The corrected frozen candidate
reconstructs byte-identical wheel/compressed sdist artifacts on Python 3.11–3.14
with 127 exact deployment resources. Both explicit allowlists now include
`roles/snapshot_config/tasks/main.yml`; the shared `certweaver.snapshot` Python
module is packaged with the application and required in the Ansible controller's
Python environment. Fresh artifact, installed-resource, normalization and
reconstruction checks pass. This is local exact-source evidence; final release
identity, hosted provenance/consumer qualification and independent approval
remain required. See the [current checkpoint](enterprise-readiness-status.md).


The release path uses a clean checkout, source-bound Python tools, deterministic
archive metadata and a byte-for-byte rebuild check. These are implementation
controls. They do not substitute for approved build inputs, independent review
or an authorized enterprise production decision.

## Build contract

Install the reviewed [Python build profile](python-dependencies.md), then invoke
the builder with the full expected source commit:

```sh
python scripts/install-python-deps.py build
python scripts/build-package.py --commit "$EXPECTED_COMMIT"
python scripts/check-package-reproducibility.py --commit "$EXPECTED_COMMIT"
python scripts/check-wheel.py dist/*.whl
```

`EXPECTED_COMMIT` must identify the intended immutable candidate. The builder
rejects a dirty checkout, a different HEAD, an abbreviated commit, inconsistent
module/package versions, mismatched installed build-tool versions and existing
output/work directories. It checks source identity again after the backend runs.
The backend uses `--no-isolation` after verifying the locked build environment;
it cannot silently resolve new build dependencies.

The builder derives `SOURCE_DATE_EPOCH` from that commit's committer timestamp,
sets `PYTHONHASHSEED=0` and `TZ=UTC`, and removes Python/pip/Git/setuptools
environment overrides from the backend environment. The backend interpreter
uses `-s`, rather than isolated mode, so the explicit hash seed remains effective.
The accepted timestamp range fits both gzip and ZIP representations. The
code-derived timestamp approach follows the
[SOURCE_DATE_EPOCH specification](https://reproducible-builds.org/specs/source-date-epoch/).

## Archive metadata policy

The original backend wheel and sdist are inspected before replacement. Package
normalization changes metadata and container representation; every file's bytes
and executable/non-executable semantics must remain equal before and after.

| Artifact | Canonical representation |
|---|---|
| Source distribution | Lexical member order; source-commit epoch in tar and gzip; UID/GID zero and empty owner names; directories/executable files 0755 and other regular files 0644; deterministic PAX encoding and gzip without a source filename |
| Wheel | Lexical member order; source-commit timestamp at ZIP's two-second resolution; Unix creator metadata; matching canonical modes; no variable extra fields/comments; deflate level 9 |

Wheel `RECORD` and every other member's bytes are preserved. The normalization
does not regenerate content checksums to conceal a content change. Archive
paths, links, special files, duplicates and expansion limits are checked.
Source archives are bounded at 128 MiB compressed, 512 MiB of declared expanded
content and 10,000 members; wheel entries additionally have a 64 MiB per-file
limit. Temporary outputs never replace the original archive unless inspection
and payload comparison succeed.

Gzip explicitly records a fixed mtime and omits the source filename, using the
[documented GzipFile controls](https://docs.python.org/3.11/library/gzip.html).
Recompression is part of this repository's declared package policy, not an
assertion that every upstream backend already emits reproducible archives.

## Fresh reconstruction

The reproduction command first verifies the original checkout and build tools.
It creates a fresh local Git clone without hardlinks, checks out the exact commit
with hooks disabled, and creates a second virtual environment without pip.
The already pinned pip provisions that environment from the full build hash lock,
with hash checking and wheels only. Pip supports this target-interpreter path
even when the new environment initially has no pip; see
[pip's interpreter-management contract](https://pip.pypa.io/en/stable/topics/python-option/).

The second environment runs the committed builder in the clean clone. The
verification then requires:

- The same full source commit, epoch, package policy and locked tool versions.
- Matching interpreter and zlib version records.
- Successful payload-preserving normalization on both builds.
- Exactly the expected package files matching their build receipts.
- Identical SHA-256 values for both the wheel and compressed source archive.

Any missing output, changed policy or byte difference fails. The helper never
repairs a mismatch by changing the expected hashes. Its status is
`BYTE_IDENTICAL_PACKAGE_REBUILD_NOT_PRODUCTION_APPROVAL`, and its independent
reviewer-approval field is always false.

## Release and evidence integration

GitHub's installed-package matrix and release build, GitLab's verification and
package jobs, and `make package` use the exact-source builder and reproduction
check. The common release qualifier requires matching receipts before scanners
run. It copies the build/reproduction receipts into restricted qualification
storage, and the derived evidence record retains their hashes and candidate-bound
reproduction facts. Publisher verification checks the reproduction facts against
the transferred package hashes and expected source commit.

Raw backend and reconstruction logs remain under ignored, restricted
`.certweaver/package-build` and `.certweaver/package-reproduction` storage. They
are not published with release assets. Original-evidence retention still needs
the service's approved protected storage arrangement.

## Remaining assurance

The second build is an automated reproduction in a fresh checkout/environment,
using the same provisioned interpreter and host. It is not an independent human
review, a separate organization's rebuild, or proof across all host platforms.
Interpreter, operating system, Git, compression libraries and other build-image
inputs still need the frozen inventory and acquisition/support decisions for the
actual proposed release. The receipt records interpreter/zlib facts; it does not
approve those inputs.

SUP-05 still needs those approved production inputs, retained exact-candidate
hosted results and authenticated independent acceptance. The full enterprise
framework and other staging/operational requirements remain unchanged.

The local 2026-11-03 qualification used the same synthetic commit on Python
3.11.18, 3.12.16, 3.13.18 and 3.14.4. Every case passed fresh-environment
reconstruction; wheel and compressed-sdist bytes also matched across all four
versions. Full suites passed 661 tests on each Linux endpoint version and 657
with four platform skips on Windows Python 3.12.14. The explicit candidate
substitution probe rejected the changed wheel for its expected digest mismatch.
Original receipts, the local synthetic Git bundle and the real scanner/handoff
integration are bound by `.certweaver/running-identity-20261103/attempt-1/verification-summary.json`.
These records are local implementation evidence and grant no independent approval.

Installed deployment resources must also match their allowlist after an ordinary
pip installation. A managed-host Python verifier is shipped as an extensionless
script resource and invoked explicitly with Python. This avoids pip creating a
derived `.pyc` inside the deployment asset tree. The packaging regression now
installs the built wheel, checks the exact resource set and compares every
resource's bytes. The installed-wheel smoke check retains the same strict
equality rule; generated files are not silently excluded to make it pass.

## Maintained-baseline checkpoint — 2026-11-03

The latest frozen source includes the updated distribution/cert-manager example
pins, exact-tag installer defaults, ingress ownership guards and five-chart
offline compatibility gate described in [platform-baseline.md](platform-baseline.md).
Its complete local verification, fresh-environment Python 3.11–3.14 byte-identical
package reconstruction, real artifact qualifier/handoff and exact digest-negative
probe passed. Evidence is retained in ignored
`.certweaver/maintained-baseline-20261103/attempt-4/verification-summary.json`.
This is a synthetic local candidate; hosted CI, final release/input acceptance,
consumer provenance qualification and independent production approval remain open.

## GitLab release-policy checkpoint — 2026-11-03

The current corrected frozen source, including the release-verifier build pins,
again produced byte-identical wheel and compressed-sdist bytes on Python
3.11.18, 3.12.16, 3.13.18 and 3.14.4, with a fresh checkout and locked-environment
reconstruction on each. Both full Linux suites and static Ansible profiles passed;
the real qualifier/handoff and explicit positive/digest-negative oracle passed.
The manifest is `.certweaver/gitlab-release-20261103/attempt-2/verification-summary.json`.
Its source commit is synthetic local proof. The new signed-JSON GitLab policy
does not claim a SLSA level, actual hosted signing or independent acceptance.

## Source-security diagnostic checkpoint — 2026-11-03

The frozen source with the diagnostic changes again produced byte-identical
wheel and compressed-sdist outputs on Python 3.11.18, 3.12.16, 3.13.18 and 3.14.4,
with fresh checkout/locked-environment reconstruction on each. All 122 resources,
real artifact qualification/handoff and the explicit positive/digest-negative
candidate oracle passed. A subsequent local scanner ENOSPC condition was
diagnosed from retained evidence and the affected checks moved to disk-backed
temporary storage; the source and successful matrix were unchanged.
The manifest is `.certweaver/source-diagnostics-20261103/attempt-1/verification-summary.json`.
These are synthetic local release checks; independent input/policy acceptance,
hosted execution and production approval remain outstanding.

## Managed preparation checkpoint — 2026-11-03

The changed managed playbooks are included in the current 122-resource payload.
The frozen candidate again produced byte-identical wheel and compressed-sdist
outputs on Python 3.11.18, 3.12.16, 3.13.18 and 3.14.4 with a fresh source clone and
locked reconstruction on each. Installed-resource equality, actual artifact
qualification/handoff and the explicit positive/digest-negative candidate oracle
passed. The manifest is
`.certweaver/rolling-preparation-20261103/attempt-1/verification-summary.json`.
The same source has fresh full suites and both Ansible profiles; synthetic
control-flow fixtures remain distinct from real deployment/availability and
independent release-policy acceptance.

## Private export resource checkpoint — 2026-11-03

The private kubeconfig helper and two task files are explicitly included in both
runtime and sdist allowlists, bringing the payload to 125 reviewed resources.
The initial omission from `MANIFEST.in` failed full packaging tests on Windows
and Linux; the corrected snapshot changes only those three include entries.
Its wheel and compressed sdist are byte-identical on Python 3.11.18, 3.12.16,
3.13.18 and 3.14.4, each with a fresh clone and locked-environment reconstruction.
Installed-resource equality, actual qualifier/handoff and explicit accepted-
candidate/digest-mismatch rejection passed. The current manifest is
`.certweaver/kubeconfig-export-20261103/attempt-2/verification-summary.json`;
it preserves the failed attempt and the exact source correction. All commits
and artifacts remain synthetic local proof, with no hosted or independent
production acceptance.

## Managed operator endpoint checkpoint — 2026-11-03

The managed operator staging/configuration task is explicitly included in both
allowlists, bringing the reviewed runtime payload to 126 resources. The frozen
candidate again produces byte-identical wheel and compressed-sdist files on
Python 3.11.18, 3.12.16, 3.13.18 and 3.14.4, with a fresh source clone and locked
reconstruction on each. Installed-resource equality, real artifact qualifier/
handoff and the explicit accepted-candidate/digest-negative oracle pass.
The manifest is
`.certweaver/operator-endpoint-20261103/attempt-4/verification-summary.json`.
Its 903-case full suites and both native profiles are fresh current-source
executions. Local synthetic TLS is distinct from actual VIP/cluster qualification,
hosted CI, final upstream-input acceptance and independent production approval.
