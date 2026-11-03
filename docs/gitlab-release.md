# GitLab.com release identity and intake

This is an implemented release policy awaiting hosted qualification and owner
approval. Local tests, synthetic credentials and vendor-signature probes do not
establish a working CertWeaver GitLab release channel or production acceptance.
The configured repository currently has a GitHub remote; an authoritative GitLab
project URL and numeric project ID have not been supplied.

## Trust profile and protected signing

The initial profile supports GitLab.com, public production Sigstore and
Linux/amd64 runners. Self-managed GitLab or private Sigstore requires a separately
reviewed profile; changing endpoint variables does not select another trust root.
The reviewed CI configuration must be the project's own root `.gitlab-ci.yml`.

`source-scan` runs before packaging and signing. It checks raw committed source
bytes against the working tree, qualifies the pinned scanner with seeded
positive/negative controls, scans source secrets and reconciles vulnerability
inventory for every declared Python runtime/build/development lock. The matrix
covers CPython 3.11–3.14 and Linux, Windows and macOS marker environments. Identical
inventories share one scan target. A lock entry that activates in none of those
environments is rejected. This is source/lock coverage; it does not provide a
complete SAST program or OS, image and running-service assessment. Raw findings
stay outside exported job artifacts; retained diagnostics contain static failure
classes and vulnerability identifiers, with no raw secret matches.

Diagnostics now identify a fixed execution stage and failure category, with a
numeric scanner exit code when available. They distinguish unavailable advisory
extraction from a successfully parsed empty advisory list. Missing/malformed
scanner reports cannot prevent the redacted failure record from being written.
The gate retains captured scanner stdout/stderr in its private output directory,
including output captured before a timeout; those logs are not public CI
artifacts. Existing output directories are rejected without overwriting earlier
evidence, and failure to write the derived diagnostic still fails the gate.
Local verification must copy private reports in a `finally` path before removing
its temporary checkout. Protected retention of original hosted evidence still
requires an approved destination and access policy.

The original local invocation that emitted only a redacted ValueError remains
unexplained: its temporary workspace was removed before raw reports were copied.
These changes improve subsequent diagnostics and retention; they do not establish
the historical failure's root cause or retroactively convert it to a success.

`sign-release` accepts only protected stable-tag push pipelines. It receives no
upstream artifacts or cache, rebuilds its own exact-commit candidate, checks a
fresh locked-environment byte-identical reconstruction and runs the common real
artifact qualifier before signing. Its 30-minute job requests the sole
`SIGSTORE_ID_TOKEN`, with audience `sigstore`, and targets environment `release`.

The signer verifies the token's RS256 signature against GitLab.com's fixed HTTPS
JWKS endpoint before building and again before signing. It rejects redirects,
proxy/CA environment overrides, alternate key URLs, duplicate JSON fields,
unexpected algorithms, ambiguous keys and RSA keys below 2048 bits. Validation
binds issuer, exact audience, bounded lifetime, default subject, project/job/
pipeline identities, source/configuration commits, tag ref, push source and
environment. Both `ref_protected` and `environment_protected` must be authenticated
true claims. An environment named `release` alone cannot satisfy the policy.
Token values are neither command arguments nor retained provenance fields.
See [GitLab's ID-token claims](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

The project owner must configure the actual protected tag and protected `release`
environment, verify the required feature entitlement, restrict deployment and
pipeline-variable authority, and approve runner isolation and job-token access.
The policy requires the default GitLab `sub` format and job-project claims
available since GitLab 18.4. Changes to those settings require qualification;
the scripts do not configure or attest the project's protection administration.

## Signed statement and consumer policy

The signer emits `release-evidence/gitlab-provenance.json` and its modern v0.3
certificate-backed Sigstore bundle. The JSON has an in-toto Statement v1 shape
with the SLSA provenance v1 predicate, signed using `cosign sign-blob`. It is a
signed JSON blob, not a DSSE envelope, and carries no SLSA level claim. Subjects
are all six exact distribution outputs and the derived `qualification.json`.
The statement binds the full commit, exact project ID, tag, build configuration,
signing policy and concrete GitLab job invocation.

Intake first verifies the signature, exact certificate identity and issuer, public
Sigstore trust and transparency proof using the pinned Cosign executable. It then
checks certificate extensions for source/configuration identity and digest,
numeric project ID, tag ref, push trigger, job invocation and environment. The
required fields follow [Fulcio's documented OID mapping](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
A changed/missing mapping fails closed pending a reviewed profile update.
Legacy, key-only and certificate-chain-only bundle formats are rejected.

Intake verifies private copies of the exact signed statement/bundle bytes before
interpreting them, requires the complete expected subject set and compares the
whole parsed statement with the independently constructed expected statement.
It also reruns release identity/content checks and verifies current qualification
against the trusted checkout's policy, including the existing 24-hour database
freshness limit. Archived releases therefore require a separately approved
long-term verification/fresh-requalification policy; this intake does not waive
freshness to accept old evidence.

`verify-release` uses `GIT_STRATEGY: empty` and downloads only the signer's
allowlisted candidate artifacts. Its compiled inline bootstrap clones the exact
expected commit into a private directory outside those artifacts, installs the
trusted checkout's hash-locked verifier environment and pinned Cosign, then
passes candidate files as data. The workflow guard requires the inline code to
match `ci/gitlab-consumer-bootstrap.py`. No candidate script, Python import path,
OIDC token or release environment is used by the consumer. This is process/source
separation within the pipeline; independent human or organizational acceptance
remains a separate requirement.

An operator verifying a downloaded candidate supplies project URL, numeric project
ID, tag and full commit from approved release metadata, never from that candidate:

```sh
python scripts/install-python-deps.py build --project
python scripts/install-ci-tool.py cosign
python scripts/gitlab-release.py verify /private/candidate \
  --cosign "$PWD/.certweaver/tools/cosign" \
  --project-url https://gitlab.com/APPROVED-GROUP/APPROVED-PROJECT \
  --project-id APPROVED-NUMERIC-ID --tag v0.1.0 \
  --commit APPROVED-FULL-COMMIT --output /private/verified.json
```

Use a trusted, reviewed verifier checkout and fresh private environment. The
capitalized values above are placeholders that intentionally fail validation.
Passing intake does not authorize publication, installation or production use.

## Python and YAML SAST gate

`python-yaml-sast` is a blocking security-stage job before packaging/signing.
It selects GitLab's Semgrep analyzer 6.30.0 by immutable image digest. The
observed upstream source identity, Semgrep 1.181.0 version and all bundled rule
and notice hashes are recorded in `ci/sast.lock.json`. These are acquisition
identities awaiting maintainer trust/license review, not organizational approval.

`scripts/check-sast.py` first requires both a clean control and a deliberately
unsafe `eval` control classified High. It materializes exact committed source
bytes, scans every committed Python/YAML file including tests, and adds byte
copies of the two extensionless Python credential/acquisition helpers. Explicit
Semgrep JSON coverage must contain exactly those targets with no scan errors.
The native GitLab report must agree on every finding's rule, path, line and
upstream security severity. High/Critical findings block the job even when the
analyzer process exits zero. Missing/changed/partial reports also fail.

The scanner receives fixed local bundled rules and a restricted environment,
without ambient tokens, custom-rule features, baseline filtering or exclusion
overrides. The explicit coverage pass disables inline suppression. Original
raw reports and qualification controls remain private runner evidence; only
the native GitLab report, bounded derived result and fixed failure-stage
diagnostics enter the maintainer-restricted seven-day artifact allowlist.
Owners must arrange protected durable retention for originals before relying
on hosted evidence.

This gate does not establish complete SAST language/rule coverage, cross-file
analysis, vulnerability disposition, independent approval or actual hosted
execution. Shell and Jinja deployment logic, transitive dependencies and the
production runtime require complementary review and qualification. GitLab
security-report display depends on the hosting tier/version; the script's
nonzero release-gate exit does not depend on that UI feature.

Primary references: [GitLab SAST](https://docs.gitlab.com/user/application_security/sast/),
[pinned analyzer source](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep/-/tree/ae62d4e8112d16d13c20e562f4e1e1ea6aae7eeb)
and the [observed image identity](https://gitlab.com/api/v4/projects/33525078/registry/repositories/2732175/tags/6.30.0).

## Acquisition and qualification boundaries

Cosign 3.1.4 is acquired as a raw Linux/amd64 executable, with both downloaded
payload and executable SHA-256 pinned in `ci/tools.lock.json`. The installer
rehashes cache reuse, rejects symlinks/empty files and bounds raw executable
size separately from compressed archives. Its currently observed executable hash
is `424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`.
Build/development locks add cryptography and PyJWT for certificate/JWT parsing;
product runtime dependencies are unchanged. All locks retain the original
dependency-age cutoff and generated-pins-require-maintainer-review status.

The official Cosign vendor blob/bundle passed actual verification with the
documented Google service-account identity, and failed verification for a changed
blob, signer and issuer. Those probes qualify the pinned verification primitive;
they do not qualify GitLab certificate issuance, demonstrate a CertWeaver signing
job or replace independent approval of the initial tool trust bootstrap.

Still required: authoritative GitLab project/ID and trust approval; reviewed
protection, runner and access settings; actual hosted positive and adversarial
signing/consumer rehearsals with original protected evidence; complete SAST and
release-channel policy; a versioned publication destination and consumer
revocation/requalification procedure; and independent control-owner acceptance.
Job artifacts expire after seven days and are not the durable release store.
The workflow deliberately stops at verified candidate intake; publication policy
has not been silently invented. See [GitLab's artifact retention guidance](https://docs.gitlab.com/ci/jobs/job_artifacts/).
