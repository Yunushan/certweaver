# Enterprise readiness execution status — 2026-11-03

**Controller prerequisite follow-up, 2026-11-06:** The twenty-adapter installation
work now has a [mode/placement/input and live-check contract](adapter-installation.md).
Its frozen local snapshot passed 1,399 tests on each Linux Python profile,
production Ansible lint, seven playbook syntax checks, twelve native fixture
families per profile, isolated Lemur build/activation-decision checks and clean
package reconstruction. These are local implementation proofs, not live
installation or independent assurance. Original evidence is retained under
`.certweaver/adapter-installation-20261106/`.

A subsequent controller audit found that both locked Linux environments lacked
the `pywinrm` dependency required by Ansible's Windows connection plugin. The
development/controller profile now includes the hash-locked default WinRM/NTLM
closure. Regeneration kept the existing release-age cutoff, changed no existing
package pins and left the runtime/build lockfiles byte-identical. The new
transport tests exercise real plugin loading, offline session construction and
synthetic HTTPS trust/hostname cases; dependency and publisher/license review,
optional authentication prerequisites and actual Windows staging remain open.
See [Python controller dependencies](python-dependencies.md).

The native Windows localhost TLS diagnostic observed a peer leaf certificate
and issuer different from the generated fixture, despite loading the fixture CA.
Plain Python SSL also rejected that path. The failing evidence is retained in
`.certweaver/controller-prerequisites-20261106/attempt-1/`; certificate validation
and trust policy have not been relaxed. An approved representative test path is
required before claiming that Windows-local HTTPS qualification. Linux is the
supported Ansible controller environment for the Windows target adapters.

The controller follow-up and installation changes remain local and unpublished.
PR #7 was observed open at `3d9a5c8021e82e63e1ac116d2f59d908dc1277d8` on
2026-11-06; its hosted checks do not cover these later bytes. The original
RKE2 staging draft and its selected subject have not been retargeted. Live
infrastructure, remaining staging inputs, an independent reviewer, verified
publication/signing and authenticated final approval are still required.
No enterprise assurance points or production authorization are granted by this
checkpoint. Subsequent frozen-source controller verification is retained under
`.certweaver/controller-prerequisites-20261106/` with its exact snapshot bindings.

**Selected-controller fail-fast follow-up, 2026-11-06:** Windows/WinRM `doctor`
and deployment preflight now inspect the Python environment reported by the
selected Ansible executable. They reject missing base or explicitly selected
authentication libraries before inventory creation/replacement, with bounded
read-only probes and sanitized diagnostics. CI requires a real working-controller
and separate hash-locked Ansible-only negative fixture on both Python profiles;
the negative runtime genuinely lacks `pywinrm`, and target command execution is
forbidden by the fixture. Results and exact source bindings are retained under
`.certweaver/controller-probe-20261106/`. Local prerequisite checks do not replace
Windows/WinRM live authentication, endpoint identity, host integration or
independent acceptance, and do not award enterprise assurance points.

**Staging preparation:** The [input and approval handoff](staging-qualification.md)
now defines the exact operator inputs and pre-execution/final-release review
sequence. `staging-init` creates a private package containing the assessment,
schemas, complete control plan and approval-purpose checklist. `staging-check`
checks all 100 assignments, 24 objectives, eight applicability decisions, access/
execution/assurance references, and explicit local configuration/inventory
bindings. Input completeness does not authorize a run or award points. The
organization-specific authority backend and actual live qualification remain
required. The latest hosted checkpoint before these additions is `be10233`,
where all five required checks and Python/package matrices passed; changes
after that checkpoint require their own verification.

**Draft publication checkpoint, 2026-11-03:** The user approved publishing the
reviewed candidate to [draft PR #7](https://github.com/Yunushan/certweaver/pull/7)
and starting hosted CI. Candidate `6244f0f` was published, and its first hosted
run exposed a runner/root workspace-ownership failure and CodeQL findings in
verification fixtures. Follow-up `703b427` creates the private runner-owned
workspace before privileged checks, makes fixture TLS minimums explicit and
uses named text templates for Helm arguments. Its CodeQL, Security/Trivy and
Python 3.11–3.14 package checks passed at this checkpoint; both full hosted test
jobs were still running. One remaining nonblocking unused-assignment warning
was then removed. These statements are dated observations of those exact
commits; the current PR head must pass its own required checks.

The subsequent `703b427` hosted sequence exposed a second ownership boundary:
the privileged snapshot API fixture created a root-private shared tool cache,
and the runner's later Helm installation was denied. Preparation now creates
both `.certweaver` and `.certweaver/tools` as private runner-owned directories
before any privileged fixture. Root-owned tool payloads retain their ownership;
the runner can install its separately pinned Helm payload in the same cache.
The workflow contract rejects preparation that omits the shared cache. Both
failed hosted attempts remain retained rather than counted as successful CI.
A real pinned-etcd/root then pinned-Helm/unprivileged regression reproduces the
old denial and passes with the prepared cache, including Helm execution and
preserved root payload ownership/private permissions. The follow-up's 154
focused workflow/tool tests pass; its final hosted matrix requires a fresh run.

Fresh local verification of `703b427` passed all **1,128 tests** separately on
Linux Python 3.11.18/Core 2.19.14 and Python 3.14.4/Core 2.21.5. Each profile
also passed production Ansible lint, seven playbook syntax checks, Ruff, YAML,
workflow contracts and coverage gates. Windows passed **1,114 tests**, with
fourteen platform-specific skips. A real cross-user regression reproduced the
old permission failure and verified the runner-owned mode-0700 parent after a
privileged child, preserving that child's root ownership. Local receipts are in
`.certweaver/pr-publication-20261103/attempt-1/ci-fix-1/`.

CodeQL and Security workflows are active. Authenticated read-only observation
confirmed main requires all five configured checks, an approving review,
code-owner review, last-push approval, signed commits, linear history and
conversation resolution, with administrator enforcement. The local draft
commits are unsigned. Maintainers must establish an eligible independent review
and approved signing path before any protected merge. No repository policy was
weakened, and no merge, tag, deployment or production approval was performed.
The enterprise assessment remains unassessed with zero accepted assurance
credit and twelve unknown category gates.

**Current verified checkpoint:** The user selected the new 100-control
enterprise framework as this goal's acceptance basis. The
[release gate report](release-gates.md) records the artifact qualification suite,
shared GitHub/GitLab artifact qualification, pinned tool acquisition, mandatory
scanner qualification and complete Python inventory reconciliation. Its complete
isolated integration passed with real tools in a synthetic Git repository.
The evidence handoff additionally retains a derived qualification record, binds
the vulnerability database identity and freshness, and isolates downloaded
candidate files from the publisher's trusted verification scripts.
GitLab now also defines a blocking Python/YAML SAST job with an immutable
Semgrep analyzer image, bundled-rule identities, clean/seeded scanner controls,
exact-source materialization, explicit coverage and agreement with the native
GitLab finding report. It refuses High/Critical findings independently of the
scanner process exit. The [SAST contract](gitlab-release.md#python-and-yaml-sast-gate)
states the restricted artifact policy and complementary language/review gaps.
Local qualification is retained under `.certweaver/gitlab-sast-20261103/`;
actual hosted execution, input/license acceptance, finding disposition and
independent assurance remain required. No control receives credit from job
configuration alone.

Source-bound runtime/build/development hash locks now drive CI, local setup and
candidate installation. The latest clean environments reran Python and Ansible
verification with those pins. See [Python dependency locks](python-dependencies.md)
for acquisition, regeneration and the remaining approval boundaries.
The [exact-source package builder](reproducible-packages.md) additionally derives
timestamps from the commit and requires byte-identical wheel/sdist reconstruction
in a clean clone with a fresh hash-locked environment. Its real Python 3.14
integration and payload-preservation checks passed. The same synthetic commit
also produced identical wheel/sdist bytes on Python 3.11–3.14, with a fresh
locked-environment reconstruction on each version. Independent acceptance remains open.

The latest managed reconciliation change puts host preparation inside the same
serial play as server reconciliation. The bootstrap host completes preparation,
server changes, pending handlers and authenticated readiness before joiners begin;
each joiner completes that sequence before the next joiner is prepared. Installed
version and changing-server runtime are rechecked immediately before preparation.
Fresh installs and same-version repair remain supported. See the
[managed operating contract](operations.md#managed-cluster-reconciliation-and-upgrade-health).
The CLI plan describes API/Node readiness and optional administrative kubeconfig
export. Opt-in export now requires a private POSIX controller destination,
protected source/target permissions, bounded SHA-256-verified atomic transfer
and suppressed credential logging/diff. It defaults to
`~/.config/certweaver/<metadata.name>/kubeconfig`; disabled export retains the
managed-profile operator provisioning step. See the
[export and migration contract](operations.md#optional-administrative-kubeconfig-export).
No automatic quorum proof or live credential qualification is claimed.

Managed operator preparation now stages the distribution kubeconfig privately,
updates only its current context's cluster through `kubectl config set-cluster`,
and atomically publishes the final root-owned mode-0600 file. This fixes the
textual replacement that missed valid quoted YAML and prevents recopy/rewrite
churn on an unchanged run. Source, other clusters, trust and credentials are
preserved; rejected staged validation leaves the previous operator file intact.
See the [managed endpoint contract](operations.md#managed-operator-api-endpoint).
The actual pinned client passes local positive and adverse TLS/authentication
cases; actual VIP/cluster identity and remote privilege qualification remain open.

The source-security diagnostic follow-up now records fixed stage/failure kinds,
survives malformed advisory reports, preserves captured scanner output on timeout
and refuses to overwrite prior evidence. Real CLI failure cases and private
report retention are qualified locally. The new diagnostics exposed an ENOSPC
scanner failure in the 3.9 GiB `/tmp` memory filesystem; the affected checks passed
using an owned disk-backed `/var/tmp` workspace and `TMPDIR`, with no mount or
scanner-policy changes. This does not identify the earlier unretained failure.

The [GitLab.com release policy](gitlab-release.md) now implements a complete
candidate path for source/lock scanning, cryptographically authenticated protected
tag/environment claims, exact signed JSON provenance and trusted-checkout consumer
verification. Actual GitLab project/protection administration, hosted signing and
consumer qualification, durable publication, complete SAST and independent
acceptance remain open. Local vendor-signature and public issuer-key probes do
not represent a CertWeaver GitLab signing run.

The dated example baseline now selects RKE2 **v1.36.5+rke2r1**, K3s
**v1.36.5+k3s1** and cert-manager **v1.21.3**. Exact official distribution
artifacts matched their publisher manifests/asset digests and reported the
selected identities in unprivileged `--version` probes. All five real add-on
archives now pass a repeatable offline schema/render gate using the deployed
flags and explicit expected API capabilities. This exposed and corrected values
errors in all five chart profiles. The gate is mandatory in GitHub/GitLab CI.
RKE2 now explicitly selects no packaged ingress when CertWeaver manages Traefik;
conflicting structured settings are rejected. Installer defaults select the
configured release tag and retain the mandatory SHA-256 check. See the
[platform baseline, migration boundaries and remaining qualification](platform-baseline.md).
These are implementation/local observations, not approved deployment support.

The latest adapter acquisition work requires approved checksums before Linux
binary extraction/copy and Windows win-acme extraction, rejects unsupported
Linux architectures, and honors the exact Posh-ACME version. The
[adapter contract](pki-adapters.md#reviewed-binary-acquisition) documents inputs
and check-mode behavior. A repeatable localhost HTTPS fixture passed nine cases
on both supported Ansible versions with actual root-owned temporary caches.
This qualifies the shared Linux helper locally; upstream artifact acceptance
and native Windows/WinRM behavior remain unqualified.

The three repository Quadlets and five manual Compose images now use explicit
registry names and digest references. Structured deployment rejects image tags;
step-ca has a separate `step_ca_image` key for its container path. Changed
Quadlets request service restart when activation is enabled; unchanged units
request `started`, and OpenBao configuration changes also request restart.
The [container contract](pki-adapters.md#container-image-identity-and-updates)
documents migration and the remaining image-resolution/runtime boundaries.

The four Git adapters now require full commit identities and private
content-addressed checkouts. A packaged verifier checks commit/tree objects and
actual working bytes, independent of index flags/timestamps; the managed Git
launcher removes inherited transport bypasses. acme.sh reconciles selected
revision/executable changes and disables unpinned automatic upgrade in managed
configuration. See the [Git source contract](pki-adapters.md#exact-git-source-acquisition).
The synthetic qualification caught and corrected both a TLS environment bug
and pip-generated bytecode inside the resource tree. Earlier failed attempts
remain recorded; the final package keeps strict installed-resource equality.

All nine chart installation paths now acquire a literal version through the
shared verified-chart role, require an archive SHA-256 and matching chart
name/version, and install the verified local archive. HTTPS and OCI acquisition
use private Helm state and fail on untrusted TLS. Reuse rechecks cached bytes;
check mode grants no acquisition proof. The fixture passed fifteen cases on
each supported Core version with the checksum-verified Helm 3.21.2 client.
Five baseline add-on archives were retrieved from their configured official
sources and their actual archive hashes recorded in the examples. These are
observations awaiting trust/support approval; an archive hash is distinct from
an OCI manifest digest. SPIRE CRDs have independent version/checksum inputs.
See the [chart acquisition contract](pki-adapters.md#verified-chart-acquisition).

Managed RKE2/K3s health now binds the authenticated local API `gitVersion`
and own Node `kubeletVersion` to an explicit expected identity. Before an
upgrade, that is the observed installed binary version; after reconciliation,
it is the selected release. Every changing server is checked before platform
preparation and again before its installer. Fresh installs skip unavailable
runtime preflight and still require final exact identity checks. No phase
disables version comparison.
The selected client context must preserve TLS verification and have no proxy;
its inspection and validation use `no_log`. The actual role and pinned real
client passed 45 TLS/context/version/progression scenarios per Core version.
A separate wrong-context probe reached the explicit local target while keeping
synthetic credential/context canaries out of the log. These are local fixture
proofs; live cluster identity, upgrade and availability qualification remain open.
See the [operating contract](operations.md#managed-cluster-reconciliation-and-upgrade-health).

Managed RKE2/K3s deployment now checks every server's observed binary version
before platform preparation, and repeats the check before server-role changes.
Upgrade preflight requires every installation to exist. The shared numeric gate
rejects downgrades, skipped minors, malformed/ambiguous versions and unsafe
executable locations; equal versions skip the installer. CLI validation requires
a canonical stable distribution release before deployment. The actual Ansible
role, source installer condition and fleet preflight passed 74 temporary cases
per Core version. This enforces a transition boundary; supported release paths,
component skew, migrations and live upgrade/recovery qualification remain open.
See the [version transition contract](operations.md#managed-distribution-version-transitions).

The enterprise framework is **NOT ASSESSED** for an actual release/environment.
The initial record contains 100 unassessed controls, zero accepted evidence
credit, twelve unknown gates and no production approval. Zero accepted credit
does not establish zero operational readiness. The older CLI's 97/100 is a
different repository rubric and cannot be transferred into this assessment.

The enterprise implementation includes a separate evaluator, adversarial tests,
installed-artifact qualification and the framework's exact coverage policy.
The shared release routine adds real-tool integration proof and rejects a
successful scanner exit when installed-package coverage is missing or incomplete.
The goal remains active; 100/100 has not been demonstrated.

## Implemented and verified locally

- `enterprise-init` creates a blank record and refuses to overwrite an existing
  assessment. `enterprise-score` exports all control decisions, recalculates
  credit and gates, and returns exit 2 for incomplete evidence.
- The evaluator pins the v1 catalogue/schema and rejects duplicate keys,
  changed criteria/weights, bad totals/counts, invalid times, stale evidence,
  wrong subjects, missing/tampered files, unsafe paths, unresolved references,
  failed runs and unsupported review/gate/release claims.
- Trust is provided through an independently configured approval backend, not
  editable names or assessment-supplied code. The standalone CLI has no such
  integration and cannot approve a release. Integration and real independent
  assurance remain outstanding.
- The package includes all three enterprise JSON contracts. Installation smoke
  checks exercise initialization and evaluation from outside the checkout and
  verify the complete runtime resource payload against source hashes.
- Coverage policy now checks **line >=90% and branch >=85% independently using
  exact counts**, with no upward rounding. GitHub CI, GitLab CI and `make test`
  invoke the policy. The former 84.915% branch result correctly failed the
  enterprise threshold; substantive failed-criterion and future-gate regression
  tests brought branch coverage above the required floor.

## Real Kubernetes API checkpoint — 2026-11-03

The actual snapshot Ansible block now has a mandatory gate against real upstream
Kubernetes **v1.36.5** and etcd **v3.6.8**, supplementing the earlier HTTP model.
Both binaries have source/member/hash-pinned acquisition and verified caches.
The API version must match the configured RKE2/K3s upstream patch. These are
owned loopback-only processes with mutual TLS, synthetic CA/client identities,
RBAC, default API admission and fixture-owned encrypted storage. The API server
has its internal controllers; worker nodes, scheduler and kube-controller-manager
are absent. This qualifies the API boundary without claiming distribution or
production staging. See [release gates](release-gates.md#real-kubernetes-api-gate--2026-11-03).

Thirteen observations per Core cover create/repeat, rotation, owned-field
removal, foreign metadata preservation, same-manager drift, foreign ownership
conflict, immutable Secret rejection, denied RBAC, check mode, actual enforcing
admission policy, encrypted storage and terminal process cleanup. Metadata-only
audit confirms the persistent request counts: unchanged and rejected operations
do not invoke live apply. Foreign ownership is rejected without forced takeover.
The storage envelope check uses an ephemeral fixture encryption key, not a
production custody/rotation configuration.

The first unprivileged seven-observation API probe passed and stopped both
processes. The first actual-role smoke incorrectly expected HTTP 403 for
admission rejection. Real audit recorded HTTP **422**, the named policy/binding
and the exact synthetic denial message. The corrected oracle requires that
response; the original failure audit and terminal-process receipt are retained.
The corrected thirteen-case smoke and both final frozen profiles passed.

| Check | Observed result | Boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 1,086 passed on each | Fresh complete frozen-source suites |
| Windows Python 3.12.14 | 1,072 passed, 14 platform skips | Fresh complete frozen-source suite |
| Runtime coverage | Lines 1331/1428 on Windows/3.11 and 1332/1428 on 3.14; branches 623/708 on all | Exact 90% line / 85% branch floors passed |
| Ansible Core 2.19.14 / 2.21.5 | Production lint: zero rule findings, 102 processed / 108 encountered; seven syntax checks each | Fresh qualification profiles |
| Real upstream API/etcd | Thirteen observations per Core | 26 fresh observations; real source block, TLS/API semantics and metadata audit |
| Retained native proof | 277 observations per Core | 554 reviewed/reused observations; every deployed role/module/default/playbook and prior fixture implementation matches |
| Acquisition/lifecycle/CI regressions | 29 new tests | Eighteen acquisition cases, five baseline/source checks, three process-cleanup cases and three CI mutations |
| Ruff, YAML, actionlint, CI workflow guard and source declarations | Passed | Fresh frozen source; actionlint shellcheck disabled |
| Python 3.11–3.14 package matrix | Byte-identical wheel/compressed sdist with fresh clone/environment reconstruction per version; 127 resources | Complete current candidate reconstructed |
| Real release qualification, handoff, source-lock scanning and digest rejection | Passed | Current tools/database and clean/seeded controls; no hosted or independent acceptance |

The valid native total is **580 behavior observations: 26 fresh real-API and
554 retained after exact-scope review**, plus ten retained offline chart renders.
All 217 unchanged execution inputs were matched. The four older CI tool records,
source allow expression, installer/extraction/redirect/cache/bounds logic remain
equivalent; the new identity branches apply only to API-server/etcd. Current
real release/source scanners also execute the updated installer. Earlier model
observations retain their narrower scope and do not stand in for API ownership
or admission semantics.

The current manifest is
`.certweaver/kubernetes-api-20261103/attempt-1/verification-summary.json`.
It binds the 263-file frozen source, 225 execution inputs, real API/etcd logs,
metadata audit, process cleanup, acquisition/probe artifacts, prior original
proof manifests and post-snapshot documentation. The fixture commit is local
and synthetic. Previously approved workflow activation remains separately
bound; hosted execution of this candidate remains unqualified.

Enterprise acceptance remains **NOT ASSESSED: zero accepted assurance points,
100 unassessed controls, twelve UNKNOWN gates and NOT_APPROVED**. Real staging
configuration/access, frozen release/support scope, all 24 objectives, owners,
reviewers and authenticated assurance integration remain required. Actual
distribution/runtime identity and policies, production key custody, remote
privilege, issuer/workload lifecycle, fault/restore/telemetry/load exercises,
hosted release evidence and independent production approval remain open.
The gap register preserves every control and its full acceptance requirements.

## Snapshot Secret reconciliation checkpoint — 2026-11-03

The original snapshot Secret block used shared `/run` filenames. A deterministic
reproduction with two actual Ansible processes showed invocation A publishing
invocation B's credential into A's synthetic Secret, then deleting B's staging
before B rendered it. The final original-source baseline preserves the exact
prior task hash and records exit codes 0/2, crossed credentials and disrupted
cleanup. Separate repeated-run probes showed three temporary-work changes and
one live apply on both runs; the actual apply task reported unchanged because
the real server-side client's `serverside-applied` output did not match the
old client-side `created`/`configured` condition.

The corrected block clears stale staging identity and allocates an independent
root-owned mode-0700 directory for each invocation. Input, rendered Secret,
client cache and comparison files stay inside it. Credential files remain
mode 0600 and exact transfer hashes/size remain required. Cleanup removes only
the allocated directory after success/failure. Server-side diff with the same
field manager gates apply: unchanged state skips apply, differences apply,
errors stop. Temporary work reports no persistent change; successful apply
reports one. The required standard comparison utility is included in the common
package set. See the [operating contract](operations.md#operating-requirements).

The mandatory real-client fixture uses authenticated localhost HTTPS discovery
and a minimal Secret model. It covers create, repeat, credential rotation,
removed input fields, live drift, preserved unrelated metadata, read/diff/apply
errors, untrusted CA, denied authentication, check mode, inherited external-diff
override, stale staging and allocation failure. Two additional scenarios run
actual interleaved Ansible processes against distinct Secret names with the same
or different input values. Staging isolation does not serialize same-object
writers, and the model does not emulate Kubernetes ownership/admission semantics.

| Check | Observed result | Boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 1,057 passed on each | Fresh complete frozen-source suites |
| Windows Python 3.12.14 | 1,043 passed, 14 platform skips | Fresh complete frozen-source suite |
| Runtime coverage | Lines 1331/1428 on Windows/3.11 and 1332/1428 on 3.14; branches 623/708 on all | Exact 90% line / 85% branch floors passed |
| Ansible Core 2.19.14 / 2.21.5 | Production lint: zero rule failures/warnings, 102 processed / 108 encountered; seven syntax checks each | Fresh updated roles and all seven playbooks |
| Snapshot policy/private transfer | 35 cases per Core | Fresh updated actual block; real client rendering and marker publication |
| Secret reconciliation | 17 cases per Core | Fresh actual block/client, local authenticated HTTPS model and two real concurrent processes |
| Retained version/health/strategy/tag/chart/export/endpoint proof | 225 observations per Core | Reviewed exact inputs and selected task bodies; original manifests/hashes retained |
| New source/CI guard tests | 26 passed | Twenty-three source mutations and three CI mutations |
| Ruff, YAML, actionlint, CI workflow guard and source declarations | Passed | Fresh frozen source; actionlint shellcheck disabled |
| Python 3.11–3.14 packages | Byte-identical wheel/compressed sdist with fresh clone/environment reconstruction per version; 127 resources | Updated task/default assets included |
| Real release qualification, handoff, source-lock scanning and digest rejection | Passed | Current real tools and clean/seeded controls; no hosted or independent acceptance |

The valid native total is **554 behavior observations: 104 fresh and 450
reviewed/reused**, plus ten retained offline baseline chart renders. Earlier
35-case transfer reports are superseded by the updated fresh runs. All 214
unchanged execution inputs were matched; the add-on task sequence differs only
in the Secret block, and common defaults differ only by `diffutils`. Retained
version/health fixtures replace common/add-on work with markers; retained
strategy fixtures replace roles; chart/export/endpoint fixtures select unchanged
task bodies. No changed snapshot behavior is qualified through those old reports.

Original incomplete OpenAPI fixture responses, the first baseline's incorrect
temporary-change count and a diagnostic predicate mistake remain retained with
their corrected final probes. Client validation was kept enabled. The pre-freeze
corrected smoke passed fifteen cases; the final frozen fixture adds the two
stale-reference/allocation failure cases. Historical failures retain their
original narrower scope.

The preceding reconciliation checkpoint manifest is
`.certweaver/snapshot-reconcile-20261103/attempt-1/verification-summary.json`.
It binds the 261-file snapshot, 223 execution inputs, current reports, original
and intermediate reproduction artifacts, both prior proof manifests and updated
documentation. The synthetic commit is not a published release. Previously
approved workflow activation remains separately bound; no current-candidate
hosted execution is inferred.

Enterprise acceptance remains **NOT ASSESSED: zero accepted assurance points,
100 unassessed controls, twelve UNKNOWN gates and NOT_APPROVED**. Actual staging
configuration/access, immutable release/support scope, all 24 numeric objectives,
real owners/reviewers and authenticated assurance integration remain required.
Actual Kubernetes ownership/admission and competing writers, scheduled off-host
backups and replacement-host restore, certificate lifecycle/fault/telemetry/load
exercises, hosted release evidence and independent production approval remain
open. Each control's exact acceptance and evidence requirements remain in the
current gap register; the local fix does not waive them.

## Managed fleet strategy checkpoint — 2026-11-03

The previous snapshot checkpoint's global stop claim depended on the controller's
default strategy. A real pinned-Core reproduction showed that `free` and
`host_pinned` allowed the valid peer to advance after another peer failed,
despite a final exit code of 2. Full source play-boundary probes on RKE2, K3s
and upgrade reached three later phase markers; linear stopped before all later
markers. The first-play and full-boundary reproductions are retained.

All fourteen managed deploy/upgrade plays now explicitly select
`ansible.builtin.linear` and retain fatal fleet errors. The new mandatory
GitHub/GitLab native fixture exercises three playbooks, three controller strategy
environment settings and healthy/preflight/health outcomes. Each healthy case
reaches all five expected markers; every failed case reaches none. RKE2 uses the
actual shared snapshot preflight; K3s version and fleet health failure injection
is synthetic. Host/service changes are marker replacements. See the
[operating contract](operations.md#managed-cluster-reconciliation-and-upgrade-health).

| Check | Observed result | Evidence boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 1,031 passed on each | Fresh complete frozen-source suites |
| Windows Python 3.12.14 | 1,017 passed, 14 platform skips | Fresh complete frozen-source suite |
| Runtime coverage | Lines 1331/1428 on Windows/3.11 and 1332/1428 on 3.14; branches 623/708 on all | Exact 90% line / 85% branch floors passed |
| Ansible Core 2.19.14 / 2.21.5 | Production lint: zero rule failures/warnings, 102 processed / 108 encountered; seven syntax checks each | Fresh current managed playbooks |
| Version, health and managed strategy | 74 + 60 + 27 native cases per Core | 322 fresh observations; actual source boundaries with synthetic host/API/phase fixtures |
| Snapshot/tag, chart acquisition, export and endpoint | 35 + 4 + 15 + 23 + 22 cases per Core | 198 reused observations after exact input/caller-body review; original hashes and scope retained |
| Baseline chart renders | Five per Core | Ten reviewed/reused offline renders, excluded from behavior total |
| New strategy unit tests | 34 passed | Thirty strategy mutations, three CI mutations and one valid baseline |
| Ruff, YAML, actionlint, CI workflow guard and acquisition declarations | Passed | Fresh frozen source; actionlint shellcheck disabled |
| Python 3.11–3.14 package matrix | Byte-identical wheel/compressed sdist, fresh clone/environment reproduction per version; 127 resources | Current changed playbook assets included |
| Real artifact qualification, handoff, source-lock scanning and digest rejection | Passed | Real local tools and clean/seeded scanner controls; no hosted or independent acceptance |

There are **520 valid native behavior observations: 322 fresh and 198 reviewed/
reused**, plus ten offline chart renders. The eight older full-play fleet
observations are superseded by the 54 new strategy observations and are not
counted again. All 213 unchanged execution inputs and the snapshot caller bodies
were compared before reuse; changed version/health/strategy boundaries and all
package/scanner checks ran freshly. Historical narrower proofs retain their
original scopes and failure history.

The preceding strategy checkpoint manifest is
`.certweaver/strategy-20261103/attempt-1/verification-summary.json`. It binds the
259-file frozen source, 221 execution inputs, current reports, original defect
reproduction, exact prior proof manifest and post-snapshot documentation. The
synthetic fixture commit is not a published release. The approved CodeQL and
Security workflow activation remains bound to its receipt; activation does not
establish hosted execution of this current candidate.

Enterprise acceptance remains **NOT ASSESSED: zero accepted assurance points,
100 unassessed controls, twelve UNKNOWN gates and NOT_APPROVED**. This is the
count of independently accepted evidence, not a software-quality percentage.
The local strategy defect is corrected. Actual staging configuration/access,
immutable release/support scope, all 24 numeric objectives, accountable people,
the real assurance backend, representative lifecycle/fault/restore/telemetry/
load exercises, actual hosted release proof and independent production approval
remain required. The current gap register preserves each control's exact
acceptance criteria, evidence, verification and accountable/reviewer roles.

## Native snapshot preflight checkpoint — 2026-11-03

Production snapshot input validation now runs through the same Python module
in the CLI and direct Ansible. The deploy/upgrade first-play preflight covers
all managed servers before version observation or host changes. Standalone
RKE2/add-on roles repeat it before their changes, and the Secret block rechecks
immediately before transfer. Scheduled snapshots and S3 must be enabled in the
production profile; disabled flags cannot bypass validation. Local controller
execution explicitly disables privilege escalation and SSH transport. The
[operating contract](operations.md#operating-requirements) describes the matching
installed-package prerequisite, bounds, literal env-file syntax and migration.

Private transfer binds the validated source through its transfer checksum and
an actual staged SHA-256/byte-count check before Secret rendering. Same-size
controller/staging races, rendering/application failures and cleanup are covered.
Check mode validates input and skips staging/render/apply. No real object store,
Secret publication to a cluster, snapshot delivery or restore is claimed.

A real pinned-client boundary probe found the initial 1 MiB file limit was
insufficient: a 65,536-byte env-file line caused kubectl to omit credential data
while returning exit zero. The retained reproduction demonstrates complete
rendering at 65,535 bytes and omission at 65,536/65,537. The corrected shared
reader enforces a raw 65,535-byte UTF-8 line limit before BOM/CR handling.
ASCII boundary, multibyte, BOM and CR unit cases plus three native boundary
cases qualify the correction. A Windows unit fixture initially converted LF
to CRLF and was corrected to write exact bytes; no production rule was relaxed.
An earlier adverse guard test caught acceptance of `when: false` on cleanup;
the guard now rejects any cleanup condition. Failed tests, the first frozen
attempt and the real-client reproduction remain preserved.

| Check | Corrected observed result | Boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 997 passed on each | Fresh complete suites |
| Windows Python 3.12.14 | 983 passed, 14 platform skips | Fresh complete suite; new skip covers POSIX named pipes |
| Runtime coverage | Lines 1331/1428 on Windows/3.11 and 1332/1428 on 3.14; branches 623/708 on all | Independent exact 90% line / 85% branch floors passed |
| Ansible Core 2.19.14 / 2.21.5 | Production lint: zero rule failures/warnings, 102 processed / 108 encountered; seven syntax checks each | Fresh corrected source on both profiles |
| Snapshot policy/transfer | 35 native cases per Core | Real module, private files, real client rendering; marker-only publication |
| Snapshot tag/fleet behavior | Four default/selected-tag cases and four two-host fleet cases per Core | Bad peer stops every host before progression markers |
| Version/fleet and API/node health | 74 version cases and 60 health/progression cases per Core | Fresh; synthetic binaries/API and installer/preparation/handler markers |
| Chart acquisition / baseline | 15 acquisition cases and five exact baseline chart renders per Core | Fresh real Helm; no cluster admission or workloads |
| Private export / operator endpoint | 23 export and 22 endpoint cases per Core, including 15 actual TLS client cases | Fresh private-file/localhost API fixtures; no actual remote privilege or VIP |
| Ruff, YAML, workflow guard, source declarations, actionlint | Passed | Fresh corrected frozen source; four workflows, shellcheck disabled |
| Python 3.11–3.14 package matrix | Byte-identical wheel/compressed sdist with fresh checkout/environment reconstruction per version; 127 resources | New snapshot role and shared module available in the installed package |
| Real qualification / handoff / source-lock security / digest rejection | Passed | Fresh real tools/current database and scanner controls; no full SAST, host/image, hosted or independent acceptance |

The native profile total is **474 behavior observations**, excluding the ten
offline baseline chart renders. The mandatory GitHub/GitLab snapshot fixture
and 24 source-policy mutations plus three CI-gate mutations protect the new
path. Version/health fixtures now supply valid synthetic production snapshot
inputs instead of bypassing the new preflight; their existing failure rules
and scenario counts remain intact. Historical Git/HTTPS/container, source-failure
and crypto proofs retain their original narrower scopes. The earlier pip/Rich
Windows console failure remains documented in its original checkpoint; neither
new full Windows execution reproduced it, and its underlying cause is unproven.

Evidence for the preceding snapshot checkpoint is
`.certweaver/snapshot-native-20261103/attempt-2/verification-summary.json`.
It binds 219 execution inputs, the corrected 257-file snapshot, fresh native and
package/scanner reports, the superseded first attempt and retained failures,
the previous proof manifest and post-snapshot documentation. The synthetic
commit is not a published CertWeaver release. Earlier approved workflow activation
remains recorded separately; no current-candidate hosted run is inferred.

Enterprise status remains **NOT ASSESSED: zero accepted assurance points,
100 unassessed controls, twelve UNKNOWN category gates, NOT_APPROVED**. The
direct-Ansible implementation gap is closed at this local qualification scope.
Actual object-store transport/trust, storage encryption/custody/retention,
scheduled off-host delivery and replacement-host recovery still need approved
live proof. The real staging configuration/access, immutable deployment/support
profile, all 24 numeric targets, accountable owners/reviewers, assurance backend,
lifecycle/fault/restore/telemetry/load exercises, hosted release proof and final
independent production decision remain required. The current gap register
preserves every control's exact acceptance, verification, evidence and roles.

## Snapshot transport verification — preceding checkpoint

The current production CLI rejects a supplied RKE2 S3 env-file configuration
that enables plaintext transport or disables certificate verification. The
retained pre-change reproduction shows both unsafe switches were accepted.
The corrected validator also rejects implicit environment lookups, duplicate
keys, invalid names, quoted/whitespace-tainted transport booleans and comment-only
files. It preserves literal values, first-line BOM, CRLF, leading whitespace,
the six Go false spellings and secure omitted-switch defaults. Diagnostic
messages contain fixed policy/key names and line numbers, never credential data.
See the [operating contract](operations.md#operating-requirements).

Forty new regression cases include actual CLI rejection before inventory
creation or Ansible invocation. Fifteen cases with the real checksum-pinned
kubectl client independently verify env-file semantics, including inherited bare
keys, preserved quotes/trailing spaces, duplicate rejection and credential values
containing equals signs. Synthetic Secret output is inspected in memory and is
not retained in the derived receipt.

| Check | Current result | Boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 957 passed on each | Fresh full suites, unprivileged |
| Windows Python 3.12.14 | 944 passed, 13 platform skips on the full rerun | Initial subprocess failure and isolated reproduction attempt retained |
| Linux 3.14 runtime coverage | Lines 1287/1378; branches 614/696 | Independent exact 90% line / 85% branch floors passed |
| Linux 3.11 runtime coverage | Lines 1286/1378; branches 614/696 | Independent exact 90% line / 85% branch floors passed |
| Windows runtime coverage | Lines 1286/1378; branches 614/696 | Independent exact 90% line / 85% branch floors passed |
| Ruff, YAML, workflow guard, source declarations, four actionlint workflows | Passed | Fresh current frozen source; shellcheck disabled |
| Python 3.11–3.14 package matrix | Byte-identical wheel/compressed sdist; fresh checkout and hash-locked reconstruction per version; 126 resources | Local synthetic committed subject |
| Real qualifier, handoff, source/lock security and exact candidate-digest rejection | Passed | Real tools/current database and scanner controls; no complete SAST, host/image or hosted proof |
| Native Ansible Core 2.19.14 / 2.21.5 | Prior zero-finding lint, seven syntax checks per Core and 90 total export/endpoint observations retained | Relevant native inputs unchanged; no fresh native execution claimed |

The first Windows full run had 943 passes, one failure and 13 skips. Its existing
packaging test's pip subprocess raised `Bad file descriptor` in the Rich legacy
Windows console renderer and exited 120 while reporting installation success.
That exact test passed in isolation, and a fresh full run of the same frozen
source passed without source or environment changes. The underlying intermittent
console/file-descriptor cause is unproven. No source workaround, dependency
relaxation, failure suppression or automatic retry was added. Both full runs and
the isolated result remain retained; the later pass does not erase the failure.

Only `src/certweaver/config.py`, `tests/test_config.py` and `tests/test_cli.py`
differ among the 215 execution inputs from the required-check checkpoint.
The other 212 inputs match. Native Ansible roles, playbooks, fixture scripts,
configuration, dependency locks and tool declarations remain unchanged. The
earlier proofs retain their original local/synthetic scope. Package/scanner and
full-suite results above are fresh for the changed runtime validator.

Current local evidence is retained in
`.certweaver/snapshot-transport-20261103/attempt-1/verification-summary.json`.
It binds source, reports, original defect reproduction, failed Windows execution,
corrective verification and the prior hash-verified proof chain. The synthetic
candidate is not a published release commit. All 100 controls remain unassessed,
accepted assurance credit is zero, all twelve category gates remain UNKNOWN and
production is NOT_APPROVED. The full current `gap-register.json` preserves every
criterion and adds the new implementation/test pointers without awarding credit.

This change enforces production CLI input policy. Direct Ansible invocations
do not execute this validation and still need a reviewed equivalent preflight.
Actual snapshot transport/trust, encryption at rest, bucket permissions/retention,
scheduled delivery and isolated recovery remain to be qualified. The approved
staging configuration/access, immutable deployment/support scope, 24 objective
targets, real owners/reviewers, organization assurance backend and live exercises
remain required. The prior provider/intake audit is historical. No protection
change or hosted current-candidate run is inferred.

The user subsequently explicitly approved re-enabling both existing CodeQL and
Security workflows. Both GitHub pages reported successful activation and a fresh
public API receipt independently confirms both states are `active`. The current
`workflow-activation.json` binds the approval, before/after provider state and
the observation receipt. Initial browser captures were rejected because they
could expose unrelated private content; after the current window title confirmed
CodeQL, screenshot-only observations of the task GitHub pages supported the two
approved activation clicks. No branch/protection settings were changed. This
restores scheduled execution; it does not publish or qualify the local candidate.

## Required-check verification — preceding checkpoint

The current candidate fixes a provider-integration mismatch discovered through
the authenticated read-only `main` branch-protection view. The local workflows
now emit the protected `CI / test`, `Security / scan` and
`CodeQL / Analyze Python` job names. The first is an unprivileged, always-run
aggregate that fails unless both complete test and installed-package matrices
succeed. Fourteen adverse mutations reject removed dependencies, bypassed
conditions, allowed failures, changed success exits, extra privileges and
incorrect names. The separate `CodeQL` and `Trivy` service checks remain
required from their configured GitHub Advanced Security application. See the
[protected-check contract](release-gates.md#protected-check-names-and-matrix-completion).

| Check | Current observed result | Evidence boundary |
|---|---|---|
| Linux Python 3.11.18 / 3.14.4 | 917 passed on each | Fresh full suites on the frozen source, unprivileged |
| Windows Python 3.12.14 | 904 passed, 13 platform skips | Fresh full suite on the same normalized source |
| Runtime coverage | Statement 1259/1351 on Windows/3.11, 1260/1351 on 3.14; branch 597/680 on all | Separate exact 90% line / 85% branch floors passed |
| Ruff, YAML, workflow guard, source inventory | Passed | Fresh current source; 65 declarations / 71 inspected files |
| GitHub workflow syntax | Four workflows pass pinned actionlint 1.7.12 | Shellcheck disabled; local syntax only |
| Four-version package matrix | Byte-identical wheel/compressed sdist on Python 3.11–3.14, fresh clone and locked environment per version; 126 resources | Synthetic local committed subject |
| Real qualifier, handoff, source/lock scan | Passed; 12 inventories / 36 environments; clean and seeded-secret controls pass | Real tools/current database; no complete SAST, host/image or hosted proof |
| Candidate rejection oracle | Original accepted; exact rebuild-digest mismatch rejected for the expected reason | Fresh local candidate |
| Ansible Core 2.19.14 / 2.21.5 | Prior zero-finding production lint, seven syntax checks and 45 export/endpoint observations per Core retained | Reused only after exact unchanged relevant-input review; no fresh native run claimed |

Exactly five execution inputs differ from the managed-endpoint checkpoint:
three workflow definitions, the workflow guard and its tests. All 210 other
execution inputs match, including native roles, playbooks, fixtures,
configuration, dependency locks and tool declarations. The preceding native
reports and retained failure history preserve their original scope. Fresh
source/package/scanner checks above cover the changed candidate.

The current local evidence is
`.certweaver/required-checks-20261103/attempt-1/verification-summary.json`.
It binds the frozen source, 215 execution inputs, fresh reports, the earlier
hash-verified proof manifest and post-snapshot documentation. Its synthetic
fixture commit is not a published CertWeaver release commit.

The acceptance prerequisite audit is retained in
`.certweaver/acceptance-audit-20261103/attempt-1/acceptance-prerequisites.json`.
Public provider receipts report Security and CodeQL as `disabled_inactivity`;
prior successful runs and the open PR refer to older commits. The authenticated
protection view confirms the five required contexts and disabled admin bypass.
No protection settings were changed. Re-enabling the workflows awaits the
explicit owner approval requested after automatic approval review rejected the
activation action as a persistent CI/resource-use change. No alternative route
was used to bypass that decision. Actual final-candidate hosted runs remain
required even after activation.

The input review found no supplied actual staging configuration/access method,
approved deployment subject, numeric objectives or independent approvals in
the reviewed chat and assessment records. The default `certweaver.yml` is
absent and `inventories/` contains only `.gitkeep`; this does not prove that no
external/private staging exists. All **24 objective targets** remain
unapproved. All **100 control owners and independent reviews** still need
assignment and authenticated proof. The organization-specific evidence/identity/
review backend described in [the evaluator contract](enterprise-evaluator.md)
also remains unimplemented for the actual organization.

Required next inputs are the actual staging configuration path and approved
access references, the immutable release/deployment/support profile, accountable
owners and independent authorities, all 24 measured objectives and approved
exercise boundaries. Then execute and accept the complete catalogue: real
deployment and remote privilege checks; certificate/consumer lifecycle and
denied requests; effective IAM/custody/isolation; fault/failover/quorum and
off-host replacement-host restore with RTO/RPO; telemetry/responder handoff;
load/renewal bursts/soak; hosted signing/provenance/consumer qualification and
protected retention. `gap-register.json` gives the exact acceptance criteria,
verification, evidence and owner/reviewer role for every one of the 100 controls.
The final score requires fresh subject-bound proof, all twelve category gates,
all activated conditional gates and authorized production approval.

The fresh evaluator result remains **NOT ASSESSED: zero accepted assurance
points, 100 unassessed controls, twelve UNKNOWN category gates and
NOT_APPROVED production status**. Zero accepted points do not measure the
software's quality as zero; they state that enterprise acceptance prerequisites
have not been established.

## Managed endpoint verification — preceding checkpoint

| Check | Observed result | Boundary |
|---|---|---|
| Windows Python 3.12.14 | 890 passed, 13 platform-specific skips | Fresh full suite on the corrected frozen source |
| Linux Python 3.11.18 / 3.14.4 | 903 passed on each interpreter | Fresh full suites, run unprivileged |
| Statement coverage | 1259 / 1351 = 93.190229% on Windows and Linux 3.11; 1260 / 1351 = 93.264249% on Linux 3.14 | Runtime package only; helper filesystem behavior tested separately |
| Branch coverage | 597 / 680 = 87.794118% | Separate exact 90% statement / 85% branch floors passed |
| Ansible Core 2.19.14 / 2.21.5 | Production lint: zero failures/warnings; 100 processed / 106 encountered; seven playbooks each | Fresh corrected-snapshot execution; fourteen syntax checks |
| Private kubeconfig export | 23 actual Ansible observations per Core; 23 export-guard and 3 CI-gate mutations | Fresh corrected snapshot; synthetic credentials and local root controller |
| Managed operator endpoint | 22 observations per Core, including 15 actual TLS client cases; 19 preparation-guard mutations | Quoted YAML, selected context, repeat/rotation, failure preservation, wrong CA/name/token; no live VIP or cluster |
| Managed versions / health | Historical 74 version/fleet and 60 health/progression cases per Core | Relevant role/playbook/helper inputs unchanged; TLS/API and preparation/handler markers only |
| Chart acquisition / baseline | Historical 15 acquisition cases and five official baseline charts per Core | Unchanged inputs; no admission or cluster proof |
| Git / HTTPS acquisition | Historical 19 Git and 9 HTTPS cases per Core | Local fixtures with unchanged helper inputs |
| Container configuration | Historical 18 decisions and 9 rejected inputs per Core | No image pull, container or service operation |
| Source declarations | 65 declarations in 71 inspected files; zero guard errors | Complete approved deployment inventory remains open |
| Example configurations | Default and all eight examples valid | Expected missing-secret warnings retained |
| Ruff / YAML / workflow contracts | Passed on current frozen source | Includes mandatory export gate and workflow mutation checks |
| GitHub workflow syntax | Four workflows passed pinned actionlint 1.7.12 freshly | Shellcheck disabled; no hosted execution |
| Wheel / compressed sdist | Byte-identical on Python 3.11–3.14 with fresh checkout/environment reconstruction on each | 126 exact resources; explicit positive/digest-negative candidate oracle passed |
| Source/lock security | 12 inventories reconciled across 36 profile/platform/Python environments; all 253 committed fixture files bound | Real tools/current database and 0-clean/6-secret controls; no complete SAST or OS/image claim |
| Failure diagnostics / retention | Historical focused and five real CLI rejection paths; current full suites rerun unit cases | Source-failure implementation/lock/tool inputs unchanged; raw matches stay private |
| Cosign / issuer keys | Historical vendor signature and issuer-key probes | No actual GitLab signing, token issuance or hosted job |

All three full suites above are fresh executions of the corrected final snapshot.
The thirteen Windows skips comprise the earlier four platform cases plus nine
POSIX credential-filesystem cases. Every full suite has one expected Python ZIP
warning from the intentionally duplicated-member rejection fixture.

Both native Ansible profiles ran freshly against the corrected final snapshot.
Each passed production lint, seven syntax checks, 23 private export observations,
and 22 managed endpoint observations. Fifteen endpoint observations per Core
use the real pinned client against a synthetic authenticated TLS API. Positive
cases preserve credentials, CA, other contexts and the distribution source;
the full preparation/export repeat run reports zero changes. Rotation updates
the file. Invalid context, TLS-bypass/proxy settings and malformed endpoint
inputs preserve the prior operator file and prevent progression to export.
Wrong CA, TLS server name and token are rejected by the actual client/API.
This proves the local task/client behavior, not actual VIP reachability or
trusted production cluster identity. Synthetic credential canaries are absent
from verbose/diff and client logs; private staging is cleaned on success/failure.

The initial endpoint probe failed because its synthetic server compared the
whole request target with `/readyz`. The pinned client sends a timeout query
parameter. A retained independent reproduction verifies that the synthetic
token matched and that raw-target routing returned 401 while parsed-path routing
returned 200. The corrected fixture uses the parsed URL path and preserves the
same exact token check. A subsequent multi-context assertion incorrectly
required named entries to retain list order. The pinned client sorts those
records. A separate real-client reproduction confirms that every field was
preserved by unique name; the comparison now follows that contract and rejects
duplicates. Six tests cover order, duplicate names and changed trust/credentials.
Those two fixture corrections preserved production role bytes. A later staged
postcondition caught `kubectl --server` clearing an explicit TLS server name.
Publication stopped before that changed trust configuration reached the final
file. The corrected role passes the original TLS name explicitly and additionally
rejects source/destination device-inode aliases. Valid explicit TLS names work;
incorrect names remain subject to certificate validation and are rejected by
the real client. Another native run stopped at the mandatory Jinja spacing rule;
a task-scoped reference fixes the expression without suppressing the rule.
All four failed native attempts and four reproductions remain bound by
`failure-history.json`; no trust/authentication condition was relaxed.

The preceding private-export checkpoint retains its separate sdist manifest
omission and correction. The current 126-resource payload includes both explicit
allowlists and passes the full packaging and reconstruction checks.

Managed version/health, chart/Git/HTTPS/container, source-failure and crypto
observations remain historical with reviewed unchanged relevant inputs. The
health fixture replaces the add-on role with a progression marker; the new
export tasks have their own native fixture. Existing rolling-health proof does
not establish real OS/service mutation, workload evacuation, quorum safety or
availability budgets. The current actionlint, package/reconstruction, qualifier,
handoff and source/lock scans are fresh. All native work uses owned disk-backed
`/var/tmp` with private child `TMPDIR`; the earlier ENOSPC and unretained failure
remain documented in their original checkpoints.

Local evidence is retained in ignored `.certweaver` paths:

- **Managed-endpoint checkpoint:** `operator-endpoint-20261103/attempt-4/verification-summary.json`
  binds 215 execution inputs, fresh three-platform full suites/coverage, both
  fresh Ansible profiles and 90 export/endpoint observations, the four-version
  126-resource package reconstruction, real qualifier/handoff, source/lock scan,
  candidate digest oracle and retained failure history. `ansible-311/` and
  `ansible-314/` contain native reports; `../probe-1/`, `../attempt-1/` and
  `../attempt-2/` and `../attempt-3/` retain failed checks and their exact corrections.
  All 100 controls remain unassessed, accepted credit is zero, twelve
  category gates remain unknown and production is NOT_APPROVED.

- **Private-export checkpoint:** `kubeconfig-export-20261103/attempt-2/verification-summary.json`
  retains the preceding 878-case suites, 125-resource reconstruction and
  byte-matched native probe reuse. Its first attempt's omitted sdist resources
  and manifest-only correction remain recorded separately. It does not provide
  actual remote SSH/become, cluster or independent acceptance.

- **Rolling-preparation checkpoint:** `rolling-preparation-20261103/attempt-1/verification-summary.json`
  retains the preceding 825-case suites, exact coverage, 74 version/fleet and
  60 health/progression cases per Core, including 23 three-node fleet cases.
  Preparation, handler, final readiness and late precheck failures stop later
  nodes and add-ons; fresh install and same-version repair were covered locally.
  Actual host mutation, cluster safety and independent acceptance remain open.

- **Source-diagnostic checkpoint:** `source-diagnostics-20261103/attempt-1/verification-summary.json`
  binds the current frozen source, fresh 811-case suites, exact coverage,
  four-version package reconstruction, real artifact qualification/handoff,
  source/lock positive and five negative CLI cases, candidate digest oracle,
  source/policy AST review and prior unchanged Ansible/deployment proofs.
  `capacity-incident.json` and `retained-source-security/` preserve the current
  ENOSPC failure. `source-security-results/`, failure-case directories and
  `retained-recheck-source-security/` preserve the disk-backed rerun and failures;
  the two `*-finally.json` receipts distinguish their cleanup/retention paths.
  `failure-seeded-source.bundle` is only a private synthetic negative fixture,
  never a release. `invocation-correction.json` also records an earlier local
  pytest basetemp-parent setup error and its corrected focused runs.
  The complete zero-credit gap register and fresh enterprise evaluation remain
  unassessed. No hosted signing, deployment or independent acceptance occurred.

- **GitLab implementation checkpoint:** `gitlab-release-20261103/attempt-2/verification-summary.json`
  binds the corrected frozen source, current full Linux suites, reviewed Windows
  reuse, both fresh Ansible lint/syntax profiles, four-version package matrix,
  real artifact qualification/handoff, exact digest-rejection oracle, current
  source/lock scans, four vendor-signature probes and public issuer-key fetch.
  It audits the historical native-fixture manifest and keeps its execution scope
  separate. `attempt-1/result.json` retains both failed POSIX fixture runs and the
  successful original Windows suite. `gap-register.json` preserves every control's
  original criteria, required evidence/review, owner role and zero accepted credit.
  Public vendor inputs are retained in the parent folder. No actual GitLab token,
  signing job, hosted pipeline, live deployment or independent acceptance occurred.

- **Maintained-baseline checkpoint:** `maintained-baseline-20261103/attempt-4/verification-summary.json`
  binds the normalized execution files, fresh two-Core native/Helm results,
  full-suite and coverage reports, package/reconstruction matrix, real-tool
  artifact qualifier/handoff and positive/digest-negative probe. The full
  `gap-register.json` retains every control's original acceptance criteria,
  required evidence/review and zero accepted credit. `baseline-input-evidence.json`
  binds official input receipts and the two unprivileged vendor CLI probes;
  `windows-reuse-review.json` defines its explicit suite reuse boundary.
  Earlier schema diagnostics are retained in the baseline folder; corrected
  verifier assumptions and a private driver path error remain in preceding attempts. No actual cluster,
  native Windows/WinRM deployment, hosted pipeline or independent approval ran.

- `running-identity-20261103/attempt-1/` contains the latest frozen source,
  661-case suites, exact coverage, both production lint/syntax sets, 90 current
  real-client health/progression observations, 148 current version-gate
  observations, supplemental target/privacy proof, package matrix, exact digest
  rejection and real scanner/handoff qualification. Its manifest binds current
  execution sources/results, the explicitly reused adapter/workflow records and
  the complete zero-credit assessment/gap register. No real cluster, service
  upgrade, outage, quorum test or independent acceptance occurred.
- `cluster-transitions-20261103/attempt-2/` contains the preceding corrected source,
  652-case full suites, exact coverage, both production Ansible lint/syntax sets,
  package/reconstruction matrix, real scanner/handoff qualification, explicit
  artifact-digest rejection and zero-credit assessment/gap register. Its manifest
  binds the native version/health results and both source-comparison reviews.
  `attempt-1/` retains the six obsolete unit-test failures on each platform;
  the gate fixtures passed there and their execution inputs are unchanged.
  The upstream CLI formatting observations are source inspections, not actual
  product execution or publisher-signature approval. No real server installation,
  cluster upgrade or recovery was performed.
- `cluster-health-20261103/attempt-2/` contains the preceding frozen source,
  607-case suites, exact coverage, both Ansible lint/syntax sets, 52 real-client
  health/upgrade-boundary observations, package/reconstruction matrix, explicit
  candidate digest-rejection proof and real scanner/handoff qualification.
  The manifest binds current source/results, separately identified reused
  adapter fixtures, the change-impact record and the full zero-credit gap
  register. `attempt-1/` retains the failed synthetic routing case and its
  obsolete source/results. No service restart, real upgrade or production
  approval occurred. The fixture client version does not change the deployment
  baseline or establish client/server-skew qualification.
- `chart-acquisition-20261103/attempt-1/` contains the preceding frozen source,
  587-case suites, exact coverage, both Ansible lint/syntax sets, thirty actual
  chart fixture observations, Git/HTTPS/container fixtures, exact-source package
  matrix and real scanner/handoff qualification. Its explicit pinned-interpreter
  probe accepts the original candidate and rejects changed package bytes for
  the expected digest reason. The source/report manifest binds all of these;
  the gap register still preserves all 100 unaccepted controls. Parent-folder
  baseline archives and metadata retain the five actual add-on observations,
  awaiting independent source/support decisions. No upstream application,
  Kubernetes release, hosted CI or production environment was exercised.
- `git-acquisition-20261103/attempt-3/` contains the preceding corrected source,
  suites, exact coverage, Ansible lint/syntax, Git/HTTPS/container fixtures,
  package/reconstruction matrix, source declarations and real scanner/handoff
  integration. The gap register preserves all 100 remaining acceptance criteria,
  methods, evidence and owner/reviewer requirements with no assurance credit.
  `attempt-1/` records the failed TLS-bypass attempt; `attempt-2/` records the
  installed-resource failure, its bytecode diagnosis and the canceled obsolete
  matrix. No failure is represented as a successful production qualification.
  The final manifest binds source/results and identifies reused unchanged
  Compose inputs. All source commits and artifacts remain synthetic fixtures.
- `container-pins-20261103/` contains the preceding 518-case frozen-source suites, exact
  coverage, Ansible checks, container configuration/decision and HTTPS fixtures,
  actual offline Compose parsing, current source declarations, package
  reconstruction/matrix and real scanner/handoff integration. Its gap register
  retains every control's full remaining criteria, evidence, method and owner/
  reviewer roles. The fresh enterprise evaluation remains unassessed. The
  manifest binds normalized execution-relevant source and local reports; these
  records provide no actual deployment or independent production acceptance.
- `adapter-acquisition-20261103/` contains the preceding 474-case frozen-source suites,
  coverage, both Ansible lint/syntax sets, the eighteen HTTPS case results,
  source declaration inventory, exact-source package/reconstruction receipts,
  compatibility matrix, real scanner/isolated-handoff qualification and explicit
  positive-candidate/changed-digest rejection probe. Its fresh enterprise
  evaluation still records 100 unassessed controls and twelve unknown gates.
  `gap-register.json` preserves the full criteria, verification, required
  evidence and owner/reviewer roles for every control, with candidate code
  pointers and zero awarded assurance credit. All commits and artifacts are
  synthetic local fixtures; `verification-summary.json` binds the results and
  normalized execution-relevant source files.
- `reproducible-builds-20261103/` contains the prior 427-case full-suite results, exact-source
  build/reconstruction receipts, an explicit candidate-digest rejection probe and
  the complete real scanner/isolated-handoff integration. All commits and package
  hashes in this folder belong to a synthetic local fixture, not an approved release.
  Its `verification-summary.json` binds 152 execution-relevant source files and
  the suite, reconstruction, matrix, explicit digest-rejection and real-tool
  qualification reports to their hashes.
- `dependency-locks-20261103/` contains the earlier frozen source, clean Windows
  and Linux JUnit/coverage reports, pinned-tool/runtime acquisition records,
  Ansible logs, build matrix and source-archive timestamp comparison. Its
  `verification-summary.json` binds the final results; these are local proofs,
  not hosted CI, approved dependency selection or independent assurance.
- `evidence-handoff-20261103/verification-summary.json` binds the previous 365-case
  Windows/Linux reports, exact source snapshot and real-tool synthetic integration.
  The folder also contains the derived qualification record, original database
  metadata and isolated-handoff/inventory-substitution probe results. These are
  local implementation proofs; they are not an actual release or independent review.
- `qualification-20261103/verification-summary.json` binds the previous Windows
  and Linux reports and complete synthetic integration result to their hashes;
  128 execution-relevant source files match the tested snapshot. Its fresh
  enterprise evaluation records 100 unassessed controls and twelve unknown gates.
- `pytest-enterprise-policy-windows.xml` and
  `enterprise-policy-coverage-windows.json`.
- `enterprise-final-validation-20261103/` containing the Linux test, coverage,
  collection, Ansible lint/syntax and configuration-validation outputs.
- `enterprise-policy-package-build.log`, `enterprise-policy-wheel-smoke.log`
  and `enterprise-policy-release-20261103/` for the local distributions.
- `enterprise-baseline-20261103/assessment.json`, `evaluation.json` and
  `gap-register.json`. The last file maps **each of the 100 controls** to its
  acceptance criteria, required verification, required evidence and owner/review
  roles. Candidate implementation pointers grant no maturity credit.

## Exact remaining work for enterprise 100/100

Every row below still needs control-by-control acceptance and authenticated
review. The [complete catalogue](enterprise-production-readiness.md#7-control-catalogue)
and local gap register preserve the individual requirements; no category or
conditional gate is removed to raise the score.

| Controls | Required result still to establish | Accountable role |
|---|---|---|
| GOV-01–06 | Freeze the actual release/profile, support claim, environment/dependency boundaries, accountable people, numeric objectives, approved methods, threat/risk/change policy and ownership continuity. | Service owner |
| CFG-01–08 | Prove actual deployment targeting, prerequisites, safe execution, repeated convergence, drift/partial-failure handling, supported upgrades/rollback and installed CLI behavior for the frozen profile. Local tests are candidate evidence. | Platform automation owner |
| PKI-01–14 | Qualify the selected issuer and complementary adapter roles: allowed/denied requests, custody, actual consumer certificate delivery, renewal/adoption, rotation, invalidation, trust rollover and retirement. | PKI authority |
| SEC-01–12 | Verify effective identity/permissions, tenant and network isolation, secret handling, host/workload policy, protected audit, incident access removal and approved abuse limits. | Security owner |
| HA-01–10 | Execute approved node/process/webhook/backend/dependency/partition/maintenance scenarios with client-observed budgets, quorum/ownership safety, cleanup and convergence. Use the approved external-LB path if applicable. | Platform/SRE owner |
| DR-01–10 | Retrieve off-host backups and restore to isolated replacement infrastructure, prove bootstrap/key/custody continuity, independently accessible recovery, integrity and measured RTO/RPO. | Recovery owner |
| SUP-01–10 | Qualify the actual candidate's acquisition/pins, complete inventory/licenses/SBOM, clean/reproducible builds, consumer-side provenance verification, least-privilege release identities and executed security release gates. | Release engineering owner |
| TST-01–08 | Run the approved critical cases, repeatable end-to-end harness and selected compatibility/upgrade matrix in real CI and representative staging. Local coverage floors now pass, but full TST-01 assurance is pending. | Quality/verification owner |
| OBS-01–08 | Prove end-to-end service signals, certificate-lifetime-aware alerts, missing-data detection, dashboards, independent audit where required, real technical notification delivery and release-policy telemetry. | Observability/SRE owner |
| OPS-01–06 | Exercise accountable responder triage/escalation/handoff, runbooks, controlled credentials, change/maintenance and sustained operational ownership. | Operations owner |
| PERF-01–04 | Approve the demand model and budgets; execute sustained/degraded load, renewal storms, backlog recovery, quotas/headroom and endurance/growth tests inside approved load boundaries. | Capacity/performance owner |
| EVD-01–04 | Integrate and qualify the real approval/evidence backend; verify current exact-subject original evidence, independent review, change invalidation and authenticated release decisions; independently reproduce the final evaluator result. | Independent assurance owner |

The eight conditional gate decisions remain unknown: PKI-10, PKI-13, SEC-11,
DR-03, DR-09, TST-06, OBS-06 and OBS-08. The service/security/recovery owners must
freeze and review applicability before their relevant tests. Inactive gate
status does not award a point; these controls still require assurance for 100.

## Required external inputs and release boundaries

No actual `certweaver.yml` or staging access reference has been supplied.
The example-relative token, Keepalived authentication and etcd S3 credential
files are absent. No placeholders were manufactured. Before live work, provide
the real staging configuration/access references, selected adapter/issuer and
support matrix, numeric service/recovery/capacity/response targets, approved
fault/load boundaries and accountable independent authorities. Secret values
must remain in the approved secret system or restricted files.

The managed-LB SELinux prerequisite remains a host-owner policy decision. The
role checks policy without broadening it. Reviewed issuer manifests and working
monitoring/notification dependencies also need to be present for their live
qualification paths.

Remaining repository work includes maintainer approval, licensing/support review
and acquisition review of the implemented Python hash locks; the approved
production build-input inventory and independent acceptance of the implemented
normalization/reconstruction policy;
protected retention of original hosted qualification evidence/database
metadata, hosted SAST execution with complementary source-language coverage
and finding disposition, and durable versioned publication policy. The
GitLab signing/source-security/consumer path now exists as implementation/local
proof; actual hosted signing, approved protection/runner/job-token settings and
independent consumer qualification remain required on the actual project.

The new source declarations are not a complete resolved dependency inventory.
Git revisions, chart content, container image identities, OS repository inputs
and transitive dependencies still require immutable candidate reconciliation,
acquisition/support review and ownership/license acceptance. Posh-ACME exact
version selection still needs publisher/package-trust qualification. Review the
upstream version baseline for support and advisories before selecting an actual
release. The five observed core-chart archive hashes are recorded; independent
publisher-trust, support and organizational acceptance remain required.
Full Git identity enforcement and local payload checks now exist; actual
upstream commit resolution/trust review, selected-version installation and
complete runtime/submodule dependencies remain unqualified. Git clone history
and retained per-commit cache capacity/retention also need the deployment
profile's operating policy. Verified cache reuse is not upstream approval.
Verified chart-content acquisition now exists for every Helm install path.
Selected adapter chart hashes, publisher/provenance trust, embedded subcharts
and rendered image/runtime dependencies still require candidate reconciliation.
Actual chart upgrades, rollbacks and cluster behavior remain unqualified.

Numeric no-downgrade/no-minor-skip gates and authenticated local API/node
identity gates now exist, including installed/running consistency before changes
and exact selected identity afterward. Actual upgrade qualification remains open: review and staging
proof of the selected sequential release path and component skew, workload evacuation,
etcd member/quorum health, recovery checkpoints, rollback and client-observed
availability must be implemented/qualified for the approved profile. Local
readiness success does not establish those properties.

The Kubernetes 1.33 example-baseline issue is now addressed in repository
defaults with the dated stable-channel 1.36.5 releases and cert-manager 1.21.3.
The [baseline contract](platform-baseline.md) records current primary sources,
archive/script digests, offline assumptions, corrected chart settings and
ingress ownership. This replaces an EOL upstream example choice; it does not
complete advisory disposition or establish vendor entitlement, safe transitive
downloads/images, supported OS/architecture/CNI behavior or real installation.
Existing clusters still require reviewed sequential minor upgrades, the
cert-manager RBAC/metrics migration review, and a staged ingress/CRD ownership
migration with recovery evidence before applying these settings.

The root working tree remains uncommitted relative to its original main base;
the isolated review candidate has been committed and published to draft PR #7.
The dated checkpoint above distinguishes actual hosted results from local
proof. Actual GitLab candidate execution, a published SBOM, approved signed
provenance verification, a final immutable release and an authenticated
production decision remain unproved. The frozen-source local audit used a fresh database and reconciled all
declared lock environments; it is not a security disposition for an approved
production release. Local success must not be presented as the missing hosted
results or as qualification of every advertised adapter/platform.

Final completion still means **all 100 controls at current assured level 4**,
all twelve category gates and activated conditional gates passing, complete
release/environment-bound proof, no unresolved criterion substitutes, and
authenticated independent review and authorized production approval.
