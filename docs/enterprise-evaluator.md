# Enterprise assessment evaluator

The enterprise v1 evaluator is implemented in `src/certweaver/enterprise.py`.
It is separate from the older `certweaver score` rubric. Implementing this
evaluator does not establish that any deployment satisfies the enterprise
framework or that EVD-04 has received independent assurance.

## Local commands

Create a blank assessment in a restricted working location:

```sh
certweaver enterprise-init -o .certweaver/enterprise/assessment.json
certweaver enterprise-score .certweaver/enterprise/assessment.json
certweaver enterprise-score .certweaver/enterprise/assessment.json --json
```

Initialization refuses to overwrite an existing file. Scoring reads the
assessment and evidence without modifying either. Exit 2 means incomplete or
invalid; exit 0 requires a fully assured, authorized result. The JSON export
contains the evaluator/catalogue versions, evaluation time, scope and review
digests, category totals, gate decisions, every control's claimed and accepted
level, owner/evidence/review references, and specific limitations.

The untouched template has **zero accepted proof**, 100 unassessed controls,
and twelve unknown gates. This is not a measurement that operational readiness
is zero. No authenticated production assessment has been performed.

## Trust boundary

The CLI intentionally has no organization-specific approval backend. It cannot
turn names, URLs, JSON approval objects, file hashes, or declared PASS values
into authenticated approval, and cannot award positive maturity credit on
that basis. It does not execute an assessment-selected plugin or fetch an
assessment-selected URL. There is no `--trust-all` or self-approval option.

An organization must integrate the Python `AssuranceBackend` protocol through
a controlled application/job, configured outside the assessment. The backend
must query its authenticated approval system and enforce:

- Current approval state, withdrawal/revocation, authorized actor identity,
  required domain role, separation of duties, and approval validity.
- The exact requested purpose and payload digest. An approval for another
  control, level, release role, subject, or revision cannot be substituted.
- Cumulative maturity semantics, actual execution methods, numeric objective
  interpretation, complete criterion coverage, and sufficiency of original
  evidence. A hash match alone cannot prove that a live test occurred.
- Approved access, retention, classification and network policy for controlled
  evidence. `evidence()` must enforce its own download size/time limits and
  return verified bytes or deny access. The evaluator rechecks the hash and
  rejects empty content or content over 64 MiB; it does not print the content.

`Approval` responses carry canonical actor identity and timezone-aware issue
and expiry times. The backend returns `None` on uncertainty. Service failures,
exceptions, expired/future approvals and self-review fail closed. The unit
test authority is explicitly a logic fixture; it must never be used as an
operational backend. Adding an editable trusted-names file would not satisfy
this boundary.

The integration remains **required and unimplemented for any actual
organization**. Backend qualification must include real identity/role,
withdrawal, changed-payload, wrong-purpose and denied-access exercises. A
second AI review does not supply that authority.

## Binding contract

`canonical_digest()` hashes UTF-8 JSON with sorted keys, compact separators,
unescaped Unicode, and no NaN/Infinity. Duplicate JSON keys are rejected before
validation. Maximum assessment size is 16 MiB. The v1 catalogue and structural
schema bytes are pinned in the evaluator; changing them requires an explicit
versioned implementation change rather than a path in an assessment.

`scope_digest()` binds the framework ID/version/digest, complete subject,
approved objectives, and conditional gate decisions. Keys ending in
`ApprovalRef` (case insensitive) are recursively omitted to avoid circular
references to approvals of that payload. Scope approval must precede evidence
observation and run authorization must precede execution. All source records'
`subjectBindingSha256` values must match this digest. Final release subject
identity requires a full Git commit, no working-tree patch, complete resource,
configuration, pipeline and packaging digests, and artifact digests/provenance
references.

`review_digest()` binds every assessment field except `$schema`, the derived
`results` and `gates` summaries, the `approvals` locator objects, and
`auditTrail`. Approval-reference keys are recursively omitted. This binds
criterion observations, maturity claims, ownership, evidence metadata/digests,
verification runs, findings, exceptions, change reviews and FINAL/DRAFT state.
Changing a covered claim invalidates existing domain and release approvals.
Audit entries are checked separately against their controlled record and the
review digest. Gate membership comes from the pinned catalogue, and gate
approval is requested for its exact gate purpose against the review digest.

The backend receives the following purpose strings:

| Purpose | Payload |
|---|---|
| `scope` | Scope digest |
| `objective:OBJECTIVE_NAME` | Scope digest |
| `applicability:CONTROL_ID` | Scope digest |
| `run:RUN_ID` | Scope digest; authorization must precede run start |
| `evidence:EVIDENCE_ID` | Review digest; approval follows collection |
| `control:CONTROL_ID:level:N` | Review digest; domain reviewer attests cumulative level N |
| `gate:G-NN` | Review digest; independently reviewed category decision |
| `closure:findings:ID` / `closure:exceptions:ID` | Review digest; disposition follows closure |
| `change:ID` / `audit:ID` | Review digest |
| `release:ROLE` | Review digest; role approval follows control assurance reviews |

The domain approval service must retain the inspectable payload corresponding
to each digest. Receiving only a digest does not itself establish the truth of
its records. Actor references must use canonical identities so aliases cannot
bypass independence checks.

## Evaluation rules and boundaries

The evaluator checks all 100 one-point records and exact immutable criteria
through the pinned schema, then recomputes accepted quarter-point credit.
An observed failed criterion receives zero. A blocked control may retain a
proved lower level. Declaring a lower level alone earns no credit: scope,
ownership, subject-bound evidence and a trusted cumulative domain review are
required. Levels 3 and 4 additionally require passing criterion/run coverage,
valid chronology, and current verification; level 4 requires current
independent assurance and accepted ownership.

Local evidence must be a regular nonempty file under the bundle; absolute,
drive-qualified, parent-traversal and backslash paths, symlinks, missing files,
digest mismatches and synthetic deployment evidence are rejected. Controlled
locations require the independently configured backend. All evidence and runs
are inspected, including unreferenced records. Failed records cannot be hidden
by deleting their references. Preserve earlier failed assessment revisions in
controlled history and produce a new, reviewed corrective revision.

Evidence obeys both its declared freshness window and its control's window;
an editable expiry date cannot extend either. Windows are 90 days for policy,
7 days for candidate CI, 24 hours for security disposition, 30 days for live
qualification/review, and 365 days for provider standing. The schema has no
typed discriminator for mixed CI/live observations, so v1 conservatively
applies the seven-day limit to `mixed7_30`. The provider's release applicability
still requires a review within 30 days at assured level. Approved policy
equivalents require a separately authorized versioned profile/integration;
there is no runtime switch that silently relaxes these defaults.

Gates use the pinned mandatory controls and authenticated conditional
decisions. All required controls must be current level 4, with separate gate
approval. Full score additionally requires all 100 controls, even when a
conditional gate is inactive. Open findings prevent credit for their affected
controls. Open P0/P1 findings and unresolved criterion exceptions prevent final
approval. CLOSED records require authenticated closure and inspectable proof.
Change-impact records require disjoint, complete control coverage and the
current subject; unsupported evidence reuse remains rejected.

Stored totals, control counts and gate verdicts are checked against recomputed
records. An invalid assessment envelope grants zero accepted points and
exports the original claims plus rejection reasons. This conservative rule
prevents a misleading accepted 100 accompanied by an authorization error.
Conditional production approval is not issued by this implementation; an
incomplete result remains NOT_APPROVED. Partial accepted credit is still
reported when its assessment envelope and lower-level proofs are valid.

The evaluator cannot independently authenticate local files, prove observations
from arbitrary text, discover an omitted real-world incident, decide whether
an organization froze adequate objectives, or perform the live tests. Those
responsibilities remain with the controlled evidence/approval integration and
accountable independent reviewers. Final qualification must exercise that
integration and independently reproduce the assessment before EVD-04 is
assured.
