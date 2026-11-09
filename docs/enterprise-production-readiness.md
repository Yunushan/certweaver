# CertWeaver enterprise production readiness framework

**Version:** 1.0.0

**Prepared:** 2026-10-26

**Maximum:** 100 points, comprising 100 one-point controls

**Purpose:** A rigorous acceptance contract for a future implementation and deployment goal

**Current enterprise assessment:** NOT ASSESSED

**Implementation update, 2026-11-03:** A separate enterprise evaluator core and
adversarial regression suite now exist. See the [evaluator contract and current
integration boundary](enterprise-evaluator.md). The original framework and
catalogue below retain their version 1.0.0 acceptance rules. No enterprise
control has been granted organizational assurance by this implementation work.

This framework defines the evidence required to call a named CertWeaver release
and production deployment profile enterprise-ready. It covers the delivered
software, privileged automation, certificate lifecycle, infrastructure,
dependencies, recovery, operations, and organizational approval. A premium
result means demonstrated behavior and accountable operation, not a polished
repository or a larger test count.

The framework is an engineering assurance model. It does not confer regulatory
certification, an external audit opinion, a contractual SLA, or a guarantee that
failures cannot occur. Its thresholds and governance rules are proposed policy
for this framework; they are not represented as universal requirements from
NIST, Kubernetes, SLSA, or an upstream CA vendor.

## Contents

- [How to use the package](#1-how-to-use-this-package)
- [Assessment scope](#2-what-is-being-scored)
- [Scoring mechanics](#3-scoring-mechanics)
- [Release gates and production decisions](#4-release-gates-and-production-decisions)
- [Evidence contract](#5-evidence-contract)
- [Service objectives](#6-service-objectives-to-approve-before-grading)
- [100-control catalogue](#7-control-catalogue)
- [Execution roadmap](#8-execution-roadmap-for-a-future-goal)
- [Assessment and evidence layout](#9-required-assessment-and-evidence-layout)
- [Evaluator acceptance cases](#10-evaluator-requirements-and-adversarial-acceptance-cases)
- [Findings and requalification](#11-exceptions-findings-and-requalification)
- [Relationship to the existing score](#12-relationship-to-the-existing-certweaver-assessment)
- [Future goal](#13-ready-to-copy-future-goal)
- [Primary references](#14-primary-references-and-design-boundaries)

## 1. How to use this package

1. Freeze the release, deployment profile, support claims, trust boundaries,
   owners, and numeric service objectives before awarding points.
2. Copy the blank assessment template and evaluate every control honestly.
3. Implement gaps, execute the specified verification, and retain both failures
   and successful reruns.
4. Obtain authenticated independent review of the evidence and the release
   decision from the responsible authorities.
5. Recompute the score and every release gate from the underlying records.
   Missing evidence, expired evidence, or an unknown mandatory gate prevents
   a claim of 100/100.

Package files:

| Artifact | Purpose |
|---|---|
| [Control catalogue](readiness/enterprise-controls.v1.json) | Authoritative IDs, weights, acceptance criteria, evidence, verification steps, ownership roles, freshness policies, and gate designations. |
| [Assessment template](readiness/enterprise-assessment.template.json) | Blank, explicitly unassessed assessment for the future release and environment. |
| [Assessment schema](readiness/enterprise-assessment.schema.json) | Structural contract for assessment data, including a requirement for all 100 control slots. |
| [Future goal prompt](enterprise-production-readiness-goal.txt) | Ready-to-copy objective and definition of done for a future goal. |

**Implementation boundary:** These files define a new framework. The current
`certweaver score` and `certweaver score --evidence` commands implement the
existing repository scorecard, not this 100-control framework. This package
does not silently change CLI behavior, replace the prior assessment, or start
a new goal. The separate evaluator implementation now has an
[explicit integration and qualification contract](enterprise-evaluator.md);
EVD-04 still requires its complete independent verification. An independently
audited manual assessment may track interim
progress, but cannot claim EVD-04's full credit before its evaluator requirements
are satisfied. JSON Schema validates structure, not the truth of an artifact
or the identity of a person named in a file.

## 2. What is being scored

The default scope is the **production RKE2 HA profile plus the explicitly
selected production adapters and issuer paths**. A score belongs to an
assessment subject, never to an unqualified product name.

Freeze at least these identifiers:

- Product version, full Git commit, source provenance, and final artifact
  digests. During development, retain the working-tree patch digest as well;
  final release approval requires an immutable committed subject.
- Framework version, catalogue digest, assessment/profile ID, and the intended
  assurance claim: new production launch or operation of an existing service.
- Deployment YAML digest, effective/rendered configuration, inventory,
  deployment resources, CI definitions, build/packaging definitions, approved
  host baseline, and organization policy revisions.
- Controller Python/Ansible versions, OS/architecture, Kubernetes distribution
  and version, charts, images, collections, adapter versions, and external CA,
  DNS, identity, storage, logging, and monitoring dependencies.
- Target environment, tenant and trust domains, protected failure domains,
  endpoints, expected demand, approved SLO/RTO/RPO values, and maintenance and
  fault-injection boundaries.
- Accountable service, platform, PKI, security, recovery, on-call, release, and
  independent assessment owners, with the approval authority for each.

Do not convert a deployment-specific result into a product-wide claim. A
validated cert-manager deployment does not qualify every one of the twenty
adapters. A product-wide claim requires evidence for the complete advertised
support matrix. Conversely, do not force installation of an unselected CA or
Windows component into an RKE2 deployment merely to create artificial evidence.
Declare scope accurately and preserve all support claims the future goal
explicitly includes.

### Launch readiness and operating readiness

For a new service, approve a representative staging qualification and soak
window before testing. It must include the modeled renewal and backup overlap,
failure cases, and workload, rather than a brief idle observation. Record the
window numerically; unknown duration cannot pass PERF-04. A starting
proposal of 72 hours is a planning example, not proof of a monthly SLO and not
an automatic pass threshold.

For an existing service, use the agreed operational observation window, normally
a rolling multi-week window, and include real incidents, missing telemetry,
and consumer impact. Do not relabel an existing unhealthy service as a new
launch to discard its adverse evidence. The selected claim and observation
requirements must be fixed in GOV-01 and GOV-03.

## 3. Scoring mechanics

Every control has a maximum weight of **1.00 point**. There are exactly 100
control slots, and the denominator is always 100 for this version.

| Level | Credit per control | Required proof |
|---:|---:|---|
| 0 | 0.00 | Not assessed, inadequate current evidence, or an observed failure of acceptance criteria. Distinguish UNKNOWN from a known FAIL in the status record. |
| 1 — Defined | 0.25 | Scope, accountable owner, acceptance criteria, dependencies, and verification procedure are approved and recorded. |
| 2 — Implemented | 0.50 | Required implementation/process artifacts exist at the assessed revision, and applicable static/unit or document inspections pass. This does not prove live effectiveness. |
| 3 — Verified | 0.75 | Every specified acceptance check, including required negative and failure cases, passes using the required method in the representative environment. Expected and observed results are traceable. |
| 4 — Assured | 1.00 | All preceding requirements hold; evidence is current, release-bound, complete, and independently reviewed through an authenticated approval process. Operational ownership is accepted. |

Levels are cumulative. One successful happy-path demonstration cannot skip
missing authorization, failure, recovery, or ownership checks. An observed
acceptance failure earns zero until it is corrected and the failed acceptance
case is reverified. Existing valid lower-level evidence may be retained for a
blocked control, but infrastructure unavailability does not create credit.

For governance controls, an implemented artifact is an approved policy or
process; verification is its specified inspection, sampled operation, or
exercise. Do not invent a meaningless runtime test for a policy document.
For live controls, source files, mocked subprocess calls, and configured
workflows are not live evidence.

```text
verified_points = sum(control.weight * control.maturity_level / 4)
                  for controls with valid, supported levels

unassessed or invalid higher-level evidence contributes no unsupported credit
maximum = 100
```

Report quarter-points without rounding upward. Show category totals as well as
the aggregate, and display assessment coverage separately: assessed,
unassessed, failed, blocked, stale, and assured controls. An empty template has
zero verified points and a null assessment score; this means lack of proof,
not a measurement that the software has zero actual operational readiness.

### Fixed denominator and applicability

No control may be deleted, silently down-weighted, marked N/A for a free point,
or removed from the denominator after results are known. Conditional mechanisms
must follow a predefined equivalent-outcome path frozen with the profile:

- An external CA still needs accepted custody, availability, recovery, and
  incident-responsibility evidence. It does not require the operator to export
  that provider's private keys.
- HSM/KMS integration is mandatory where the approved key-custody profile
  requires it; otherwise an approved alternative custody design must meet the
  same profile's security objectives.
- Where protocol revocation is unavailable, a tested short-lifetime and
  emergency-invalidation design must meet the approved exposure bound.
- An external load balancer must meet the same availability and ownership
  safety objectives as the managed VIP path through its approved mechanism.

A genuinely inapplicable control requires an independently approved, separately
versioned **100-point profile before assessment**. The original profile remains
visible. Framework/profile changes are not a remediation technique and do not
carry forward an earlier score automatically.

## 4. Release gates and production decisions

A numerical score and production authorization are separate outputs. Each
category has a named release gate covering its mandatory controls. A gate is
PASS only when every mandatory control in that gate is assured and current,
and every triggered conditional gate is satisfied. A known failure is FAIL;
missing or unverifiable proof is UNKNOWN. Both FAIL and UNKNOWN block an
unqualified production approval.

All 100 controls remain required for 100/100, including controls that are not
mandatory release gates. Those controls can distinguish a conditionally
authorized release from a fully assured result. A conditional-gate trigger
must be explicitly reviewed against the frozen release scope; an undecided
trigger cannot be treated as false.

| Verified points | Interpretation, subject to gates |
|---:|---|
| 0–49.75 | Foundational assurance is incomplete; no enterprise readiness claim. |
| 50–74.75 | Engineering implementation is progressing; operational qualification remains substantial. |
| 75–89.75 | Qualification is advanced, but the enterprise target remains incomplete. |
| 90–99.75 | A release authority may consider a documented conditional decision only if all mandatory gates pass and the remaining risks are eligible. This is not 100/100. |
| 100.00 | Every control is assured, every gate passes, and all conditions below are satisfied for the named subject. |

These bands are framework interpretation policy, not statistically calibrated
failure probabilities. Do not present 99 points as 99% uptime or a 1% breach
probability.

**Required decision outputs:** verified points; assessment completeness;
gate verdict; open findings/exceptions; and production decision
(`NOT_ASSESSED`, `NOT_APPROVED`, `CONDITIONALLY_APPROVED`, or `APPROVED`).
Release decision authority is organizational. A scoring tool must not grant
itself deployment approval.

For a claim of **100/100**, all of the following must hold:

1. Exactly the 100 versioned control IDs are present, each at level 4 with valid
   evidence and completed acceptance results.
2. All twelve category gates pass, including activated conditional controls.
3. The final artifact, code, configuration, environment, compatibility matrix,
   policies, and catalogue are the exact approved subject.
4. Relevant CI and security checks executed successfully for that subject;
   a YAML workflow existing in Git is insufficient.
5. The selected certificate, trust, deployment, failure, recovery, and consumer
   paths were exercised with real approved staging infrastructure.
6. No active exception substitutes for a required acceptance criterion; no
   unresolved material critical/high defect or exposed credential remains.
7. Authenticated independent reviews and service/PKI/security/operations/change
   approvals are recorded, with required separation of duties.
8. Evidence remains within its freshness window, required monitoring and
   response are operational, and no material invalidating change has occurred.

An example of non-compensation: 99 controls at 1.00 plus a failed issuance
authorization control produces 99/100 and a failed gate. It is not approved.

## 5. Evidence contract

Each evidence record must identify the control and procedure, exact assessment
subject and relevant component fingerprints, observation/collection/review times
with UTC offsets, collector, authenticated reviewer approval reference, method,
expected result, actual result, limitations, immutable artifact reference,
SHA-256 digest, classification, retention, and relevant CI/change/tool versions.

Store secret values, private keys, recovery tokens, kubeconfigs, and sensitive
host details in the approved restricted systems. Public or ordinary repository
evidence should use sanitized outputs and controlled references. Redaction
must preserve the measurement and its meaning. Compute hashes after sanitizing
the review copy, and record restricted-original custody separately where needed.

A hash checks integrity; it does not establish truth, an authorized environment,
or the authenticity of an approval. A reviewer name typed into editable JSON
does not authenticate that person. Use a trusted review system or verified
signature with the expected identity, subject, timestamp, and permissions.

A second AI agent's review is useful quality assistance, not automatically an
organizational approval. Automated assessment or approval can count only where
the frozen organizational policy authorizes that trusted mechanism and its
identity/permissions are verifiable. Required human/domain-owner decisions
cannot be invented or self-approved by the implementation agent.

Evidence reuse is permitted only when it proves distinct acceptance assertions
and each control cites the relevant section/results. A generic green dashboard,
an empty command output, an unexecuted runbook, or a generated checklist cannot
be recycled as proof for unrelated controls. Test fixtures, mocks, examples,
and simulated output must be labeled and cannot become live proof.

### Freshness and invalidation

| Evidence class | Default freshness policy for this framework |
|---|---|
| Release-candidate CI/artifact verification | Exact candidate, executed within seven days of approval; rerun affected checks after relevant changes. Immutable older build provenance may remain valid, but its verification and the candidate's security disposition must be current. |
| Vulnerability/secret/security disposition | Exact shipped subject; final scan/disposition and advisory/database refresh within 24 hours of release approval, subject to an approved offline equivalent. |
| Live qualification, failure, restore, and capacity tests | Observed within 30 days of approval and applicable to the exact relevant topology, configuration, policies, versions, and dependencies. |
| Governance and operational policies | Reviewed within 90 days and still applicable to the named release; a relevant change requires immediate review. |
| External-provider standing assurance | Underlying report within its approved validity period, no more than 365 days by default, plus a release applicability/responsibility review within 30 days and the required customer-side tests. |

These are proposed framework defaults. Freeze any stricter organizational
requirements before testing. A policy variant that relaxes them requires an
approved new version/profile, not an unnoticed expiry edit.

Requalify affected controls after material changes to source, packaging,
workflows, dependencies, versions, config, topology, IAM, CA/issuer/trust policy,
credential custody, backup storage, recovery paths, monitoring, service
objectives, or threat assumptions. Record a dependency/impact review for
unaffected controls; do not assert that all evidence survives any change merely
because a single broad configuration hash is unchanged.

Quarterly or annual exercise cadence is a maintenance minimum, not permission
to ignore the release evidence window. Keep failed attempts, deviations,
corrective changes, rerun results, and review decisions in the audit trail.

## 6. Service objectives to approve before grading

Targets must be numeric, owned, justified, and fixed before the test. Do not
choose a threshold after seeing the result. Units and denominators matter.

| Objective | Required specification |
|---|---|
| API access and request admission | Eligible event definition, measurement location, successful outcome, availability ratio/window, timeout, and missing-data policy. |
| Reconciliation scheduling | Request-to-authorization/reconciliation-start deadline and percentile, with queue-age measurement. |
| Certificate issuance/readiness | Approved eligible request-to-valid-certificate deadline, percentile, sample size, issuer/provider assumptions, and intentional-denial treatment. |
| Consumer certificate availability | Actual served/used identity, chain, key/certificate generation, validity, hostname/mTLS checks, probe interval, and allowed disruption. |
| Renewal safety | Per-certificate-class renewal window and minimum remaining lifetime compared with plausible detection, outage, repair, retry, and adoption time. |
| Revocation/exposure | Maximum invalidation delay and accepted behavior during CRL/OCSP or alternative-mechanism outage. |
| VIP and component recovery | Client-observed outage budgets for protected failure cases and recovery thresholds. |
| RTO/RPO | Numeric recovery-time and recoverable-data-age limits, including access, host replacement, dependency restoration, and consumer verification. |
| Alerts and response | Delivery, acknowledgement, escalation, containment, and recovery targets, with coverage during responder absence. |
| Capacity | Managed certificate classes/counts, tenant mix, sustained and burst rates, renewal synchrony, CA/DNS quotas, resource/headroom limits, and protected-node-loss case. |
| Qualification duration | Approved soak/load windows that cover relevant renewal/backup overlap; existing-service operating observation window. |
| Maintenance and support | Supported version matrix, maintenance window, patch/rotation/review deadlines, retention, and end-of-support actions. |

Keep request admission, certificate readiness, and the application's actual
certificate service separate. A healthy Kubernetes API proves none of the
end-to-end certificate outcomes by itself. SLO targets should reflect the
service's users and approved error-budget decisions; see the
[Google SRE SLO guidance](https://sre.google/workbook/implementing-slos/).

## 7. Control catalogue

Every control below is **one point**. Full credit requires every listed
acceptance criterion and the cumulative level-4 requirements. The procedures
are assessment instructions, not authorization to run destructive operations.
Faults, restores, traffic generation, trust changes, and credential operations
require an approved staging scope, stop conditions, rollback, and access.

The machine-readable catalogue carries the same IDs and text. Owners shown are
roles to assign, not invented named employees. Mandatory gate designation is
independent of whether a lower-scoring conditional release could be considered.


### Allocation and mandatory gates

| Area | Points | Controls | Category gate | Mandatory controls |
|---|---:|---:|---|---:|
| GOV — Scope, governance, and accountability | 6 | 6 | G-01 | 1 |
| CFG — Configuration and deployment safety | 8 | 8 | G-02 | 5 |
| PKI — PKI, keys, and certificate lifecycle | 14 | 14 | G-03 | 11 |
| SEC — Security, identity, and isolation | 12 | 12 | G-04 | 11 |
| HA — Availability, network, and resilience | 10 | 10 | G-05 | 7 |
| DR — Backup, recovery, and continuity | 10 | 10 | G-06 | 6 |
| SUP — Supply chain, builds, and releases | 10 | 10 | G-07 | 5 |
| TST — Verification and compatibility | 8 | 8 | G-08 | 2 |
| OBS — Observability, SLOs, and alerting | 8 | 8 | G-09 | 5 |
| OPS — Operations, response, and change | 6 | 6 | G-10 | 4 |
| PERF — Capacity, performance, and endurance | 4 | 4 | G-11 | 2 |
| EVD — Evidence, review, and score integrity | 4 | 4 | G-12 | 3 |
| **Total** | **100** | **100** | **12 gates** | **62 mandatory controls** |

A conditional gate supplements these mandatory sets when its frozen trigger applies. Every control, whether a mandatory gate or not, remains required at level 4 for 100/100.

### 7.1 GOV — Scope, governance, and accountability (6 points)

Accountable role: **Service owner**. Category release gate: **G-01**. Assign actual identities and independent reviewers in the assessment.

#### GOV-01 — Assessment scope and support claims

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `policy90`

**Acceptance criteria**

- The frozen assessment profile identifies the release commit, artifact digests, named environment, deployment mode, selected adapters and issuer paths, supported platforms, and external dependencies.
- Every enterprise-readiness claim maps to an in-scope capability and trust boundary; unverified modes, adapters, and environments are explicitly excluded from that claim.
- The profile is approved before scoring; changes to scope, catalogue version, or applicability create a new assessment revision rather than deleting an unsuccessful result.

**Verification procedure**

1. Compare the profile with the actual release manifests, rendered inventory, adapter registry, and deployment topology; record every mismatch.
2. Select each public support/readiness claim and trace it to an in-scope verification obligation; fail this control if a claim has no supported mapping.

**Required evidence**

- Approved assessment-profile.json with revision and approval reference
- Architecture/trust-boundary diagram and capability/support matrix

#### GOV-02 — Accountability and separation of duties

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `policy90`

**Acceptance criteria**

- The service owner, platform operator, security reviewer, PKI authority, key custodians, recovery authority, and escalation deputy are identified through controlled records.
- Critical changes and evidence reviews have defined maker/checker roles; an implementer cannot provide the sole approval for their own key-custody, authorization, recovery, or release claim.
- Responsibilities remain operable when the primary maintainer is unavailable.

**Verification procedure**

1. Trace a recent or rehearsed certificate-policy change, restore decision, and release approval to the accountable and independent roles.
2. Have the deputy locate the escalation path and required operating records without relying on the primary maintainer; record missing access or responsibilities.

**Required evidence**

- Approved RACI and maker/checker policy with restricted contact-record references
- Sampled change/review approvals and deputy-handover exercise record

#### GOV-03 — Business and reliability objectives

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `policy90`

**Acceptance criteria**

- Owners approve numeric availability, issuance and renewal latency, certificate-exposure/revocation, recovery-time, recovery-point, and capacity objectives for the named service.
- Every objective defines its numerator/denominator or measurement boundaries, observation window, exclusions, target, and responsible owner.
- Objectives distinguish request reconciliation, issued-certificate readiness, consumer delivery, and the certificate actually served by a relying application.

**Verification procedure**

1. Recompute one worked example for every objective from the stated inputs and confirm a second reviewer obtains the same result.
2. Map each objective to an instrumented verification or exercise control; identify any objective for which no measurement method exists.

**Required evidence**

- Versioned SLO/RTO/RPO and security-exposure specification
- Measurement definitions and owner approval record

#### GOV-04 — Compatibility and lifecycle policy

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `policy90`

**Acceptance criteria**

- The release defines supported controller Python/Ansible combinations, host operating systems and architectures, Kubernetes distributions/versions, charts, and adapters.
- Each dependency has an upstream support/lifecycle status, maintenance owner, and upgrade/deprecation decision; community support is not represented as a vendor support contract.
- Unsupported or unqualified combinations are rejected or visibly excluded from enterprise support claims.

**Verification procedure**

1. Compare every declared support combination with upstream requirements and the release's actual pins; flag expired or contradictory entries.
2. Attempt representative unsupported combinations and confirm validation or documented support boundaries prevent an implicit supported verdict.

**Required evidence**

- Maintained compatibility/lifecycle matrix with upstream references and review date
- Deprecation policy and validation/CI mapping for supported combinations

#### GOV-05 — Threat model, risk, and change policy

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `policy90`

**Acceptance criteria**

- A versioned threat model and asset/data-flow inventory cover the privileged operator workstation and CI, hosts and cluster, CA/signing boundary, tenants, external dependencies, protected data, abuse paths, and approved retention/residency constraints; material risks have accountable owners.
- Material architecture, security-policy, dependency, credential, and operational changes have defined risk classes, approval authorities, and requalification triggers.
- Every exception records the unmet criterion, consequence, compensating measures, owner, approver, expiry, and remediation plan.
- An exception or risk acceptance cannot change a control's earned credit, suppress a failed gate, or convert the assessment into 100/100.

**Verification procedure**

1. Trace the deployed architecture and protected assets through the threat model and risk register, then sample material changes to verify risk classification, approval, and affected-control requalification.
2. Submit a controlled expired exception and a failed mandatory-gate exception to the assessment workflow; confirm neither produces assured credit.

**Required evidence**

- Approved threat model, asset/data-flow inventory, trust-boundary diagram, and current risk register
- Versioned change/risk/exception policy
- Exception register and sampled change records including an expired/rejected example

#### GOV-06 — Sustained operating ownership

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `policy90`

**Acceptance criteria**

- Named teams own maintenance, incident response, dependency updates, release operation, capacity, and end-of-support decisions for the service's planned lifetime.
- The operating model specifies escalation hours, response expectations, handover, training, and minimum available operating capacity.
- A maintainer handover or absence exercise demonstrates access to the necessary procedures and controlled systems.

**Verification procedure**

1. Review ownership and escalation coverage against the declared service hours and dependency responsibilities.
2. Have an authorized alternate operator perform the documented handover exercise and record any inaccessible system, missing procedure, or unowned dependency.

**Required evidence**

- Approved service support/maintenance plan and ownership register
- Training/handover record and absence exercise results

### 7.2 CFG — Configuration and deployment safety (8 points)

Accountable role: **Platform automation owner**. Category release gate: **G-02**. Assign actual identities and independent reviewers in the assessment.

#### CFG-01 — Schema and semantic validation

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- All in-scope configuration fields have defined types, constraints, defaults, and cross-field invariants; unsupported values cannot silently select a different behavior.
- Malformed structures, unsafe combinations, contradictory ACME ownership, invalid HA topology, missing production pins, and unsupported managed features fail with nonzero status and actionable diagnostics.
- Rejected input is not partially rendered or applied in a manner that could be mistaken for a valid deployment.

**Verification procedure**

1. Run valid boundary cases and invalid type/topology/security combinations through validate, plan, inventory, and deployment preflight.
2. Confirm each invalid case produces the expected nonzero result without a traceback, false-success message, or unintended output/mutation.

**Required evidence**

- Versioned schema/semantic-invariant catalogue and positive/negative fixture matrix
- CLI test results including exit status, sanitized diagnostics, and mutation checks

#### CFG-02 — Plan/apply/check contract

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- The plan identifies the intended hosts, environment, roles, selected adapters, versions, security prerequisites, and expected mutations for the frozen configuration.
- Check mode documents operations it cannot simulate and never reports those operations as successfully verified.
- The executed staging changes match the approved plan or stop for a recorded plan deviation.

**Verification procedure**

1. Generate the plan and inventory from the frozen configuration and independently compare targeting, versions, and intended operations.
2. Run check mode and an approved staging reconciliation, then compare observed changes with the plan; record every unexplained addition or omission.

**Required evidence**

- Release-bound plan and rendered inventory with configuration digest
- Check-mode limitations register and sanitized apply/change transcript

#### CFG-03 — Idempotence and drift reconciliation

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- A second apply of an unchanged desired state causes no unintended changes, certificate reissuance, private-key churn, service restart, or resource recreation.
- Deliberately introduced supported drift is detected and converges to the declared state with only expected changes.
- Any unavoidable nonzero change reporting is bounded, explained, and cannot conceal a functional side effect.

**Verification procedure**

1. Apply the same staging configuration twice and compare certificate serials/key identifiers, service restarts, resources, and effective configuration.
2. Introduce one safe drift case per managed subsystem and verify reconciliation repairs exactly the approved delta.

**Required evidence**

- First/second apply transcripts and before/after resource/service fingerprints
- Deliberate drift scenario, expected-change list, and reconciliation results

#### CFG-04 — Prerequisite fail-fast

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Preflight checks cover supported controller/host versions and architecture, required collections/tools, target identity, credentials, approved host policy, required connectivity, and declared capacity.
- Missing or invalid prerequisites fail before avoidable privileged mutation and identify the responsible operator action without exposing secret values.
- An unexecuted or deferred prerequisite is reported as unknown/pending rather than OK.

**Verification procedure**

1. Remove or invalidate each representative prerequisite in an isolated test and run doctor/deployment preflight.
2. Verify nonzero exit status, precise sanitized diagnostics, and absence of avoidable host/cluster changes before the failure.

**Required evidence**

- Prerequisite inventory with owner and failure behavior
- Controlled missing-prerequisite transcripts and before/after mutation audit

#### CFG-05 — Safe configuration and secret handling

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Secret inputs, generated configuration, inventory, temporary files, diagnostic output, and evidence exports follow approved confidentiality and minimum-permission rules.
- Path resolution, symlinks, traversal, permissions, file replacement, cleanup, and error handling cannot disclose or overwrite unauthorized material.
- Verbose output, Ansible diffs, failed tasks, logs, and generated release artifacts contain no seeded secret sentinel.

**Verification procedure**

1. Exercise absolute/relative paths, missing files, hostile paths, symlinks where supported, interrupted writes, and restricted permissions using nonsecret fixtures.
2. Scan all resulting logs, diffs, temporary files, inventories, evidence outputs, and package members for a unique test sentinel and verify approved cleanup/permissions.

**Required evidence**

- Permission/path threat-case matrix and filesystem before/after records
- Sanitized normal/verbose/failure transcripts and sentinel scan results

#### CFG-06 — Partial failure and safe recovery

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Each deployment phase defines failure status, timeout, retry/resume behavior, cleanup, and rollback or forward-recovery boundary.
- Interrupted bootstrap, node join, chart reconciliation, and adapter installation leave an identifiable recoverable state without uncontrolled repeated mutation.
- Handlers and restarts complete before dependent health checks, and failed health checks stop subsequent unsafe phases.

**Verification procedure**

1. Inject a controlled failure or interruption at each critical phase boundary and compare resulting state with the specified failure contract.
2. Resume or recover using the documented procedure and verify service/data integrity, handler ordering, bounded retries, and correct final exit status.

**Required evidence**

- Phase/state-transition and rollback/resume specification
- Approved staging interruption/failure transcripts with resulting state and recovery outcome

#### CFG-07 — Inventory and targeting integrity

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Host identities, bootstrap/join groups, load-balancer ownership, privilege escalation, tags, and limits match the frozen approved deployment scope.
- Duplicate identities, conflicting addresses/ports, empty or unintended target groups, and unsupported placement fail before application.
- Operator targeting options cannot silently expand the deployment to unrelated hosts or environments.

**Verification procedure**

1. Independently compare the generated inventory and selected playbook/task target set with the approved host/environment list.
2. Exercise duplicate, conflicting, empty, wrong-environment, limit, and tag cases; verify rejection or the exact explicitly authorized target subset.

**Required evidence**

- Approved targeting specification and rendered inventory/graph
- Positive/negative inventory and limit/tag selection results

#### CFG-08 — Portable CLI and resource contract

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- An installed wheel/source distribution resolves its schema, registry, roles, playbooks, templates, and examples from outside the source checkout.
- Configuration-relative file paths, module/package versions, diagnostics, and documented exit codes behave consistently across declared controller platforms.
- Missing installed resources produce an explicit failure rather than fallback to unrelated working-directory assets or an apparent successful plan.

**Verification procedure**

1. Install the candidate artifact into a clean isolated location, change to an unrelated directory, and run the documented nonmutating CLI commands.
2. Verify deployment command construction uses intended bundled paths, versions agree, relative inputs resolve correctly, and missing resources fail explicitly without contacting production.

**Required evidence**

- Isolated installed-artifact CLI smoke report and resource hash inventory
- Controller-platform CLI contract results including missing-resource cases

### 7.3 PKI — PKI, keys, and certificate lifecycle (14 points)

Accountable role: **PKI authority**. Category release gate: **G-03**. Assign actual identities and independent reviewers in the assessment.

#### PKI-01 — Approved PKI authority and trust model

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The PKI owner approves root and intermediate hierarchy, issuer responsibilities, trust domains, allowed certificate uses, maximum validity, and production/non-production separation.
- Every enabled production issuer and selected adapter maps to the approved trust model; no undocumented issuer or cross-environment trust dependency remains.

**Verification procedure**

1. Enumerate every production issuer and adapter and compare its actual signer, chain, scope, and responsibility with the approved architecture.
2. Inspect the public trust material and issuer endpoints from production and non-production representatives and record that the declared separation holds.

**Required evidence**

- Approved PKI architecture and certificate-policy decision with owner and review date.
- Issuer inventory, public root/intermediate fingerprints, and production/non-production trust-boundary review.

#### PKI-02 — CA signing-key custody and recovery

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Signing keys remain inside the approved storage and access boundary, with explicit exportability, backup, recovery, and compromise controls.
- An HSM/KMS is mandatory only when the approved custody profile requires one; that integration must be exercised, not merely named in a design.
- Required quorum or dual control is enforced for privileged signing-key operations and emergency recovery.

**Verification procedure**

1. Inspect custody metadata, effective permissions, export settings, and public key identifiers without exporting or disclosing signing keys.
2. In authorized staging, exercise an approved signing/recovery operation and an unauthorized access attempt; verify the required quorum or dual-control behavior.

**Required evidence**

- Key-custody design and effective access/export policy.
- Public key identifiers and sanitized authorized-signing, denied-access, and recovery results.
- Independent review of privileged custody and recovery access; no private key material.

#### PKI-03 — Enforced certificate and cryptographic profiles

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Actual issuance enforces approved algorithms, key sizes, SAN types, usages, EKUs, CA constraints, validity limits, and chain structure.
- Requested and issued attributes are both inspected; the selected issuer does not silently weaken the approved profile.

**Verification procedure**

1. Issue representative certificates at approved profile boundaries and decode the resulting certificates to compare every constrained attribute.
2. Submit requests exceeding validity, key, SAN, usage, or CA constraints and verify that no usable out-of-policy certificate is issued.

**Required evidence**

- Versioned issuance and cryptographic profiles.
- Sanitized decoded certificates and CSRs at approved limits.
- Rejected out-of-policy request results and issuer-configuration/output comparison.

#### PKI-04 — Explicit certificate request authorization

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Production issuance requires an approved requester-to-policy and requester-to-issuer authorization path.
- Automatic approval cannot bypass the intended policy controller; sample bootstrap policies do not authorize general workload issuance unintentionally.

**Verification procedure**

1. Review effective requester permissions, policy selectors/bindings, and enabled approvers against the approved authorization matrix.
2. Submit an allowed request using the actual authorized workload identity and correlate its approval and signing events with the expected policy and issuer.

**Required evidence**

- Effective RBAC, issuer restrictions, and CertificateRequestPolicy definitions for the installed versions.
- Enabled-controller and automatic-approval configuration.
- Allowed-request trace identifying requester, selected policy, approval, and signing issuer.

#### PKI-05 — Successful end-to-end issuance and consumption

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- A representative production client obtains a certificate through the approved issuer and receives the expected complete chain.
- The actual application presents the certificate successfully to a representative relying party with chain, identity, and validity verification enabled.
- A resource condition reporting Ready alone does not satisfy the control.

**Verification procedure**

1. Create an approved representative Certificate or equivalent adapter request and trace issuance through the selected signing authority.
2. Connect a representative relying party to the application endpoint and verify the served chain, SAN identity, validity, and intended TLS or mTLS use.

**Required evidence**

- Correlated request, approval, issuance, and deployment records.
- Sanitized issued-certificate attributes and chain fingerprints.
- TLS or mTLS validation results from the actual consumer endpoint.

#### PKI-06 — Negative issuance and tenant-boundary tests

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Unauthorized identities, wrong issuers, cross-tenant names, forbidden names/usages, excessive validity, and unauthorized CA-signing requests are rejected or remain safely unapproved.
- No rejected request produces a usable certificate, including during controller retries or policy changes.

**Verification procedure**

1. Run the negative matrix with real staging identities from the relevant tenant and namespace boundaries, including wrong-subject and wrong-issuer cases.
2. Correlate each rejection with request conditions and signer/audit records and confirm that no usable certificate or unauthorized signature was produced.

**Required evidence**

- Executed negative-authorization matrix with effective requester identities and test cases.
- Resulting request conditions and sanitized issuer/audit records proving that no unauthorized signing occurred.

#### PKI-07 — Automatic renewal and application reload

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Renewal completes inside the approved pre-expiry safety margin, and the application starts serving the renewed certificate.
- A failed renewal attempt and subsequent reconciliation recovery are exercised without exceeding the declared certificate-availability budget.

**Verification procedure**

1. Trigger or observe a controlled staging renewal and compare the request result with the certificate actually served by the application.
2. Cause an approved temporary renewal dependency failure, restore it, and measure renewal and application adoption against the documented safety margin.

**Required evidence**

- Renewal policy and approved safety/disruption margins.
- Controlled renewal/recovery timeline, old/new serials and expiry times.
- Observed served-certificate changes and application reload/restart results.

#### PKI-08 — Private-key rotation

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Renewal and emergency reissuance obey the explicit approved key-rotation policy.
- When a new key is required, its public-key fingerprint changes and the consumer adopts it without exceeding the approved disruption budget.

**Verification procedure**

1. Record the public-key fingerprint, perform an authorized staging rotation or emergency reissuance, and record the replacement public-key fingerprint.
2. Verify that the application serves the replacement key/certificate and that representative clients remain within the approved availability/disruption budget.

**Required evidence**

- Explicit key-rotation policy for each selected certificate class.
- Old/new public-key fingerprints and certificate serials; no private keys.
- Reissuance trace, application adoption observations, and TLS/mTLS continuity results.

#### PKI-09 — Scoped and verifiable trust distribution

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Trust bundles contain only approved public roots/intermediates and reach only intended namespaces, hosts, or applications.
- Explicit target selection prevents production trust from reaching unrelated tenants or non-production consumers.

**Verification procedure**

1. Compare the effective Bundle or equivalent trust-distribution configuration, public contents, and explicit target selectors with the approved target inventory.
2. Verify material and validation behavior at representative included targets and prove that excluded tenants/namespaces/environments did not receive unintended trust.

**Required evidence**

- Approved public bundle contents and fingerprints.
- Effective source references, explicit target selectors, and expected target inventory.
- Positive trust tests for included targets and negative distribution/trust tests for excluded targets.

#### PKI-10 — CA and trust-anchor rollover

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** This control becomes a non-waivable gate for any release that introduces, removes, or changes production trust anchors; it is still required for full score in other releases.

**Acceptance criteria**

- A staging rehearsal demonstrates approved trust overlap, client adoption, replacement issuance, old-trust removal, and rejection after removal.
- The procedure addresses clients with delayed or offline trust updates and identifies its safe rollback boundary.

**Verification procedure**

1. In authorized staging, introduce replacement trust and issuance, then verify representative normal and delayed-update clients throughout the overlap period.
2. Remove the old trust only after the approved conditions are met and prove that the intended old chain is rejected while replacement chains continue to work.

**Required evidence**

- Approved rollover plan, overlap policy, and delayed-client inventory.
- Before/during/after public bundle fingerprints and representative client results.
- Measured rollout completion, rollback boundary, and reviewed exceptions.

#### PKI-11 — Revocation and emergency invalidation

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Compromised or withdrawn credentials become unusable to relevant relying parties within an approved maximum time.
- CRL/OCSP is tested where used; where usable protocol revocation is unavailable, the approved short-lived expiry and emergency trust-removal design is tested.
- Status freshness and revocation-service outage behavior match the approved relying-party policy.

**Verification procedure**

1. Issue a staging credential and invalidate it using the selected CA's approved revocation mechanism or the approved short-lived/trust-removal design.
2. Observe representative relying parties before and after invalidation, including status-service outage/freshness cases, and measure when access is actually rejected.

**Required evidence**

- Revocation/invalidation design and maximum invalidation-time requirement.
- Sanitized issued-and-invalidated test certificate and authoritative status observations.
- Actual client rejection, freshness/outage behavior, and measured invalidation timing.

#### PKI-12 — Certificate ownership, inventory, and retirement

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Every production certificate class has an accountable owner, service, issuer, renewal method, deployment locations, and decommissioning procedure.
- Retirement stops issuance/renewal, removes obsolete distribution, and accounts for residual private-key copies and access.

**Verification procedure**

1. Reconcile issuer and consumer inventories, sample each production certificate class, and resolve missing owners or unexplained copies.
2. Retire an authorized staging workload and verify that renewal stops, obsolete distribution is removed, and documented residual-access/key-copy handling completes.

**Required evidence**

- Reconciled certificate/service/owner inventory and orphan/stale-certificate report.
- Sampled ownership verification and an executed retirement record.
- Residual-distribution and residual-access verification; no private key contents.

#### PKI-13 — Issuer dependency and rate-limit handling

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Mandatory release gate where the frozen profile includes issuer, signer, CA database, DNS, or identity dependencies whose loss can affect an approved issuance deadline or renewal safety budget; decide activation from the dependency map before testing.

**Acceptance criteria**

- CA, ACME, DNS, identity, database, and external signer failures produce bounded retries and visible failures without unauthorized fallback or secret exposure.
- Dependency restoration drains the affected issuance/renewal backlog before the declared expiry safety budget is exhausted.

**Verification procedure**

1. Exercise approved staging failures of selected issuer dependencies one at a time and observe retries, limits, policy enforcement, and failure reporting.
2. Restore each dependency and measure backlog recovery against the certificate-expiry budget while checking for unauthorized issuer fallback or secret disclosure.

**Required evidence**

- Dependency/failure-mode inventory, retry policies, and provider rate-limit settings.
- Controlled outage/recovery results and sanitized failure output.
- Backlog-recovery measurements and proof that signer/trust policy stayed intact.

#### PKI-14 — Selected adapter role and lifecycle qualification

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- A frozen per-adapter role/capability matrix identifies which selected component owns issuance, renewal, key rotation, authorization, trust distribution, consumer delivery, upgrade, and retirement; unsupported capabilities and ownership conflicts are explicit.
- Each selected adapter is exercised on its declared OS/runtime for its own documented capabilities. Complementary components such as trust-manager are not required to issue certificates, and intentionally disabled capabilities remain disabled.
- The composition of selected adapters demonstrates every lifecycle outcome required by the production profile without claiming that each individual adapter implements the entire lifecycle.

**Verification procedure**

1. Reconcile each selected adapter with the frozen capability/ownership matrix, its upstream support boundaries, and the effective configuration; identify unsupported capability claims or competing lifecycle owners.
2. Deploy the selected components on approved representative targets, execute their role-specific lifecycle checks and the aggregate profile-required workflow, and verify consumer outcomes plus safe upgrade and retirement behavior.

**Required evidence**

- Approved per-adapter role/capability and ownership matrix linked to the frozen profile.
- Per-adapter qualification results with exact versions, topology, target OS, supported-capability checks, and rejection or inactivity checks for unsupported/disabled capabilities.
- Aggregate lifecycle and relying-party interoperability trace with component ownership, limitations, upgrade/retirement outcomes, and linked artifacts.

### 7.4 SEC — Security, identity, and isolation (12 points)

Accountable role: **Security owner**. Category release gate: **G-04**. Assign actual identities and independent reviewers in the assessment.

#### SEC-01 — Strong human authentication

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Administrative production access uses individually attributable identities and organization-approved authentication, with MFA wherever supported.
- Shared administrator identities are eliminated or confined to a controlled emergency process; this applies to operator access paths rather than requiring a new CLI login UI.

**Verification procedure**

1. Exercise representative administrator login paths and verify the expected individual identity and required authentication factors.
2. Attempt approved invalid/unauthorized logins and review emergency-account controls to confirm that shared access cannot bypass the documented process.

**Required evidence**

- Administrative access architecture and effective authentication/MFA policies.
- Representative successful and denied authentication tests.
- Emergency-account ownership, controls, and access-review records.

#### SEC-02 — Least-privilege machine authorization

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Ansible automation, Kubernetes service accounts, issuers, DNS solvers, backup jobs, and adapters have only the permissions required for their documented duties.
- Routine operations do not retain broad administrator credentials solely for installation convenience; privileged exceptions are bounded and reviewed.

**Verification procedure**

1. Enumerate effective permissions for each production automation and workload identity and compare them with its documented responsibilities.
2. Use representative actual machine credentials to perform required actions and attempt forbidden actions, verifying denial and removal of temporary installation privileges.

**Required evidence**

- Effective role and policy exports plus subject-to-resource permission matrix.
- Positive and negative permission tests using representative machine identities.
- Privileged-exception inventory, justification, expiry, and removal evidence.

#### SEC-03 — Tenant and environment isolation

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Tenant, namespace, workload, and environment boundaries prevent cross-boundary certificate requests, secret reads, trust changes, and administrative mutations.
- Isolation is demonstrated through actual credentials and network paths, not only naming or label conventions.

**Verification procedure**

1. From representative tenant and environment identities, exercise allowed operations and attempt cross-boundary reads, requests, and mutations.
2. Repeat relevant tests over the actual permitted network paths and correlate enforcement/audit results with the approved isolation model.

**Required evidence**

- Tenant/environment boundary design and effective RBAC/network policies.
- Two-tenant and production/non-production test matrix.
- Denied cross-boundary secret, issuer, policy, trust, and administrative access results.

#### SEC-04 — Credential and secret protection

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Non-CA credentials use approved storage, required encryption, least-privilege access, and separately controlled recovery material.
- Credentials are excluded from source, release artifacts, generated output, command transcripts, logs, and ordinary evidence bundles.
- Representative credential replacement and withdrawal preserve required service operation while removing old access.

**Verification procedure**

1. Review effective credential storage/access and inspect sanitized source, distribution, log, and evidence outputs for unintended secret disclosure.
2. Rotate a representative staging credential through the approved secret system, verify consumer adoption, and confirm that the retired credential no longer authenticates.

**Required evidence**

- Secret-reference inventory and effective storage, encryption, and access-control configuration.
- Release/output/log secret-scan results and reviewed recovery-material controls.
- Sanitized credential replacement and old-credential withdrawal results.

#### SEC-05 — Approved host security baseline

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Production hosts meet the approved OS, patch, SELinux, firewall, time, audit, filesystem, kernel, and service baseline.
- Exceptions and HAProxy network-policy decisions are explicit and approved; automation does not disable security enforcement to make installation succeed.

**Verification procedure**

1. Collect read-only effective-state checks from each representative host role and compare them with the approved baseline and exception register.
2. Exercise platform services under the approved enforcement policy and investigate unexplained denials without changing enforcement merely to obtain a passing test.

**Required evidence**

- Effective host-baseline and patch reports.
- Read-only SELinux/firewall/sysctl/service/audit/time observations.
- Approved exceptions and HAProxy policy decision plus service-operation/denial review.

#### SEC-06 — Restricted workload execution

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Selected workloads use approved identities, filesystem permissions, capabilities, seccomp/privilege settings, resource boundaries, and admission enforcement.
- Necessary privileged components have bounded reviewed justifications rather than blanket unexamined exceptions.

**Verification procedure**

1. Compare deployed workload identities and execution settings with approved manifests and component-specific privilege exceptions.
2. Attempt an approved forbidden privileged-workload deployment in staging and verify admission denial while supported platform workloads continue to operate.

**Required evidence**

- Rendered manifests and effective live workload security settings.
- Admission/security-policy configuration and denied privileged-workload test.
- Reviewed component-specific exceptions with owners and limits.

#### SEC-07 — Controlled network and management access

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Management and signing endpoints accept access only from approved sources, with documented ingress and egress paths for API, webhook, CA, backup, DNS, and identity dependencies.
- TLS certificate and SSH/WinRM identity validation remain enabled on the relevant administrative and dependency paths.

**Verification procedure**

1. Test representative permitted and forbidden connections from management, tenant, external, and dependency networks against the approved path matrix.
2. Verify actual connection identity validation and reject approved bad-certificate/host-identity cases rather than relying on insecure skip-validation settings.

**Required evidence**

- Approved allowed-path and endpoint matrix.
- Effective firewall, NetworkPolicy, load-balancer, and dependency connection state.
- Allowed/denied network tests, port scans, and TLS/SSH/WinRM validation results.

#### SEC-08 — Safe privileged deployment and operator channels

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Privileged automation validates inputs and execution material, protects controller-side paths, and preserves authenticated SSH/WinRM/TLS channels.
- Untrusted configuration cannot become arbitrary shell execution; secrets do not leak through arguments, diffs, logs, or failure messages.

**Verification procedure**

1. Run approved malformed-input, path-boundary, and command-injection test cases against planning/rendering/deployment boundaries without targeting production hosts.
2. Inspect sanitized deployment check/diff/error output and effective transport settings to verify secret suppression, verified execution material, and authenticated channels.

**Required evidence**

- Privileged deployment trust-boundary and command-construction review.
- Input/path/injection tests and verified privileged-download controls.
- Sanitized check-mode, diff-mode, error, and secure-connection results.

#### SEC-09 — Attributable and protected security audit trail

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Issuance decisions, policy changes, privileged actions, sensitive access, and credential changes correlate to an attributable subject and trusted time.
- Security logs reach controlled storage with tested access, retention, integrity, and collection-failure handling.

**Verification procedure**

1. Perform representative staging security-relevant actions and trace subject, timestamp, request/change identifier, and outcome through protected audit storage.
2. Attempt an approved unauthorized log alteration and interrupt/recover the collection pipeline to verify integrity enforcement, visibility, and documented recovery behavior.

**Required evidence**

- Correlated end-to-end security audit samples.
- Log storage, access, retention, integrity, and clock configuration.
- Unauthorized log-modification test and pipeline outage/recovery results.

#### SEC-10 — Security findings resolved to release policy

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `security24`

**Acceptance criteria**

- The exact proposed release has current dependency, secret, static, configuration, and relevant runtime security review results covering shipped artifacts and deployment paths.
- No unresolved exploitable critical/high finding, exposed credential, authorization bypass, or signing-key exposure remains.
- Unsupported risk-acceptance labels do not satisfy a non-waivable release gate.

**Verification procedure**

1. Run or inspect the required security checks against the exact proposed revision and release artifacts, verifying that relevant deployment and runtime paths are covered.
2. Review each blocking finding and its remediation/disposition evidence, then independently verify closure of issues that could expose credentials or bypass signing authorization.

**Required evidence**

- Immutable CI and security-review references for the proposed revision and artifacts.
- Findings inventory with technical dispositions and verified remediation evidence.
- Coverage statement mapping scans/reviews to shipped packages and deployment paths.

#### SEC-11 — Abuse resistance and bounded issuance consumption

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Mandatory release gate where the frozen threat/capacity profile includes multiple tenants, untrusted requesters, shared signing capacity, or a mandatory per-tenant resource/isolation requirement; decide activation before overload testing.

**Acceptance criteria**

- Request, signing, webhook, and per-tenant consumption controls keep abusive or malfunctioning requesters within approved resource and issuance budgets.
- Overload does not bypass authorization, weaken issuer selection, or silently break mandatory tenant isolation.

**Verification procedure**

1. Generate approved bounded abusive or malfunctioning-requester traffic in staging and measure enforcement, resource use, rejection, and tenant impact.
2. Remove the load, verify recovery, and prove that authorization, issuer choice, and mandatory isolation remained enforced throughout the exercise.

**Required evidence**

- Approved quotas, issuance/resource budgets, and overload policy.
- Controlled abusive-request test and resource/rejection observations.
- Policy/isolation checks under pressure and recovery after load removal.

#### SEC-12 — Access removal and authorization lifecycle

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Joiner/mover/leaver and machine-identity lifecycle processes remove obsolete privileges and credentials within an approved maximum delay.
- Removing a requester or service identity demonstrably removes effective certificate-request, administration, and secret access; orphaned identities are identified and resolved.

**Verification procedure**

1. Offboard or change the role of an approved staging human and machine identity through the real identity/authorization process.
2. After the allowed propagation interval, attempt its former certificate, administrative, and secret operations using the retired identity and verify denial and audit attribution.

**Required evidence**

- Access-review and identity-lifecycle procedure with maximum removal delay.
- Sampled offboarding/role-change exercise and measured propagation time.
- Before/after permission checks and orphaned-identity report.

### 7.5 HA — Availability, network, and resilience (10 points)

Accountable role: **Platform/SRE owner**. Category release gate: **G-05**. Assign actual identities and independent reviewers in the assessment.

#### HA-01 — Quorum and single-server fault tolerance

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The deployed voting membership matches the frozen HA profile and all intended datastore peers are healthy before testing.
- An approved isolated-staging loss of one protected server preserves quorum and meets the separately approved API, request-scheduling, issuance, and consumer-impact budgets; loss beyond quorum is classified as disaster recovery.

**Verification procedure**

1. Verify the declared voting membership and begin continuous representative client probes before the approved server-loss test.
2. Isolate the authorized staging server, measure each service outcome against its frozen target, restore it, and verify membership and workload convergence.

**Required evidence**

- Sanitized node and datastore-member inventories with pre/during/post health results.
- Timestamped client API, request scheduling, issuance, and served-certificate probe timeline with observed outage and recovery calculations.
- Approved fault-test scope and restoration sign-off.

#### HA-02 — Replica and failure-domain placement

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Critical controller, webhook, approver, trust, ingress, and selected CA workloads have replica and placement rules consistent with the protected failure domain.
- Actual placement does not concentrate every required replica in the same supposedly protected host or domain, and co-location or shared external-load-balancer dependencies are explicit.

**Verification procedure**

1. Compare actual workload placement and infrastructure dependencies with the approved protected-failure-domain diagram.
2. Exercise the approved host or domain-loss case and verify the placement assumptions against observed remaining capacity and availability.

**Required evidence**

- Approved failure-domain diagram and replica/placement manifests.
- Actual node and pod placement inventory tied to the assessment profile.

#### HA-03 — Client endpoint failover and load-balancer continuity

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The frozen profile identifies the endpoint-availability mechanism and protected load-balancer or address-owner failures. The managed path exercises active HAProxy/Keepalived-owner failure; an external path exercises its approved service/instance/address-owner failure or predefined provider-assurance plus customer-side continuity route.
- Continuous representative client probes show that API and applicable ingress service recover or remain available within approved budgets. Ownership migration is required only where the selected architecture uses that ownership mechanism; a changed local VIP alone is insufficient.
- The final endpoint ownership or routing state is stable and consistent with the approved architecture after recovery, with provider-controlled boundaries and any assurance-route limitations explicitly recorded.

**Verification procedure**

1. Freeze the applicable endpoint mechanism, protected fault or assurance route, and client recovery budgets with its owner; record initial routing/ownership and start representative client probes.
2. Execute only the approved managed or external route, correlate independent client outcomes with recovery and ownership/routing evidence, then restore the test state and confirm stable service. Do not require a nonexistent VIP or claim an unperformed provider fault injection.

**Required evidence**

- Approved managed/external endpoint architecture and fault/assurance matrix identifying customer-owned and provider-owned responsibilities.
- Timestamped before/after ownership, routing, service-health, and applicable provider-assurance records for the selected path.
- Continuous representative API/ingress probe results, budget calculations, fault-test approval, limitations, and restoration record.

#### HA-04 — Functional backend health and failed-member removal

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The load balancer removes an unavailable or functionally unhealthy backend and restores it only after the declared health criteria.
- Client requests and connection/retry behavior remain within approved budgets; a successful TCP accept is not treated as proof of a working Kubernetes API or TLS application.

**Verification procedure**

1. Run approved staging cases for a stopped backend and a backend that accepts connections but fails the intended functional request.
2. Observe removal, client impact, recovery qualification, and restored routing, comparing all timings with the frozen targets.

**Required evidence**

- Actual load-balancer health-check configuration and backend transition events.
- Functional client results for unavailable and unhealthy backend scenarios, including recovery timings.

#### HA-05 — Certificate control-plane disruption tolerance

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Loss or restart of the selected controller leader, webhook, approver, or trust replica does not allow unauthorized approval or exceed scheduling and issuance interruption budgets.
- Queued work resumes without manual mutation of successful resources, uncontrolled duplicate issuance, or unresolved reconciliation errors.

**Verification procedure**

1. Create representative eligible requests and begin monitoring queue age, policy outcomes, and consumer certificate state.
2. Perform the approved component-loss scenario, verify authorization remains enforced and work resumes within target, and inspect duplicate issuance and convergence.

**Required evidence**

- Replica/leader and admission-service timeline with sanitized component events.
- Queue-age, request outcome, issued-serial-count, and consumer-probe observations before/during/after the disruption.

#### HA-06 — Controlled maintenance and eviction

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- A staged drain or reboot follows the controlled maintenance runbook, preserves intended quorum and required workloads, and completes within the approved maintenance window.
- Voluntary-maintenance protection is tested separately from involuntary failure; no permanently unavailable replica, stuck eviction, or unreconciled workload remains.

**Verification procedure**

1. Review maintenance authorization and available spare capacity, then perform the documented staging drain/reboot.
2. Check quorum, service probes, eviction behavior, rescheduling, and final readiness against the maintenance objectives.

**Required evidence**

- Timestamped maintenance transcript and eviction/PDB events.
- Availability and rescheduling results plus final node/workload state.

#### HA-07 — Required network-path functionality

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Every required flow for the actual topology is enumerated and functionally verified, including clients, node peers, CNI, VIP/VRRP, API, ingress/NodePorts, DNS, time, CA, registries, and backup storage.
- Configured addressing, ports, routes, source assumptions, MTU, and supported IP-family boundaries match the deployed profile; external-LB designs do not inherit incompatible co-located rules.

**Verification procedure**

1. Compare rendered and deployed networking with the frozen topology and required-flow matrix.
2. Run approved functional probes from each representative source network and record both the intended path and any blocked or misrouted required flow.

**Required evidence**

- Approved source/destination/protocol flow matrix with actual route, firewall, and CNI configuration.
- Functional reachability, name-resolution, and applicable MTU results from representative networks.

#### HA-08 — External-dependency failure behavior

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Controlled failure or rejection by the selected CA/ACME, DNS, registry/egress, time, and object-storage dependencies produces bounded retries, useful alerts, and an explained service impact.
- Existing consumer certificate service is measured separately from new issuance, and restored dependencies drain pending work within approved deadlines and renewal safety margins.

**Verification procedure**

1. For each applicable dependency, confirm authorized staging targets and begin separate scheduling, issuance, and consumer probes.
2. Apply the approved loss or rejection fixture, restore the dependency, and measure detection, bounded retries, client impact, and backlog drain against the frozen profile.

**Required evidence**

- Dependency fault matrix with approved timeout, retry, backoff, quota, and recovery targets.
- Queue-age, failure/retry, alert, consumer-probe, and restored-backlog-drain timelines.

#### HA-09 — Partition and conflicting-ownership safety

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The approved partition cases preserve datastore consistency and avoid unsafe competing VIP/service ownership visible to reachable clients.
- Cases outside automatic recovery have documented and tested detection plus isolation, fencing, or operator containment; unsupported split-brain behavior cannot be scored as successful failover.

**Verification procedure**

1. Review staging authorization, partition boundaries, stop conditions, and recovery access before testing the selected supported failure case.
2. Apply only the approved partition, observe both sides and representative clients, execute the required containment, and verify consistent recovered state.

**Required evidence**

- Approved partition/fencing and containment design with scoped staging test plan.
- Both-side member/VIP observations, client results, and detection/containment/recovery timeline.

#### HA-10 — Post-disruption convergence and repeatability

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- After each completed fault case, the declarative deployment reconciles and required nodes, services, endpoints, issuers, and trust targets return to their intended state.
- No emergency configuration, disabled protection, stale VIP/member, pending renewal, or cumulative degradation is left behind; repeating the selected disruption meets the same approved targets.

**Verification procedure**

1. Reconcile the declared deployment after the fault and compare actual state with its frozen configuration.
2. Repeat the selected approved disruption and verify stable recovery, absence of accumulated drift, and completion of cleanup.

**Required evidence**

- Before/after desired-versus-actual state comparison and reconciliation results.
- Post-fault health, issuance, trust, and repeated-test results with cleanup sign-off.

### 7.6 DR — Backup, recovery, and continuity (10 points)

Accountable role: **Recovery owner**. Category release gate: **G-06**. Assign actual identities and independent reviewers in the assessment.

#### DR-01 — Complete recovery scope and dependency inventory

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The recovery inventory covers datastore state, deployment configuration, approved versions/checksums, applicable CA databases/configuration, key-store recovery mechanisms, trust policy, and external dependencies.
- Ownership and assurance responsibilities are explicit for externally operated CAs and managed services; an etcd snapshot alone does not satisfy complete PKI recovery.

**Verification procedure**

1. Reconcile the recovery inventory with the actual enabled adapters, state stores, secret references, and consumer trust paths.
2. Have recovery and PKI owners review missing dependencies and demonstrate that each item has an accessible supported recovery or continuity path.

**Required evidence**

- Versioned recovery inventory and dependency graph.
- Data/key/service owner matrix and safe references to backup locations, retention classes, and provider responsibilities.

#### DR-02 — Successful scheduled off-host backups

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Scheduled backups actually reach the approved off-host destination within the frozen RPO and are retrievable from more than one scheduled cycle.
- Missed, incomplete, stale, and replication-failed backups are detected; a configured timer or a local snapshot alone earns no full credit.

**Verification procedure**

1. Inspect completed scheduled cycles at the approved remote destination and retrieve selected objects through the intended restore path.
2. Compare the latest recoverable age with RPO and test detection of the approved missed or failed backup fixture.

**Required evidence**

- Actual schedule and retention configuration plus remote object inventory with safe identifiers, times, and sizes.
- Recent scheduled backup/retrieval results and stale-backup or replication-failure alert evidence.

#### DR-03 — CA and key-store recoverability

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Release gate whenever selected CA/key-store recovery is customer-owned or provider recovery assurance is required by the frozen service profile.

**Acceptance criteria**

- Every stateful selected CA or key store has an accepted supported recovery path preserving the required issuance, revocation, and trust state.
- HSM material uses approved vendor backup/redundancy mechanisms without unsafe key export; external-provider assurance and customer-side continuity evidence follow the frozen shared-responsibility profile.

**Verification procedure**

1. Map each selected CA or key store to customer-owned recovery or the approved provider-assurance route and confirm custody permissions.
2. Perform the authorized recovery/continuity verification and prove required identity, issuance/revocation state, and trust consistency without exporting protected keys.

**Required evidence**

- Sanitized CA/database/key-store recovery test or explicitly accepted provider assurance report.
- Key identity/chain continuity verification and approved custody/provider responsibility references.

#### DR-04 — Out-of-cluster bootstrap and recovery access

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Authorized recovery can obtain matching RKE2 token, backup access, decryption or key-store recovery material, DNS/bootstrap access, and approved configuration while Kubernetes and its Secrets are unavailable.
- Recovery access does not depend on the failed cluster or a single unavailable operator; sensitive values are kept out of reports and command transcripts.

**Verification procedure**

1. Use the approved isolated scenario to make the cluster API unavailable and have an authorized recovery operator follow the out-of-cluster access procedure.
2. Confirm every required bootstrap item can be obtained and matches the selected backup, recording references and outcomes rather than credential values.

**Required evidence**

- Independent recovery-access rehearsal with API unavailability explicitly recorded.
- Custody/approval references, matching-token verification outcome, dependency checks, and safe access audit records.

#### DR-05 — Protected backup custody and retention

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Backups are encrypted and access-controlled with approved separation between production administration and destructive backup access.
- Retention and deletion protection or approved equivalent, restore access, and recovery-key custody cover the retained backup lifetime; expired keys cannot silently make retained backups unusable.

**Verification procedure**

1. Review effective permissions and key-retention coverage for the actual backup destination against the approved threat model.
2. Exercise permitted restore access and the approved denied-deletion or retention fixture without deleting required production backups.

**Required evidence**

- Storage encryption, access, retention, and deletion-protection configuration.
- Authorized restore/delete-role test outcomes, recovery-key retention mapping, and sanitized storage audit records.

#### DR-06 — Backup integrity and corruption detection

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Recovery checks trusted backup identity and integrity before use, including the intended transfer and storage path.
- A controlled corrupt, truncated, incomplete, or wrong-backup fixture is rejected clearly and cannot be reported as recoverable.

**Verification procedure**

1. Retrieve a selected backup via the intended restore path and verify its identity and integrity against the trusted record.
2. Run approved non-production corrupt and wrong-backup fixtures and confirm rejection occurs before restore or promotion.

**Required evidence**

- Trusted backup manifest/provenance and successful integrity-check result.
- Controlled invalid-backup fixture rejection output, detection/alert result, and reviewed failure handling.

#### DR-07 — Complete isolated restore rehearsal

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- A backup retrieved from the approved off-host path restores onto isolated staging or replacement hosts through the documented procedure.
- The restored service passes quorum, API/VIP, allowed-and-denied issuance, trust distribution, and representative consumer checks; reusing the original running cluster is insufficient.

**Verification procedure**

1. Provision or identify the authorized isolated replacement target and restore the approved off-host backup using matching bootstrap material.
2. Verify known recovered state and every declared return-to-service check, then obtain independent review of the observed result.

**Required evidence**

- Full restore timeline/logs, source-backup identifier, replacement-host identity, and known pre-backup canary comparison.
- Post-restore acceptance results for datastore, access, authorization, trust, and consumers, with reviewer sign-off.

#### DR-08 — Measured RTO and RPO attainment

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Measured RTO includes required access, replacement provisioning, backup/credential retrieval, restore, and consumer acceptance, and meets the numeric target frozen before the exercise.
- Measured recovered-state age meets RPO using known state or canary timestamps rather than backup-job success alone; deviations and exclusions are visible.

**Verification procedure**

1. Start the exercise clock at the recovery event defined in the frozen profile and collect timestamps across the complete restore procedure.
2. Calculate end-to-end RTO and actual recovered-state RPO, compare with approved targets, and record explicit acceptance or rejection.

**Required evidence**

- Timestamped recovery checkpoints and known recovered-state/canary observations.
- Approved targets and observed RTO/RPO calculations with deviations and acceptance decision.

#### DR-09 — Primary-location and shared-dependency loss recovery

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Release gate when the frozen service profile promises site/location-loss continuity or requires this dependency-loss scenario.

**Acceptance criteria**

- The declared primary-location, storage, identity, and DNS loss scenarios have viable replacement placement and dependency routes.
- The replacement path does not unknowingly share the failed dependency; the selected continuity or assurance mechanism is exercised exactly as approved for the profile.

**Verification procedure**

1. Trace the replacement location and access, storage, identity, DNS, and CA dependencies to identify shared failure points.
2. Exercise the authorized location/dependency-loss case or its explicitly accepted assurance route and verify the intended continuity result.

**Required evidence**

- Failure-domain and dependency-independence review.
- Approved alternate-placement/continuity exercise, endpoint or DNS transition results, and measured recovery outcome.

#### DR-10 — Independently executable recovery and safe return to service

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- An authorized operator other than the runbook author can complete recovery from the controlled instructions.
- Return to service addresses stale identities/trust, recovered credential exposure, replacement-host retirement, and renewed off-host backup success; starting etcd alone is insufficient.

**Verification procedure**

1. Have a separately authorized operator execute the controlled recovery runbook and record instructions or access assumptions that prevented completion.
2. Complete trust and credential checks, verify a new off-host backup, retire replaced identities as approved, and obtain return-to-service authorization.

**Required evidence**

- Independent-operator drill linked to the runbook version.
- Trust/credential reconciliation, first successful post-restore remote backup, host retirement, and return-to-service sign-off.

### 7.7 SUP — Supply chain, builds, and releases (10 points)

Accountable role: **Release engineering owner**. Category release gate: **G-07**. Assign actual identities and independent reviewers in the assessment.

#### SUP-01 — Complete dependency inventory

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `ci7`

**Acceptance criteria**

- Direct/transitive packages, container images, charts, installers, Ansible collections, and build/release tools are inventoried with resolved versions and owners.
- Inventory entries identify acquisition source, intended use, lifecycle status, and applicable trust/licensing decisions.
- The inventory is generated or reconciled against the actual built and deployed candidate rather than a manually curated subset.

**Verification procedure**

1. Enumerate dependencies from built artifacts, resolved package environments, charts/images, installer paths, collections, and workflow definitions.
2. Compare that enumeration with the approved inventory and investigate every missing, extra, unresolved, or unowned component.

**Required evidence**

- Release-bound complete dependency inventory and resolved lock/manifests
- Reconciliation report comparing inventory with candidate payloads and deployment plan

#### SUP-02 — Immutable references resolve

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `ci7`

**Acceptance criteria**

- Components requiring immutability are bound to verified content digests or full commit identities, including privileged installers and every action subpath.
- Each pin resolves to the intended upstream content and expected action/artifact metadata; a syntactically valid but nonexistent SHA fails qualification.
- Mutable aliases cannot replace a required immutable identity during build, deployment, or release.

**Verification procedure**

1. Resolve every required pin against its upstream and verify the retrieved definition or payload is the intended component.
2. Test nonexistent, wrong-repository, moved-tag, and mutable-reference fixtures and confirm the release qualification rejects them.

**Required evidence**

- Pin-resolution report with upstream identity, content digest, and observation time
- Action-definition/input metadata checks and resolved deployment artifact manifest

#### SUP-03 — Trusted acquisition

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `ci7`

**Acceptance criteria**

- Each privileged or security-critical download is verified using the profile's approved upstream signature/checksum/provenance policy before execution or installation.
- Verification material comes from an authenticated trusted source; calculating a digest from the downloaded payload alone does not establish authenticity.
- Tampered content, wrong signer/digest, unsupported architecture, and missing verification material fail closed.

**Verification procedure**

1. Acquire representative release artifacts through the documented path and verify publisher identity, version, architecture, and integrity before use.
2. Substitute altered bytes, a wrong checksum/signer, and unavailable verification metadata in isolated fixtures; verify no unverified payload is executed or installed.

**Required evidence**

- Acquisition trust policy and approved signer/digest-source inventory
- Successful verification transcripts plus tampered/wrong-source negative cases

#### SUP-04 — SBOM and license inventory

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `ci7`

**Acceptance criteria**

- The SBOM identifies the actual released packages/images and relevant dependencies with versions and artifact identifiers.
- License/redistribution obligations have an accountable review and are reflected in distributed notices or required source/materials.
- Unresolved component identity or license obligations remain visible and cannot be represented as complete assurance.

**Verification procedure**

1. Compare sampled and high-risk SBOM entries with the candidate payload and resolved dependency inventory.
2. Inspect the distributed archives/images for the reviewed notices/materials and record any unidentified component or unresolved obligation.

**Required evidence**

- Artifact-bound machine-readable SBOM and dependency reconciliation
- License/notice inventory with accountable review and distributed notice check

#### SUP-05 — Build reproducibility

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `ci7`

**Acceptance criteria**

- Two clean builds using the frozen source and declared build inputs produce identical functional payloads under the documented reproducibility policy.
- Any permitted variation is explicitly identified, nonfunctional, reproducible in comparison tooling, and independently reviewed; unexplained binary/payload differences fail.
- Builds cannot depend on undeclared local files, stale build trees, mutable downloads, or workstation secrets.

**Verification procedure**

1. Build the same candidate twice in clean isolated environments using only approved inputs and compare file lists and payload digests.
2. Repeat with seeded local/stale files and verify they cannot affect the released payload; investigate every unexplained difference.

**Required evidence**

- Two independent clean-build manifests, environment/input records, and payload comparison
- Documented normalization/variation policy and dirty-worktree/stale-build test

#### SUP-06 — Release provenance

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `ci7`

**Acceptance criteria**

- Release attestations/signatures bind artifacts to the intended source commit, builder/workflow identity, and approved release context.
- A consumer-side verification procedure validates those bindings and fails for a substituted artifact, source identity, or unauthorized signer.
- Provenance, checksums, and signing/verification policy are retained with the release record.

**Verification procedure**

1. Verify the candidate using the documented consumer workflow without relying solely on the publisher's successful-job status.
2. Substitute the artifact digest, source commit, and signer/builder identity in controlled fixtures and confirm verification rejects each mismatch.

**Required evidence**

- Candidate provenance/attestation, signature, checksum manifest, and policy
- Independent consumer verification transcript and substitution-negative results

#### SUP-07 — Distribution completeness and confidentiality

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `ci7`

**Acceptance criteria**

- Source and wheel/container distributions contain exactly the approved runtime resources and required build/metadata files.
- Ignored credentials, local environment files, private data, stale cached manifests, and obsolete build resources cannot enter release archives.
- The installed candidate remains functional outside the checkout and its intended resource payload matches approved source identities.

**Verification procedure**

1. Seed realistic ignored secret fixtures and stale source/build manifest entries, then build every published distribution format.
2. Inspect every archive member/content and run isolated installation smoke checks; fail on sentinel presence, unexpected members, missing resources, or resource hash mismatch.

**Required evidence**

- Complete archive-member/content inspection and approved resource allowlist
- Dirty/stale-manifest secret-sentinel regression and isolated installed-candidate smoke report

#### SUP-08 — Release identity and permissions

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `ci7`

**Acceptance criteria**

- Publishing, signing, artifact access, and deployment identities have approved least-privilege scopes and appropriate branch/environment approval boundaries.
- Untrusted pull-request code cannot access privileged release/deployment credentials or obtain an authorized release identity.
- Credential lifetime, revocation, recovery, and audit ownership are defined and exercised without publishing to an unintended destination.

**Verification procedure**

1. Inspect the effective permissions and trust conditions for each publishing/signing/deployment identity and compare them with approved destinations/actions.
2. Rehearse authorized and unauthorized contexts against a safe release target, then revoke a test identity and verify it no longer authenticates.

**Required evidence**

- Workflow/identity permission review and protected-release configuration record
- Controlled release-identity rehearsal, unauthorized-context denial, and revocation verification

#### SUP-09 — Vulnerability release gate

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `security24`

**Acceptance criteria**

- Security scans use current policy/database information and cover the actual candidate artifacts and relevant source/deployment configuration.
- Material critical/high findings have recorded exploitability/impact triage and remediation verification; unresolved blocking findings prevent release.
- Suppression, accepted risk, skipped scans, or configured-but-unexecuted workflows cannot produce an assured passing control.

**Verification procedure**

1. Run the required scans against the candidate and reconcile all blocking findings with their reviewed disposition and verified fixes.
2. Introduce a controlled blocking-finding or skipped-scan fixture into the release gate and confirm publication approval is denied.

**Required evidence**

- Artifact/commit-bound security scan reports with tool/database timestamps
- Finding disposition/remediation records and gate failure/retest evidence

#### SUP-10 — Advisory and lifecycle response

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `ci7`

**Acceptance criteria**

- Every critical upstream has an advisory/lifecycle monitoring owner and a documented review/response target.
- Routine release aging and expedited security updates follow distinct approved paths; unsupported dependencies have dated migration decisions.
- A representative advisory exercise demonstrates triage, scope identification, pin update, regression verification, and deployment decision within the declared target.

**Verification procedure**

1. Select a relevant upstream advisory/lifecycle event and trace detection through affected-release identification and accountable triage.
2. Rehearse the update and verification path, measuring elapsed time against the declared response objective and recording overdue/unowned steps.

**Required evidence**

- Advisory/lifecycle ownership register and response policy
- Advisory exercise or incident record with timestamps and verified update results

### 7.8 TST — Verification and compatibility (8 points)

Accountable role: **Quality/verification owner**. Category release gate: **G-08**. Assign actual identities and independent reviewers in the assessment.

#### TST-01 — Functional/configuration regression

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Tests cover supported CLI/configuration contracts, boundary cases, prior defects, and materially unsafe combinations with explicit expected results.
- This framework's baseline policy requires at least 90% line and 85% branch coverage over the declared application scope; measured scope and any stricter thresholds are frozen before assessment.
- Critical behaviors have named positive, negative, and failure cases with passing results; coverage percentages alone do not establish behavioral completeness.

**Verification procedure**

1. Run the full declared regression suite against the candidate revision and verify both coverage thresholds are enforced by the actual CI command.
2. Trace every critical behavior and prior material defect to passing behavioral cases, then inspect uncovered branches for untested critical behavior.

**Required evidence**

- Release-bound unit/regression results and line/branch coverage reports
- Critical-behavior-to-test traceability matrix and prior-defect regression list

#### TST-02 — Installation and reconciliation integration

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Actual supported host/controller combinations exercise installation, unchanged reapply, representative drift repair, and relevant cleanup/uninstall boundaries.
- Integration results identify real target versions and effective deployed state; mocked command construction is not substituted for host/cluster execution.
- Unexpected restart, recreation, residual privileged material, or unsupported cleanup behavior is resolved or explicitly remains unqualified.

**Verification procedure**

1. Run the documented lifecycle sequence on clean approved staging targets for every in-scope support combination.
2. Compare observed packages, services, resources, permissions, and residual files with the specified state after each phase.

**Required evidence**

- Supported-combination integration matrix and sanitized host/cluster transcripts
- Before/after state snapshots for install, reapply, drift repair, and cleanup boundaries

#### TST-03 — Repeatable release-bound certificate lifecycle E2E harness

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- A versioned, repeatable qualification harness maps the profile-required issuance, renewal, key-rotation, delivery, and served-credential scenarios to their PKI control assertions and binds every run to the actual candidate and approved staging target.
- The harness uses independently inspectable consumer/credential oracles rather than Ready conditions alone; controlled wrong-identity, wrong-key or stale-certificate, and failed-adoption fixtures make the expected assertions fail.
- A documented command or controlled job reruns the frozen scenario set, retains run-specific sanitized artifacts, reports nonzero failure for an unmet critical assertion, and safely cleans its own test resources. Harness qualification does not replace the separate PKI behavior claims.

**Verification procedure**

1. Run the documented harness twice with the frozen scenario parameters against the same approved candidate/profile, checking release binding, reproducible assertions, retained artifacts, and safe cleanup.
2. Inject the controlled oracle-negative fixtures and verify the expected assertions fail with nonzero status and usable diagnostics; keep those fixtures separate from the real staging traces used to qualify PKI behavior.

**Required evidence**

- Versioned harness/scenario source, invocation/job definition, candidate binding, and scenario-to-PKI-control assertion map.
- Two reproducible qualification-run records with independent serial/key/chain/consumer observations, timing, exit results, and cleanup outcomes.
- Oracle-negative fixture results demonstrating detection of incorrect identity/key generation, stale served credentials, and missed consumer adoption; synthetic fixtures are labeled.

#### TST-04 — Negative authorization and isolation

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Requests outside approved names, subjects, usages, namespaces/tenants, issuer permissions, or trust-target policy are denied.
- Unauthorized identities cannot read private keys, approve requests, change trust targets, or obtain another tenant's credentials.
- Denial evidence includes the attempted action, effective identity/policy, and resulting absence of an unauthorized issued credential or secret disclosure.

**Verification procedure**

1. Attempt every defined unauthorized case using appropriately constrained staging test identities rather than an administrator identity.
2. Confirm the expected denial and independently inspect issuer, secret, trust-target, and consumer state for any unintended credential or disclosure.

**Required evidence**

- Authorization/isolation negative-case matrix and effective policy/RBAC snapshots
- Denied-request/access transcripts plus issuer/consumer/secret-state verification

#### TST-05 — Declared compatibility matrix

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Every combination included in the enterprise support claim has an explicit qualified, failed, or unqualified status and release-bound evidence.
- Matrix dimensions cover relevant controller versions, host OS/architecture, Kubernetes distribution/version, chart versions, adapter paths, and upgrade source/target versions.
- Selected-profile approval does not imply compatibility for unselected or merely registry-listed integrations.

**Verification procedure**

1. Enumerate the support claims from release documentation, registry, and profile, then reconcile them with the qualification matrix.
2. For each supported entry, inspect the corresponding actual test result and version identities; mark missing, failed, or stale entries unqualified.

**Required evidence**

- Frozen support/compatibility matrix with evidence references and limits
- Candidate test/qualification results for every declared supported combination

#### TST-06 — Failure and recovery contracts

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Conditional gate:** Mandatory release gate when the assessed profile includes a critical dependency or managed process whose failure can affect issuance, served credentials, trust, or recovery.

**Acceptance criteria**

- Each in-scope critical dependency/process has explicit timeout, retry, degraded-operation, stop, and recovery behavior.
- Approved staging fault cases demonstrate the declared behavior for dependency loss, process/node failure, and interrupted operations without unbounded retries or silent data/trust corruption.
- Measured failure/recovery outcomes meet the relevant availability and recovery objectives.

**Verification procedure**

1. Inject the declared dependency/process/operation failures in approved staging one controlled case at a time.
2. Measure detection, timeout/retry, degraded behavior, and recovery; inspect resulting data/trust state and compare with the contract.

**Required evidence**

- Critical-path failure contract and approved fault-injection plan
- Fault/recovery transcripts with timestamps, resulting state, and objective comparison

#### TST-07 — Security robustness verification

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Relevant static analysis, secret scanning, dependency analysis, malformed-input testing, and adversarial-path verification execute against the assessed revision/artifacts.
- Results and tool/policy versions are retained, and material findings are triaged and remediated with passing regression evidence.
- A configured scan, absent result, or narrow unit check cannot stand in for the required security-verification scope.

**Verification procedure**

1. Run each declared verification activity on the candidate, including malformed and hostile-path inputs relevant to CLI, inventory, and privileged operations.
2. Reconcile every material finding with a verified disposition and verify that required activities with missing results block assurance.

**Required evidence**

- Required-security-verification scope and executed reports with tool/policy versions
- Finding-to-fix-to-regression traceability records

#### TST-08 — Release-candidate artifact validation

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `mixed7_30`

**Acceptance criteria**

- Qualification exercises the actual built candidate packages/images and rendered deployment assets with recorded digests.
- Charts/manifests render and validate for the intended platform versions; installed-artifact CLI/resource behavior is checked outside the source tree.
- Source-only success, mock-only success, or testing a different build cannot qualify the release candidate.

**Verification procedure**

1. Retrieve the candidate through the intended release-consumer path, verify its identity, and install or render it in the approved test environment.
2. Compare the tested digests and effective rendered/deployed versions with the proposed release record; reject any substitution or unverified regeneration.

**Required evidence**

- Candidate artifact digest manifest and isolated installation results
- Rendered chart/manifest validation and staging deployment record bound to candidate digests

### 7.9 OBS — Observability, SLOs, and alerting (8 points)

Accountable role: **Observability/SRE owner**. Category release gate: **G-09**. Assign actual identities and independent reviewers in the assessment.

#### OBS-01 — Explicit outcome indicators and service objectives

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The service catalog separates request admission/scheduling, eligible approved-request issuance/readiness, and actual consumer certificate availability.
- Each indicator has a numerator, denominator, measurement point, time window, numeric target, exclusions, owner, and error-budget policy; intentional policy-denied tests are not confused with failed eligible requests.

**Verification procedure**

1. Review definitions and profile targets with platform, PKI, and consumer owners, resolving missing denominators and excluded outcomes.
2. Recompute representative indicators from raw events and verify classification of eligible failures, deliberate denials, missing data, and consumer failures.

**Required evidence**

- Approved SLI/SLO definitions and executable measurement queries or probe logic.
- Sample event classification and dashboard calculations reconciled against raw observations.

#### OBS-02 — Working telemetry and missing-data detection

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Monitoring operators/CRDs, rule selection, scrapes, exporters, retention, and time alignment actually work for the pinned versions.
- Actual metric names/labels are verified and missing or stale telemetry or monitoring-path loss produces an independent signal; storing a rule manifest does not prove operational monitoring.

**Verification procedure**

1. Inspect the running monitoring integration and reconcile each required signal with observed metrics and loaded rules.
2. Interrupt the approved non-production telemetry fixture and verify stale/missing data is detected through the intended independent route.

**Required evidence**

- Loaded-rule and scrape-target status, observed metric/label samples, freshness and retention results.
- Controlled missing-scrape or monitoring-path test and independent detection/alert outcome.

#### OBS-03 — Lifetime-aware renewal and expiry safety alerts

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Expiry and failed-renewal alerts leave sufficient time for the certificate class's approved recovery window across both short- and long-lived credentials.
- Signals distinguish replacement readiness from consumer adoption, identify affected consumers, and do not assume one blanket expiry threshold suits every lifetime.

**Verification procedure**

1. Compare alert thresholds with each certificate class's approved lifetime and recovery objectives.
2. Run the authorized stuck-renewal/adoption fixture and verify actionable detection occurs before its class-specific safety margin is consumed.

**Required evidence**

- Certificate-class lifetime, renewal, recovery-margin, and alert-threshold configuration.
- Controlled short-lifetime or stuck-renewal fixture results with evaluated alert and consumer-adoption timelines.

#### OBS-04 — End-to-end certificate service probes

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- A controlled representative probe follows allowed issuance, approval, delivery/adoption, and the certificate actually served or used by the consumer.
- The probe verifies expected identity, chain, validity interval, and certificate/key generation or fingerprint, and detects broken adoption while Kubernetes and controller signals remain healthy.

**Verification procedure**

1. Run the approved synthetic lifecycle through the intended issuer and representative consumer and correlate each stage.
2. Introduce the approved non-production delivery/adoption fault and confirm the probe detects the consumer outcome independently of Certificate Ready and API health.

**Required evidence**

- Timestamped synthetic observations for each lifecycle stage and identified issuer/environment.
- Served-chain/fingerprint results and a controlled adoption-failure detection result.

#### OBS-05 — Component and dependency diagnostic coverage

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Operational views cover datastore/API, controller queues/retries, admission, approval/trust reconciliation, LB/VIP state, DNS/CA quotas, backup age, time, and resource/disk pressure.
- A responder can distinguish platform, provider, policy, and consumer-delivery failures using collected signals without accessing secret values.

**Verification procedure**

1. Map the approved dependency and failure model to existing dashboards, logs, and alerts, recording missing diagnostic coverage.
2. Give a responder selected sanitized failure traces and verify correct fault localization using the operational views and runbooks.

**Required evidence**

- Working dashboard/query inventory mapped to critical components and dependencies.
- Representative staged failure traces and responder diagnosis walkthrough.

#### OBS-06 — Centralized correlated operational audit

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Release gate if the frozen threat model or assurance profile requires independently retained issuance, authorization, or trust-change audit evidence.

**Acceptance criteria**

- Relevant host, Kubernetes, CA, approval, and trust events reach the approved central system with usable timestamps, access controls, and retention.
- Records correlate request, authorization, serial/fingerprint, trust change, and consumer impact without exposing tokens, private keys, or credentials; local cluster loss does not remove the only audit copy.

**Verification procedure**

1. Trace a representative approved issuance or trust change through the central audit record and confirm required linkage and timestamps.
2. Test approved redaction and audit-forwarding-loss fixtures and verify protected data is absent while loss is detected.

**Required evidence**

- Sanitized correlated event sample and forwarding/access/retention configuration.
- Clock alignment, redaction-fixture results, independent retention, and audit-path loss detection.

#### OBS-07 — Actionable end-to-end alert delivery

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Critical conditions reach the accountable on-call route with service/tenant context, severity, runbook, and escalation information.
- Routing, silences/inhibition, acknowledgement, and escalation meet the approved response target; an alert visible only in Prometheus is insufficient.

**Verification procedure**

1. Inject an authorized non-production critical alert through the real approved routing path and inspect suppression behavior.
2. Confirm receiver delivery, acknowledgement and required escalation against targets, then remove test alerts and restore any changed test silences.

**Required evidence**

- Controlled alert injection, receiver delivery, acknowledgement, and escalation timestamps.
- Actual routing/silence configuration, responder confirmation, runbook reference, and cleanup record.

#### OBS-08 — Error-budget and telemetry review operation

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Conditional gate:** Mandatory release gate where the frozen release policy uses SLO/error-budget state or critical-service telemetry to authorize changes; decide activation from the approved policy before qualification.

**Acceptance criteria**

- The responsible team reviews measured objectives, budget burn, renewal risk, recurring causes, and alert quality at the declared cadence.
- Missing data is not counted as success, dependency impact is not hidden by unsupported exclusions, and exhausted budgets or unobservable health invoke the frozen release/operations policy.

**Verification procedure**

1. Recompute the current assessment window's budget and signal completeness from the approved measurement sources.
2. Review the result with the accountable owner and verify that the resulting release or remediation decision follows the frozen policy.

**Required evidence**

- Current reviewed SLO/error-budget readout with reproducible calculations.
- Decision/action record demonstrating the release policy uses actual budget and telemetry state.

### 7.10 OPS — Operations, response, and change (6 points)

Accountable role: **Operations owner**. Category release gate: **G-10**. Assign actual identities and independent reviewers in the assessment.

#### OPS-01 — Executable runbooks

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Install, health diagnosis, repair, recovery, and rollback/forward-recovery procedures state prerequisites, authorized roles, stop conditions, expected results, and escalation.
- An authorized operator other than the original author successfully executes every critical recovery procedure in representative staging.
- Runbook gaps discovered during execution are corrected and the affected procedure is reverified.

**Verification procedure**

1. Have an authorized alternate operator execute the critical staging runbooks using only the documented instructions and approved access.
2. Compare measured outcomes with the acceptance criteria; update and replay any step requiring undocumented knowledge or unsafe improvisation.

**Required evidence**

- Versioned operational/recovery runbooks with ownership and reviewed boundaries
- Independent-operator exercise records and resolved runbook-gap retest results

#### OPS-02 — Human incident response and operational handoff

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Primary/secondary responders, service hours, incident authority, and acknowledgment, triage, and containment/escalation targets are approved; technical alert delivery is qualified separately under OBS-07.
- After an actually delivered representative alert, an accountable responder diagnoses impact, classifies the incident, and makes or executes the authorized staging containment/escalation decision within the approved targets. Message receipt alone is insufficient.
- When the primary responder is unavailable, a secondary takes accountable ownership and receives an actionable handoff of state, decisions, evidence, and pending recovery work without secret disclosure or loss of required response coverage.

**Verification procedure**

1. Start from an alert whose technical route is proven under OBS-07; have the responder investigate the approved staging cause, record impact and authority, and make or execute the scoped containment/escalation decision while measuring the human-response targets.
2. Make the primary unavailable in the approved exercise, verify secondary ownership and an actionable state/evidence handoff, and confirm continued safe incident handling; resolve and recheck discovered access or runbook gaps.

**Required evidence**

- Controlled on-call roster/authority references, response objectives, and incident/runbook responsibilities.
- Human-response exercise timeline covering delivered alert, acknowledgment, diagnosis, impact classification, authorized decision/action, and resulting state.
- Primary-absence and secondary-handoff record with ownership continuity, runbook/access gaps, and corrective-action closure.

#### OPS-03 — Controlled rollout

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Each production change defines approved scope, preconditions, allowed blast radius, health checkpoints, stop criteria, and rollback/forward-recovery authority.
- Staging rehearsal demonstrates serial/canary or other approved rollout limits and a stop on failed health/acceptance criteria.
- The release record identifies the actual plan, approvers, artifacts, execution window, and post-change verification.

**Verification procedure**

1. Rehearse the proposed rollout against representative staging, verifying target limits and checkpoint measurements.
2. Trigger an approved failing checkpoint and confirm subsequent unsafe rollout stops, the responsible authority is notified, and the recovery path succeeds.

**Required evidence**

- Approved change/rollout plan with thresholds and artifact/config identities
- Successful and deliberately stopped staging rollout transcripts with recovery outcome

#### OPS-04 — Credential/key rotation operations

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- Supported rotation procedures identify all consumers, authority boundaries, replacement provisioning, verification, old-access revocation, and recovery constraints.
- Critical credential/key rotations are rehearsed through the actual consumer path and complete without secret-value disclosure or unintended prolonged outage.
- Verification proves both successful replacement behavior and rejection of the superseded credential/key where the protocol permits.

**Verification procedure**

1. Rotate controlled test material for the in-scope critical credential/key classes through their supported upstream workflows.
2. Verify all consumers use the replacement, test that old access is revoked/rejected as specified, and scan resulting transcripts/artifacts for leaked test sentinels.

**Required evidence**

- Credential/key consumer inventory and approved rotation procedures
- Staging rotation, replacement verification, old-access rejection, and outage-timing records

#### OPS-05 — Maintenance operations

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Patch, upgrade, retention/cleanup, certificate-policy changes, and dependency maintenance have named owners, operating cadence, and completion targets.
- Maintenance procedures preserve intended service, recovery material, trust state, and minimum supported versions.
- A representative maintenance cycle records prechecks, execution, postchecks, and any required corrective actions.

**Verification procedure**

1. Select representative platform, chart/adapter, and retention maintenance tasks and compare their due dates with declared targets.
2. Execute the approved staging procedures and verify resulting versions, health, retained recovery material, and absence of unintended trust or credential changes.

**Required evidence**

- Maintenance calendar/backlog with ownership and lifecycle/retention policies
- Completed maintenance rehearsal/cycle records and post-maintenance health checks

#### OPS-06 — Incident learning and handover

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- Exercises cover the declared incident classes, decision authority, evidence preservation, communications, and recovery handover.
- Material exercise/incident findings have owners, deadlines, and verification of closure.
- At least one alternate authorized operator demonstrates the required knowledge/access without depending on the original implementer.

**Verification procedure**

1. Run or inspect the current representative incident exercises and trace material findings through accountable closure and revalidation.
2. Perform an alternate-operator handover scenario and confirm incident records, approvals, controlled access, and recovery responsibilities are discoverable.

**Required evidence**

- Incident exercise/post-incident review records and action register
- Handover/alternate-operator exercise with access and procedure-gap outcomes

### 7.11 PERF — Capacity, performance, and endurance (4 points)

Accountable role: **Capacity/performance owner**. Category release gate: **G-11**. Assign actual identities and independent reviewers in the assessment.

#### PERF-01 — Representative workload and dependency-limit model

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- The frozen model states certificate counts/classes, tenants, request and renewal rates, synchronization bursts, renewal windows, DNS behavior, provider quotas, backup overlap, and protected-node loss.
- Demand assumptions are tied to measured estate or an approved forecast, with numeric latency, backlog, resource, headroom, and duration targets set before testing.

**Verification procedure**

1. Reconcile the workload model with the intended consumer estate, selected issuers, demand forecast, and documented provider limits.
2. Approve the complete test profile and acceptance targets before generating load or interpreting results.

**Required evidence**

- Versioned workload model, demand baseline/forecast, and applicable upstream quota references.
- Approved test-data shape and numeric performance/headroom acceptance limits.

#### PERF-02 — Sustained and degraded-mode capacity

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- At the agreed sustained peak and protected single-failure case, scheduling and eligible issuance meet their latency/deadline targets and consumers retain valid certificates.
- Observed resources/storage remain within the approved limits and headroom across the justified test duration; steady-state averages do not replace degraded-mode evidence.

**Verification procedure**

1. Run the approved sustained workload and collect scheduling, issuance, consumer, and resource measurements across the full target duration.
2. Repeat the approved workload in the protected degraded-mode case and compare all outcomes with the frozen capacity and service objectives.

**Required evidence**

- Reproducible load configuration, population/sample size, percentile/deadline results, and consumer probes.
- CPU, memory, storage, datastore and network traces with degraded-mode comparison and headroom calculation.

#### PERF-03 — Renewal-storm and backlog recovery

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `live30`

**Acceptance criteria**

- The modeled burst, temporary rate limits, and restored backlog do not cause unbounded retries, uncontrolled duplicate issuance, quota exhaustion, or expiry of affected consumers.
- Queue age and drain time recover within the frozen budgets; tests use authorized staging issuers and quotas rather than unapproved load on public CAs.

**Verification procedure**

1. Confirm provider and environment authorization, then generate the frozen renewal-burst and temporary-rejection fixtures against the approved staging path.
2. Observe retries, quotas, duplicate issuance, backlog drain and actual consumer certificate state, and compare them with the frozen targets.

**Required evidence**

- Approved burst/rate-limit/backlog fixture and load configuration.
- Queue-age/drain curves, issuance counts, retry/rate-limit observations, and consumer expiry/adoption results.

#### PERF-04 — Endurance and resource-growth behavior

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `live30`

**Acceptance criteria**

- A justified endurance window covers representative renewal and backup overlap and shows bounded or explained growth in memory, descriptors, queues, logs, datastore size, and disk use.
- Pressure detection, retention and cleanup act before approved service objectives fail; the report includes recovery behavior and a capacity horizon with explicit assumptions.

**Verification procedure**

1. Run the frozen endurance workload through the required lifecycle and backup overlap while recording resource and storage growth.
2. Evaluate boundedness, retention and the approved pressure fixture, verify recovery, and calculate the capacity horizon against the agreed action thresholds.

**Required evidence**

- Endurance timeline, raw resource/growth observations, and retention/cleanup results.
- Approved pressure/recovery fixture results and capacity projection with assumptions, owner, and action trigger.

### 7.12 EVD — Evidence, review, and score integrity (4 points)

Accountable role: **Independent assurance owner**. Category release gate: **G-12**. Assign actual identities and independent reviewers in the assessment.

#### EVD-01 — Evidence subject and integrity

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `review30`

**Acceptance criteria**

- Every evidence claim identifies the exact release/profile/environment and relevant component, configuration, policy, and artifact fingerprints.
- Artifacts have protected locations, hashes or immutable identities, classification, access/retention rules, observation/review timestamps, and freshness/invalidation policy.
- Missing, tampered, stale, wrong-subject, or incorrectly reused evidence cannot yield assured credit.

**Verification procedure**

1. Resolve each claim to its artifact and verify subject bindings, digest/identity, access classification, timestamps, and freshness.
2. Alter a copy, substitute another environment/release, and present expired/reused fixtures; confirm the assessment rejects assured credit.

**Required evidence**

- Evidence manifest and subject/fingerprint inventory
- Integrity/freshness/access verification report including tamper, stale, and wrong-subject cases

#### EVD-02 — Reproducible observations

**Weight:** 1.00 point · **Planning criticality:** P1 · **Mandatory release gate:** No · **Freshness:** `review30`

**Acceptance criteria**

- Evidence records specify procedure/test ID, tools, expected outcome, actual outcome, timestamps, limitations, and sanitized inspectable output.
- A second authorized reviewer can reproduce or independently inspect the observation without relying on the original collector's narrative alone.
- Screenshots, generated templates, successful reads, and self-attested checklist states are not accepted as sole proof of live behavior.

**Verification procedure**

1. Select all hard-gate observations and a defined sample of other controls, then replay or independently inspect them using the recorded procedure.
2. Compare the second reviewer's outcome with the original claim and leave discrepancies or missing primary observations unresolved rather than inferring a pass.

**Required evidence**

- Per-control observation records and sanitized command/test transcripts
- Independent replay/inspection report with limitations and discrepancy handling

#### EVD-03 — Authenticated independent review

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `review30`

**Acceptance criteria**

- Review approval is attributable through an authenticated trusted approval system and is bound to the exact assessment revision and evidence set.
- Critical controls receive the required independent reviewer/separation-of-duties approval; editable reviewer-name text alone is insufficient.
- Withdrawn, expired, self-approved, or mismatched approvals cannot authorize an assured control or release verdict.

**Verification procedure**

1. Verify reviewer identity/authority and independence through the controlled approval system, then match approval references to the assessed evidence revision.
2. Exercise self-approval, withdrawn/expired approval, and changed-evidence fixtures and confirm each invalidates assured credit or the gate verdict.

**Required evidence**

- Authenticated approval records bound to assessment/evidence digests
- Reviewer-role/separation-of-duties mapping and invalid-approval rejection results

#### EVD-04 — Fail-closed scoring and auditability

**Weight:** 1.00 point · **Planning criticality:** P0 · **Mandatory release gate:** Yes · **Freshness:** `review30`

**Acceptance criteria**

- The versioned evaluator recognizes exactly the 100 stable one-point controls, cumulative 0/0.25/0.5/0.75/1 levels, frozen scope/applicability, and non-compensating gate logic.
- Duplicate/missing controls, invalid arithmetic, stale/tampered evidence, failed/unknown mandatory gates, and active criterion-substituting exceptions cannot produce 100/100 or production approval.
- The assessment exports a reproducible per-control decision trail with owner, earned credit, status, evidence, reviewer, limitations, and catalogue/profile version.

**Verification procedure**

1. Run adversarial scoring fixtures for duplicate/missing IDs, invalid levels, altered weights/denominators, N/A gaming, stale/tampered proof, and failed/unknown gates.
2. Independently recompute a complete assessment from its frozen catalogue and evidence; require exact agreement with the evaluator and verify 100 is impossible when any required criterion remains unmet.

**Required evidence**

- Versioned evaluator/catalogue/schema and decision-rule specification
- Positive/negative evaluator regression results and independently reproduced assessment export

## 8. Execution roadmap for a future goal

| Phase | Work and exit evidence |
|---|---|
| 0 — Intake and freeze | Select the real deployment/product claim, release candidate, support matrix, target environments, owners, targets, authorization boundaries, and evidence policy. Record missing access immediately. No default/example credential is treated as a production input. |
| 1 — Honest baseline | Inspect every control against the current checkout and external state. Mark facts proven, contradicted, missing, stale, or blocked. Produce an initial score with evidence coverage; do not copy the legacy 97. |
| 2 — Repository and delivery | Remediate configuration, automation, packaging, immutable dependencies, security findings, meaningful tests, CI semantics, release provenance, and secret protection. Prove installed-artifact behavior outside the checkout. |
| 3 — Deployment and lifecycle | Deploy the actual candidate to authorized representative staging; qualify the selected adapter/issuer paths, policy denials, renewal/adoption, rotation, trust, and monitoring. Preserve exact versions and effective config. |
| 4 — Resilience and recovery | Run approved failure and dependency tests, off-host recovery, alternate-path recovery, and measured RTO/RPO checks. Preserve client outcomes, cleanup, and repeatability evidence. |
| 5 — Capacity and operations | Execute the approved workload/soak model, prove alerts reach responders, exercise runbooks/rotation/incidents, and accept operating ownership. |
| 6 — Independent assurance | Validate the data structure and evaluator, review every criterion and artifact, verify approvals, recompute gates/points, resolve findings, and obtain the authorized release decision. |

Repository work may proceed while environment information is pending. Dependent
live work cannot proceed without the required access and authorization. Report
the exact blocked controls and input needed instead of substituting synthetic
output, deleting requirements, or repeatedly rerunning already-passing checks.

## 9. Required assessment and evidence layout

An example restricted working layout is:

```text
assessment/<assessment-id>/
  assessment.json
  scope-and-objectives.json
  source-and-artifact-manifest.json
  approvals/                 # controlled approval references or verified records
  evidence/
    repository/
    ci-and-security/
    deployment/
    pki-lifecycle/
    access-and-isolation/
    ha-and-network/
    backup-and-restore/
    monitoring-and-response/
    performance/
    operations/
  findings-and-exceptions.json
  change-impact-review.json
  readiness-report.md
```

Keep this working layout outside ordinary version control unless every artifact
is reviewed for disclosure. Preserve restricted originals in the approved
evidence system and publish only sanitized copies or controlled references.

Every final per-control result must include ID, weight, valid maturity level,
credit, workflow state, criterion-by-criterion result, owner, verifier,
independent reviewer/approval reference, verification run, artifact references,
subject fingerprints, dates/expiry, findings, limits, and any exception.

The final report must show the claim and scope before its score; category
totals; coverage and unknowns; all twelve gate decisions; failed and blocked
controls; current findings/exceptions; compatibility coverage; actual versus
approved SLO/RTO/RPO/capacity results; review authorities; next requalification
date; and the authorized production decision. A standalone number is incomplete.

## 10. Evaluator requirements and adversarial acceptance cases

The future evaluator required by EVD-04 must recompute results from source
records, not trust manually edited summary totals. It must reject unknown,
missing, or duplicate control IDs; modified weights; unsupported maturity
levels; invalid stage/status combinations; broken subject binding; stale or
future-dated observations; mismatched or inaccessible artifacts; and invalid
review/approval references. Gate failures and conditional-trigger uncertainty
must not disappear behind score rounding or a risk-acceptance label.

At minimum, validate these cases:

| Case | Required evaluator behavior |
|---|---|
| Empty template | Structurally valid draft; NOT ASSESSED, no approval, no invented points. |
| All implementation-only records | Award only supported lower-level credit; live controls and gates remain incomplete. |
| 99 assured controls plus failed authorization | 99/100, failed release gate, NOT APPROVED. |
| Missing control, extra control, duplicate JSON key, or altered weight | Reject input; never normalize into a passing result. |
| Stale live restore or newer material storage/credential change | Invalidate unsupported recovery credit; require requalification. |
| Tampered artifact, path traversal, unauthorized URI, or replaced signature identity | Reject the proof and fail closed. |
| Approved risk exception for an unmet criterion | Preserve the unmet criterion and reduced credit; at most a separately authorized conditional decision for an eligible non-gate risk. |
| Editable reviewer name without authenticated approval | Cannot reach assured level. |
| Mock, fixture, screenshot, configured workflow, or old unrelated CI run presented as live proof | Reject the unsupported claim; preserve the artifact's actual classification. |
| 100 current assured controls, all gates PASS, correct subject and authenticated authorities | Permit a computed 100/100 result; organizational release authorization remains separately attributable. |

The supplied schema enforces structure and several obvious approval constraints.
It cannot perform trust verification, inspect real behavior, validate every
cross-reference, or replace the future evaluator's semantic tests. A syntactically
valid assessment is not automatically an assured assessment.

## 11. Exceptions, findings, and requalification

Classify findings as P0 critical, P1 major, P2 moderate, or P3 minor for this
assessment. Severity reflects the actual affected scope and outcome; the
catalogue's criticality is a planning classification, not a validated
vulnerability finding. An observed authorization bypass, signing-key exposure,
unrecoverable required state, or material production isolation failure demands
immediate escalation and blocks the applicable release.

An exception record needs the unmet control/criterion, factual impact, affected
scope, compensating measures, accountable remediation owner, due date, expiry,
authorized risk approver, and verification/review references. It cannot change
the denominator, turn a failed gate into PASS, or earn the missing assured
point. An expired exception is an unresolved issue. No active exception may
substitute for a required acceptance criterion at 100/100.

Requalification is triggered by relevant changes, new material advisories,
incidents, evidence expiry, ownership/custody changes, or failed recurring
checks. The assessment must identify which controls were invalidated, which
proof remains applicable, who reviewed that conclusion, and what was rerun.

### Proposed operating cadence

Freeze the service-specific cadence and any stricter organizational rules in
the profile. The following is a starting operating policy, not evidence that
the activities have happened and not permission to exceed the release freshness
limits in section 5.

| Cadence/trigger | Required operating activity | Accountable role |
|---|---|---|
| Continuous or service-objective interval | Service/consumer probes, renewal margin, queue/dependency health, backup age, audit collection, and actionable alerts; detect missing data. | SRE/observability and on-call owners |
| Each backup cycle | Confirm successful protected off-host creation and age against RPO; alarm on missed or failed replication. | Recovery owner |
| Daily operator review | Review failures, capacity/disk pressure, oldest eligible work, near-expiry classes, failed backups, and unresolved security alerts. | Operations owner |
| Weekly | Review relevant upstream advisories/support changes, dependency or quota risks, anomalous issuance, and remediation deadlines. | Security, PKI, and dependency owners |
| Monthly | Review SLO/error budget, alert quality, capacity forecast, certificate/identity ownership drift, open risks, and operational actions. | Service, PKI, security, and SRE owners |
| Quarterly, and before relevant material changes | Rehearse approved HA and off-host restore paths; review privileged access, recoverability, alternate operators, and credential-operation readiness. | Platform, recovery, security, and operations owners |
| Annually, and after material trust/threat changes | Rehearse broader location-loss/CA-compromise/trust-rollover response and reassess custody, organizational dependencies, and incident lessons. Use approved staging/test trust material rather than casually rotating production roots. | PKI authority, security owner, and continuity owner |
| Every proposed release | Verify exact-candidate CI/security/artifact/provenance results, change impact, evidence freshness, gates, support matrix, independent reviews, and the release authority's decision. | Release and assurance owners |

An existing stale quarterly drill does not become current merely because a
calendar says the next quarterly drill is not due. Required release evidence
must still meet this framework's default 30-day live qualification window or
an explicitly preapproved, separately versioned alternative profile.

## 12. Relationship to the existing CertWeaver assessment

The existing [repository scorecard](production-readiness.md) and
[validation report](test-report.md) remain useful evidence sources. Their
declared 97/100 baseline and ten-control live gate are a different rubric.
They cannot be relabeled as 97/100 under this enterprise framework.

Previously passing unit tests, coverage, lint, packaging checks, and verified CI
action pins may support individual controls after subject/freshness review.
They do not prove an actual installation, every advertised adapter, served
certificate adoption, policy isolation, off-host restore, operational response,
or authenticated organizational approval. Do not discard useful evidence, and
do not promote it beyond what its scope proves.

The new assessment template deliberately starts unassessed. No current score
for these 100 controls has been fabricated, and no live credentials or named
organizational reviewers have been invented.

## 13. Ready-to-copy future goal

Use the full [goal prompt](enterprise-production-readiness-goal.txt), filling in
the real profile/release/environment and available access. Its core objective is:

> Bring the named CertWeaver release and approved production profile to 100/100
> under version 1.0.0 of this enterprise readiness framework. Demonstrate all
> 100 controls at assured level with current, release-bound evidence, every
> mandatory/activated gate passing, no exception replacing an unmet criterion,
> and authenticated independent review plus the authorized production decision.
> Preserve the scope, denominator, weights, evidence rules, and hard gates.
> Implement and verify actual gaps; do not manufacture proof or redefine success.

## 14. Primary references and design boundaries

These references inform the engineering topics covered. The 100-point
allocation, maturity levels, freshness windows, and decision rules are authored
for this framework, not quoted standards or certification criteria.

| Primary source | Relevant design context |
|---|---|
| [NIST SSDF v1.1, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Secure development, protecting software, producing secure releases, and responding to vulnerabilities. No SSDF conformance claim is made by this score. |
| [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) | Review effective cluster, workload, identity, network, and secret controls for the installed versions. |
| [cert-manager certificate lifecycle](https://cert-manager.io/docs/usage/certificate/) | Renewal, explicit key-rotation behavior, and the need to verify actual consumer use. |
| [cert-manager approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/) | Verify the effective authorization/approval path rather than the presence of a policy file. |
| [trust-manager](https://cert-manager.io/docs/trust/trust-manager/) | Scope trust distribution to explicit intended targets and inspect reconciliation results. |
| [RKE2 backup and restore](https://docs.rke2.io/datastore/backup_restore) | Restore planning must include recovery bootstrap material; cluster-held S3 Secrets are unavailable while the API is down. |
| [Kubernetes disruptions](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/) | Distinguish voluntary maintenance protections from involuntary failures. |
| [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts) | Consumers must verify provenance against expected identities, subjects, and build properties; merely producing an attestation is insufficient. No SLSA level is inferred from this framework. |
| [Google SRE SLO guidance](https://sre.google/workbook/implementing-slos/) | Define service-user outcomes, measurable indicators, and error-budget decisions with accountable owners. |

Recheck upstream support and behavior when selecting a production version.
This document does not freeze the current upstream compatibility or security
status of any component merely by naming its project.
