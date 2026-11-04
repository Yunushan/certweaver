# Staging inputs and qualification approvals

Use this handoff to prepare the named release and representative staging profile
for the [100-control enterprise assessment](enterprise-production-readiness.md).
The service owner freezes scope and objectives, domain owners supply the access
and operating plans, and independent authorities authorize and review execution.
Production acceptance requires current evidence for every control at level 4.

## Prepare the private input package

Run from the approved controller, using the reviewed candidate and locked
dependencies. Choose a new directory inside an approved restricted location:

```sh
certweaver staging-init -o .certweaver/staging/assessment-01
```

Initialization refuses an existing directory, creates POSIX mode-0700 storage
and mode-0600 files, and leaves all operator decisions unset. On Windows, apply
the organization's restricted directory ACL before storing actual inputs.
Keep this package outside version control and distributable artifacts.

| Generated file | Who completes or uses it |
|---|---|
| `assessment.json` | Service and domain owners fill the subject, 24 objectives, eight applicability decisions and control assignments. Evidence and observations are added only after execution. |
| `staging-inputs.json` | Platform, PKI, recovery and assurance owners supply the references and 100 independent reviewer/procedure assignments below. |
| `staging-inputs.schema.json` | An editor aid. The installed checker uses its own contract, so editing this file cannot weaken validation. |
| `enterprise-assessment.schema.json` | Frozen assessment schema for editor validation; the evaluator uses its installed, digest-pinned schema. |
| `control-plan.json` | Frozen planning reference with all 100 controls, exact acceptance criteria, verification/evidence requirements, gates and freshness policies. Each control's actual procedure must address its complete contract. |
| `approval-checklist.json` | Exact purpose names for 33 scope/objective/applicability decisions, 400 possible control-level purposes, 12 category gates and six release authorities, plus per-record requirements. Final assurance needs 100 level-4 control reviews attesting cumulative requirements; the lower-level purposes support interim scoring. |

Do not put token values, private keys, passwords, kubeconfig contents, S3
credentials or contact details into these JSON files. Use controlled locators;
the checker never dereferences them. Actual configuration and rendered
inventory can also contain sensitive references and need restricted storage.

## Freeze the subject and configuration

Complete every `assessment.json.subject` field except an empty working-tree
patch and explicitly reviewed exclusions. Supply the final commit, release
artifact SHA-256/provenance, configuration/resource/pipeline/packaging digests,
environment fingerprint, profile and policy revisions, trust/tenant/failure
domains, dependency references, compatibility claims and scope approval locator.
The default planning scope is RKE2 HA and explicitly selected issuer/adapters;
the service owner must approve the actual claim before observation.

Prepare the real `certweaver.yml` using the selected example and schema. The
platform owner supplies actual node names/addresses, controller transport and
privilege policy, VIP or approved external LB, interfaces, DNS/time/network
prerequisites, OS/architecture baseline, issuer/consumer configuration, approved
versions and immutable artifact identities. Supply token, Keepalived and backup
credential file references through the approved secret system. The host owner
must decide SELinux/LB prerequisites without disabling protections for the test.

Generate the inventory and inspect both the hosts and effective variables:

```sh
certweaver validate -c /restricted/staging/certweaver.yml
certweaver render-inventory -c /restricted/staging/certweaver.yml \
  -o /restricted/staging/inventory.yml
certweaver staging-check .certweaver/staging/assessment-01 \
  --config /restricted/staging/certweaver.yml \
  --inventory /restricted/staging/inventory.yml --json
```

These commands validate and render locally. `staging-check` checks the raw
configuration SHA-256 against `subject.configSha256`, reports the canonical
rendered inventory digest, and compares the supplied inventory's complete
parsed contents with that configuration-derived inventory. Copy the reported
inventory digest to `staging-inputs.json.deployment.renderedInventorySha256`
and obtain the applicable scope review. Resolved secret-file paths depend on
the configuration's controller location; changing that location requires a new
inventory review and digest. The input checker does not verify file credentials,
network reachability, remote hosts, artifact provenance or external approvals.

Exit 2 reports incomplete or inconsistent inputs. Exit 0 means input inspection
is complete and **authorization is still unverified**. Its report always states
`executionAuthorized: false`, `enterprisePointsAwarded: 0` and production
`NOT_APPROVED`. Never use this exit code as an execution or production gate.

## Supply the staging references

Every field is required for routing review. For an inapplicable dependency,
provide a controlled, reviewed applicability record as its reference rather
than a placeholder or fabricated service. Authority review establishes whether
that decision satisfies the frozen profile.

| Input section | Required fields and accountable source |
|---|---|
| `deployment` | Platform owner: actual `mode`, `configurationRef`, `inventoryRef`, and canonical `renderedInventorySha256`. |
| `access` | Platform/security/recovery owners: `controllerRef`, `transportAccessRef`, `privilegePolicyRef`, `kubeconfigRef`, `secretSystemRef`, and `independentRecoveryAccessRef` usable when the cluster is unavailable. |
| `topology` | Platform/PKI/recovery owners: `architectureRef`, `hostBaselineRef`, `networkDnsTimePolicyRef`, `loadBalancerPolicyRef`, `selinuxPolicyRef`, `issuerPolicyRef`, `backupTargetRef`, and authorized `notificationTestDestinationRef`. |
| `execution` | Operations/change authority: `runbookRef`, `faultLoadPlanRef`, `recoveryPlanRef`, `stopConditionsRef`, `cleanupPlanRef`, timezone-aware `windowStart`/`windowEnd`, and `authorizationRef`. The checker rejects expired or reversed windows. |
| `assurance` | Independent assurance/security owners: `backendIntegrationRef`, `approvalAuthorityPolicyRef`, `evidenceStoreRef`, `retentionPolicyRef`, `originalEvidenceAccessRef`, and `redactionPolicyRef`. |
| `authorities` | Canonical `actorRef` and distinct `deputyRef` for service owner, PKI authority, security owner, operations owner, independent assessor and change authority. |
| `controlPlans` | For every control, an `independentReviewerRef` distinct from owner/implementer/verifier and a controlled `procedureRef`. Assign owner, implementation author and verifier in the matching assessment control record. |

The report includes `scopeSha256`, `reviewSha256` and `inputPackageSha256`.
The latter binds the full assessment and staging inputs with approval locator
fields omitted, including `authorizationRef`, to avoid circular references.
Changing targets, plans, assignments, objectives or scope changes the applicable
digest. The authority system must resolve canonical identities, purpose,
payload, validity, revocation and separation of duties; different locator
strings alone cannot establish independence.

## Approve all 24 objectives

For each objective, fill `target`, `unitAndWindow`, `measurementRef` and
`ownerApprovalRef` in the assessment. Targets are strings to support multiple
classes, percentiles and models. The input checker requires quantitative content;
the domain reviewer must verify the actual numbers, populations, conditions,
units and measurement semantics before approval.

| Objective key | Required numerical definition |
|---|---|
| `apiAvailability` | Successful eligible requests, denominator, observation window, exclusions and availability threshold. |
| `requestAdmissionDeadline` | Admission percentile/maximum and timing start/end. |
| `reconciliationSchedulingDeadline` | Queue/scheduling delay under normal and approved degraded conditions. |
| `eligibleIssuanceLatency` | Issuance percentile/maximum by issuer and certificate class; define external dependency delays. |
| `consumerCertificateAvailability` | Consumer-observed availability, validation method and observation window. |
| `renewalSafetyByCertificateClass` | Lifetime, renewal start, latest safe adoption and required remaining validity for each class. |
| `maximumInvalidationDelay` | Revocation/distrust/exposure bound and consumer enforcement measurement. |
| `vipFailoverBudget` | Client-observed interruption budget for VIP or approved external-LB topology. |
| `componentRecoveryBudget` | Per-component/dependency detection, restart and convergence deadlines. |
| `recoveryTimeObjective` | Restore start/end and maximum time to validated consumer service. |
| `recoveryPointObjective` | Maximum accepted data loss and source/recovery timestamp method. |
| `alertDeliveryDeadline` | Signal-to-receipt deadline at an authorized technical notification destination. |
| `acknowledgementDeadline` | Delivered alert to accountable responder acknowledgement. |
| `escalationDeadline` | Unacknowledged/ongoing incident to the next accountable authority. |
| `managedCertificateEstate` | Counts by class, issuer, tenant, lifetime and consumer type. |
| `sustainedRequestRate` | Rates, distributions, duration and workload composition. |
| `renewalBurstModel` | Overlap population/rate, duration and safety margin. |
| `providerQuotaModel` | Approved CA/DNS/backend limits, reserved capacity and retry budgets. |
| `resourceAndHeadroomLimits` | CPU, memory, storage, network and degraded-mode reserve limits. |
| `soakAndLoadDuration` | Representative load/endurance duration, renewal/backup overlap and success thresholds. |
| `operationalObservationWindow` | Launch or existing-service observation period and required incident/telemetry coverage. |
| `maintenanceWindow` | Start/end, interruption budget and permitted change scope. |
| `patchAndRotationDeadlines` | Response deadlines by severity and key/credential class. |
| `evidenceRetention` | Original/sanitized evidence retention, accessibility and deletion/expiry rules. |

## Approval checklist before staging execution

- [ ] Service owner approves the frozen claim, exact subject, full support and dependency matrix, exclusions, trust boundaries and named authorities.
- [ ] Domain owners approve all 24 objectives and measurement procedures. Record numeric fault/load bounds, permitted targets, public-provider quotas, stop conditions and cleanup/recovery actions.
- [ ] Review all eight applicability decisions: PKI-10, PKI-13, SEC-11, DR-03, DR-09, TST-06, OBS-06 and OBS-08. Keep a rationale and authenticated review for active and inactive decisions. All controls remain required for 100 points.
- [ ] Assign owners, implementers, verifiers, independent reviewers and procedures for all 100 controls. Resolve canonical identities and deputies in the real authority system.
- [ ] Platform/security owners authorize exact controller, hosts, transport, privilege, secret-system access and network boundaries. Recovery owner confirms independently accessible backups, keys/bootstrap material and replacement infrastructure.
- [ ] Operations/change authority authorizes the exact window and runs before execution. Explicitly authorize notification destinations and message content before a delivery/responder exercise.
- [ ] Independent assurance owner qualifies the controlled backend and evidence store, including revoked/expired/wrong-purpose/wrong-payload/self-review denial and unavailable-backend behavior. Preserve original evidence with restricted access and review sanitized derivatives against it.
- [ ] Run `staging-check` with the exact configuration and inventory; resolve every issue, then bind the reviewed package and scope digests to the authenticated execution authorization.

## Execute and retain the control evidence

Use the 100 entries in `control-plan.json` to prepare actual procedures. Each
procedure must state prerequisites, authorized targets, commands or reviewed
manual actions, expected positive and adverse outcomes, objective measurements,
stop/rollback/cleanup, original evidence locations and the responsible verifier.
Scope and execution approvals precede observation. Keep failed runs and their
corrective reruns in controlled history.

| Qualification phase | Required results and control coverage |
|---|---|
| Baseline and deployment | Inspect prerequisites/targeting, deploy the exact candidate, repeat convergence, exercise drift/partial failure, and qualify selected sequential upgrades and rollback: GOV, CFG, TST. |
| PKI and isolation | Exercise allowed/denied requests, custody, actual consumer delivery/renewal/adoption, rotation/invalidation/trust rollover, access controls, tenant/network boundaries and abuse limits: PKI, SEC. |
| Availability and recovery | Run authorized node/process/dependency/partition/maintenance cases with client measurements; retrieve off-host backups and restore onto isolated replacements with bootstrap/key continuity and measured RTO/RPO: HA, DR. |
| Signals and responders | Test normal/adverse/missing telemetry, lifetime-aware alerts, approved delivery destinations, acknowledgement/escalation and deputy handoff: OBS, OPS. |
| Capacity and endurance | Apply the approved sustained/degraded workload and renewal burst, measure backlog recovery, quotas, headroom and soak/growth budgets: PERF. |
| Release and assurance | Reconcile the complete resolved inventory/licenses/SBOM and artifact trust, execute final candidate security/signing/consumer checks, retain protected evidence, and independently reproduce the assessment: SUP, EVD. |

Record each run in `assessment.verificationRuns`, evidence in `assessment.evidence`,
and every acceptance observation in the matching control's `criteriaResults`.
Use the schema's exact IDs, timestamps, subject bindings and references. Supply
the authenticated `run:RUN_ID` decision before its start and
`evidence:EVIDENCE_ID` review after collection. The
[evaluator contract](enterprise-evaluator.md#binding-contract) defines all
purpose names, digest bindings, freshness and chronology rules.

## Approval checklist before release

- [ ] Review the six legacy-file replacements/retirements and the old staging workflow's retirement. The offline input commands support preparation; actual staging execution must be supplied by the approved runner/runbook for the frozen environment. Input inspection is not counted as live staging evidence.
- [ ] Complete exact-candidate CI, compatibility, security disposition and protected original evidence retention. Reconcile OS repositories, transitive chart/container/runtime inputs, licenses, publisher trust and support acceptance.
- [ ] Establish an eligible independent/code-owner/last-push review path and the approved verified signing/landing process required by protected main. A changed commit, artifact or profile receives the applicable requalification.
- [ ] Close all unmet criteria and affected findings/exceptions with evidence; a waiver cannot supply an assured point. Review change-impact and freshness for every evidence reuse.
- [ ] Independently accept each control at cumulative level 4, then all twelve category gates and activated conditional gates. Obtain six authenticated release-role approvals after control assurance review.
- [ ] Finalize the immutable subject and final assessment revision, rebind the review digest, qualify the real assurance backend, and independently reproduce the evaluator result: 100 current assured controls, exactly 100/100, passing gates and authorized production decision.

Run `certweaver enterprise-score assessment.json --json` to inspect the current
record. The standard CLI deliberately has no organization-specific authority
backend and cannot turn approval locators into accepted points. The controlled
integration must supply that backend and its independent qualification.
