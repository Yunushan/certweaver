# Production operations

## Managed operator API endpoint

Managed RKE2/K3s add-on preparation reads the cluster selected by the distribution
kubeconfig's current context and sets only that cluster's server to the configured
IPv4 VIP and API front port. It uses `kubectl config set-cluster`, which merges
the supplied server field into the selected cluster entry; YAML quoting, other
clusters and nonstandard original ports do not determine whether it succeeds.
See the [upstream command contract](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_set-cluster/).

Preparation requires a root-owned regular distribution file with root group,
one hard link, mode `0600` or `0640`, and a nonzero size no greater than 1 MiB.
An existing operator destination must be a root-owned regular file with one
hard link and mode `0600`, distinct from the distribution source by device/inode.
Symlink source/destination files are rejected. The
role creates private temporary staging, copies the source there with mode
`0600`, inspects the selected context without raw credential output, and rejects
disabled TLS verification or a configured proxy. It validates the prepared
endpoint and preserves selected trust, credential references and context before
publishing the complete file atomically as root-owned mode `0600`. An explicit
TLS server-name override is passed back to `set-cluster` because changing
`--server` alone clears that field in the pinned client. The override remains
subject to normal certificate validation; it never enables a TLS bypass.

The distribution source is preserved. Invalid input or failed staged validation
leaves a previously published operator file intact and stops progression to
add-ons/export. Private staging is removed on success and failure. Internal
staging work does not count as a deployment change; publication changes only
when the resulting file differs, including credential rotation. Enabled Ansible
debug logging is rejected. Check mode validates the endpoint inputs and skips
credential preparation/publication. This section describes managed profiles;
an existing-cluster profile retains its explicitly supplied endpoint.

The repeatable local fixture uses the pinned real client, synthetic credentials,
and a localhost HTTPS API. It exercises quoted endpoints, multiple contexts,
repeat runs, rotation, rejected preparation, untrusted CA, incorrect TLS server
name, and denied authentication. It does not establish actual VIP routing,
cluster identity, remote SSH/become or issuer authorization. Those properties
still require the approved staging profile.

## Optional administrative kubeconfig export

`spec.platform.fetchKubeconfig: true` opts into transferring the complete
administrative kubeconfig for `rke2-ha`, `k3s-ha` or `existing-kubernetes`.
Treat this file as an administrative credential. The transfer does not redact
its certificates, keys or tokens. Export stays disabled by default, and other
deployment modes reject an enabled export setting.

The default controller destination is
`~/.config/certweaver/<metadata.name>/kubeconfig`. To select another destination,
set `spec.platform.kubeconfigOutput` to a literal absolute POSIX file path or a
path beginning with `~/`. The destination is relative to the actual controller
user's home when using `~/`, including when the managed host uses privilege
escalation. Controller operations explicitly use a local connection with
`become: false`, even if inventory defines a remote host named `localhost`.
Use a POSIX controller filesystem that enforces ownership and permissions;
native Windows paths and permission-emulating shared mounts are unsupported.

Before add-on changes, a read-only preflight rejects an unsafe existing path
and enabled Ansible debug logging. Existing ancestors must be root-owned or
controller-owned and protected from group/world writes. Root-owned sticky
`/tmp` and `/var/tmp` are the only writable-ancestor exceptions. Symlink
components are rejected. The final directory must belong to the controller
user with mode `0700`; an existing destination must be one regular file owned
by that user, have one hard link and mode `0600`, and be no larger than 1 MiB.
Preflight creates nothing. Export creates missing directories with mode `0700`
but does not repair permissions or ownership on existing paths. Choose or
prepare a private directory when preflight fails.

The source must be a nonempty, root-owned regular file with mode `0600`, one
hard link and a size no greater than 1 MiB. The task checks the transferred
bytes against its inspected SHA-256, uses Ansible's atomic copy with unsafe
writes and backups disabled, then verifies the resulting controller file's
ownership, mode and digest. A changed source replaces a valid existing export;
an unchanged source is idempotent. A digest mismatch stops the export rather
than accepting bytes from a source that changed during transfer. Credential
tasks disable logging and diff output, and clear the registered transfer value
afterward. These controls do not provide secure memory erasure or protect
against an administrator or another process running as the controller user.
Check mode validates the destination without creating directories, reading the
source or exporting credentials.

This replaces the previous relative `.certweaver/kubeconfig` destination.
Review any file left there under the owner's credential retention policy;
this change neither relocates nor removes old exports. If an old credential
was accessible beyond its intended administrators, investigate and rotate it
under the issuer/cluster response procedure. Local fixtures use synthetic
credentials only. Qualification of actual remote SSH and privilege escalation,
credential rotation, cluster identity, and operator access still belongs to
the approved staging profile.

## Managed distribution version transitions

Managed RKE2/K3s playbooks run the read-only `cluster_version` role on every
server before platform preparation. The upgrade playbook additionally requires
an existing installation on every server. Each server role repeats its own
version gate before configuration or installer changes, so a changed observation
cannot rely only on the earlier fleet result.

The selected version must be a canonical stable Kubernetes 1.x release with
the matching distribution revision, such as `v1.33.12+rke2r2` or
`v1.33.12+k3s2`. These examples illustrate syntax and do not approve that release
for production. Channels, ranges, prereleases, cross-distribution suffixes,
leading-zero components and trailing whitespace are rejected before mutation.
Portable nonproduction templates report the missing/invalid selection as a
warning; deployment and production validation reject it.

The role inspects the standard binary locations without following links. RKE2
allows either its tarball path `/usr/local/bin/rke2` or RPM path `/usr/bin/rke2`;
both present is an ambiguity to resolve before proceeding. K3s uses
`/usr/local/bin/k3s`. An observed executable must be regular, root-owned,
executable, bounded in size and protected from group/world writes. Its
`--version` command has a 30-second task timeout, runs read-only even in check
mode, and must return one recognizable distribution identity on its first line.
Unknown, conflicting or failed version responses stop progression.

Version comparisons use integer major/minor/patch/revision fields, including
distribution revisions such as `rke2r9` to `rke2r10`. Equal versions skip the
installer; increasing patch/revision versions and a single next-minor step are
allowed by the numeric gate. Patch/revision downgrades, minor downgrades and
skipped minors are rejected. An upgrade invocation never treats a missing
binary as permission to bootstrap that server. Check mode reports the decision
without running an installer.

This is a required transition boundary, not release support or compatibility
approval. The selected releases, API/component skew, release-specific migration
notes, operating-system support, workload evacuation and recovery checkpoints
still require profile-specific review and staging qualification. The installed
version string does not authenticate binary contents or establish running
cluster identity; post-reconciliation API/node health is a separate gate.

The upstream guides warn against skipping intermediate minor versions:
[RKE2 manual upgrades](https://docs.rke2.io/upgrades/manual) and
[K3s manual upgrades](https://docs.k3s.io/upgrades/manual). Ordinary reconciliation
has no downgrade override. A rollback needs a separately approved and qualified
recovery procedure; this gate does not implement one.

## Managed cluster reconciliation and upgrade health

Every play in the managed RKE2/K3s deploy and upgrade playbooks explicitly uses
`strategy: ansible.builtin.linear` with `any_errors_fatal: true`. This preserves
the fleet stop boundary when the controller environment selects `free` or
`host_pinned`: a failed preflight or fleet health gate prevents later phases.
The built-in strategy runs tasks in lockstep within the configured serial batch;
see [Ansible's strategy contract](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/linear_strategy.html)
and [fatal error handling](https://docs.ansible.com/projects/ansible-core/2.19/playbook_guide/playbooks_error_handling.html#aborting-on-the-first-error-any-errors-fatal).
The repeatable strategy fixture preserves source play targets, serial settings
and failure policy while replacing service changes with local markers. It
qualifies this stop boundary under the three controller strategies, with healthy,
preflight-failure and health-failure cases. Actual remote privilege escalation,
host services, quorum, availability budgets and recovery still require staging.

RKE2 and K3s server reconciliation now finishes with the `cluster_health` role
after pending restarts and TCP connectivity checks. The role uses the
distribution's client and root kubeconfig, explicitly targets the local HTTPS
API, and preserves TLS validation and authentication. It requires `/readyz` to
return `ok` and `/version` to report the exact expected `gitVersion`, including
the distribution revision. It then queries the node with the exact inventory
name. A successful
node response must identify a v1 Node, have no deletion timestamp, contain
exactly one Ready condition with status True, and report the exact selected
distribution kubelet version. An open API socket alone cannot pass.

Before network requests, the client reads the selected minified context without
exporting raw credentials. The role rejects disabled TLS verification and a
configured proxy, which could otherwise redirect the local check. Context output
and its validation are protected with `no_log`. This is a client-configuration
guard; trusted CA selection and actual cluster identity still require the
approved deployment profile and independent qualification.

The requests have explicit timeouts and bounded retries. Defaults are a
10-second request timeout, 60 retries and a five-second retry delay. Each
selected node has its own bound; this is not a client-availability SLO. Check
mode validates inputs but sends no health requests and provides no live proof.

After all-server version preflight, `playbooks/upgrade.yml` checks each server's
own authenticated local API and own Node before any installer role runs. The
`pre-upgrade` phase binds both API and kubelet versions to the binary identity
observed by `cluster_version` on that host. A Ready node or open API on the
bootstrap server cannot substitute for a peer's local readiness and version.
An older healthy installation may therefore pass preflight for a later selected
release, while installed/running drift fails before any installer runs.

Normal managed deployment also runs this fleet check before platform changes
when an existing server needs a version-changing installer. Host preparation is
now inside the bootstrap and joiner server plays, each with `serial: 1`, rather
than a separate all-server preparation phase. On each selected host, the play
reobserves its installed version and rechecks changing-server runtime before
running `common`, optional HAProxy/Keepalived and the server role. The bootstrap
host completes this sequence before joiners start; each joiner completes it
before the next joiner is prepared. A failure halts later hosts and add-ons.

Pending platform and server handlers are flushed before the final authenticated
health gate. This uses Ansible's [serial batch semantics](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_strategies.html#setting-the-batch-size-with-serial)
and [handler flush semantics](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_handlers.html#controlling-when-handlers-run).
The boundary is one complete host reconciliation per batch, including its
preparation, handler execution and final API/Node readiness. The repeatable
fixture checks this ordering across a bootstrap host and two joiners with real
TLS/authenticated client calls and marker-only preparation/restart operations.
Version observations in that health fixture remain stubs; the separate version
fixture qualifies actual binary observations. This is local control-flow proof,
not a live quorum, workload-availability or rolling-upgrade qualification.
Each server role
repeats the running-identity check immediately after observing its binary and
before configuration/installer changes. Fresh installs skip that early check;
they must pass the final check after installation. Same-version reconciliation
retains its final check and can start an otherwise stopped service without
requiring an already-running API before doing so.

The final `post-reconcile` phase explicitly binds both API and Node versions to
the selected release. There is no phase that disables version comparison.
Check mode validates phase/version inputs but performs no HTTP requests or live
readiness verification. Reconciliation proceeds one server at a time; each server must report
the newly selected version before progression. Managed cluster plays use
`any_errors_fatal: true` so a health failure prevents later servers or add-on
reconciliation from advancing in that invocation.

These gates do not drain workloads, assess etcd member health, approve minor
version jumps, select a supported upgrade path, create a recovery checkpoint,
or implement rollback. Those remain release/profile-specific requirements.
An API-ready node is not proof of issuer health, certificate delivery, workload
availability, quorum safety or a successful recovery. Qualify those properties
in authorized staging with approved budgets and the enterprise framework.

The repeatable `scripts/check-cluster-health.py` fixture uses a checksum-pinned
real kubectl client with temporary localhost TLS/API responses and actual
Ansible role execution. Its upgrade scenarios retain the source play boundaries
and failure policy while replacing mutating installers/add-ons with observable
markers and temporary API-state controls. Version observation is stubbed in this health-only fixture and executed
by the separate `scripts/check-cluster-versions.py` fixture, which also exercises
the actual source installer condition and fleet rejection boundaries.
The client lock is only a fixture tool identity; it does not update or
approve the production Kubernetes baseline. GitHub/GitLab CI require the fixture,
but actual hosted execution remains a separate evidence obligation.

## Operating requirements

- Test rolling RKE2 and cert-manager upgrades in staging.
- Keep all versions pinned and review upstream security notices before changes.
- Wait for the configured release-age window before adopting routine upstream releases unless a security advisory requires faster action.
- Configure an encrypted, access-controlled S3-compatible destination for RKE2 snapshots. The deployment requires an ignored controller-side environment file containing the documented `etcd-s3-*` keys; keep the RKE2 token, CA databases/configuration, and unseal/recovery material in approved encrypted systems.
- Alert on certificate expiry, failed CertificateRequests, ACME Orders/Challenges, webhook errors, unavailable replicas, and snapshot failures.
- Exercise VIP failover and single-node loss at least quarterly.
- Verify restore procedures rather than only checking backup job success.
- Rotate DNS API credentials and minimize their zone permissions.
- Never share a public wildcard certificate/private key across unrelated trust zones unless a documented risk decision requires it.
- Keep a sanitized evidence bundle for every production change: config hash, pinned versions, CI run, deployment plan, smoke test output, failover test, and restore-test reference.
- Do not claim a deployment is 100/100 production ready until the scorecard in `docs/production-readiness.md` has live staging evidence.

Before deploying the default RKE2 profile, create `secrets/etcd-s3.env` outside Git with the S3 configuration accepted by RKE2, for example:

Production CLI and direct Ansible share the same read-only validator in
`certweaver.snapshot`. Install CertWeaver into the Python environment running
Ansible, as the documented development/bootstrap commands do; the role uses
`ansible_playbook_python` with an explicit local connection and `become: false`
for controller validation. A missing controller module or invalid file stops
execution before host changes. This is also an installed-package prerequisite;
copying the roles without their matching Python package is insufficient.

The RKE2 deploy and upgrade plays validate every server's production snapshot
inputs in the first play's pre-tasks, with `any_errors_fatal`. The standalone
RKE2 and add-on roles also validate before their changes. Production defaults
require scheduled snapshots, enabled S3 replication, a named configuration file
and disabled Ansible debug. Explicitly disabling snapshots/S3 does not skip the
policy. Nonproduction profiles must be declared deliberately; do not relabel a
production qualification to bypass its requirements. `always` tags keep this
preflight active under ordinary tag selection; an operator who explicitly skips
safety tags/tasks has not performed the required production procedure.

The bounded reader accepts a regular UTF-8 file of at most 1 MiB. Every raw
line must be at most 65,535 UTF-8 bytes before the LF delimiter, including any
first-line BOM and carriage-return bytes. The pinned client silently omits
overlong env-file entries while exiting successfully; the preflight rejects
them before staging. The input uses literal kubectl `key=value` entries with
valid, unique names. Bare keys cannot import environment values. Quotes,
trailing spaces and inline comments remain part of values. The transport
switches `etcd-s3-insecure` and `etcd-s3-skip-ssl-verify` must be omitted to keep
secure defaults or use a literal Go false value (`false`, `False`, `FALSE`, `0`,
`f` or `F`). No shell/dotenv expansion is performed.

Immediately before transfer, Ansible revalidates the source and retains only
its hashes and byte count. Copy uses Ansible's SHA-1 transfer checksum; staged
SHA-256 and size must additionally match before kubectl renders the Secret.
This rejects controller-file and same-size staged-file changes. Each invocation
allocates a distinct root-owned mode-0700 directory under `/run`; the input and
rendered Secret are root-owned mode-0600 files inside it. Cleanup removes only
that invocation's directory after success or failure. A cleared staging identity
prevents validation/allocation failures from cleaning a stale directory reference.
Logging and diffs remain suppressed. Check mode validates controller input but skips
credential staging, Secret rendering and application. Missing portable example
files still produce CLI validation warnings; actual deployment requires them.
See [RKE2's transport switches](https://docs.rke2.io/datastore/backup_restore#s3-compatible-object-store-support),
[kubectl env-file parsing](https://github.com/kubernetes/kubectl/blob/v0.36.5/pkg/cmd/util/env_file.go)
and [Go boolean parsing](https://pkg.go.dev/strconv#ParseBool).

Secret reconciliation first runs `kubectl diff --server-side` with the same
`certweaver` field manager used by apply. Exit zero skips apply; exit one applies
the observed difference; any other exit stops reconciliation. Only successful
apply reports a persistent change. Temporary staging and cleanup do not report
deployment changes. The standard `diff` utility is required; the managed common
package set includes `diffutils`. The task clears `KUBECTL_EXTERNAL_DIFF`, masks
Secret values, keeps comparison files/cache inside private staging, and sets
30-second API request timeouts. See [the upstream diff contract](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_diff/).

Private staging isolates file contents and cleanup between concurrent invocations.
It does not serialize writes to the same Kubernetes object or coordinate whole
deployments. Coordinate production changes under the approved operating procedure;
qualify actual field ownership, admission, conflicts and concurrent writers for
the frozen profile.

These checks establish input/transfer policy, not actual endpoint trust,
storage encryption, bucket permissions/retention, scheduled snapshot delivery
or successful recovery. Qualify those properties against the approved environment
and recovery objectives. Transfer fixtures use real client rendering and
marker-only publication. The reconciliation fixture additionally uses the real
client with an authenticated localhost HTTPS Secret model, including two actual
Ansible processes targeting separate synthetic Secret names with shared or
different input values. This model does not implement Kubernetes field ownership
or admission; neither fixture contacts an object store or a real cluster.

The additional real-API gate runs this same Ansible block against isolated
upstream Kubernetes API-server and etcd binaries matching the selected patch.
It exercises actual SSA ownership, field removal, immutable objects, RBAC and
admission rejection, and checks metadata audit for skipped persistent writes.
Its mutually authenticated loopback processes, synthetic identities/data,
ephemeral encryption key and controlled storage are local test infrastructure.
Production distribution identity/configuration, same-object writer governance,
key custody, remote privilege, issuer/workload integration and recovery still
need evidence from the approved staging profile. No worker nodes, scheduler or
kube-controller-manager participate in this gate.

```text
etcd-s3-endpoint=https://object-store.example.internal
etcd-s3-access-key=REDACTED
etcd-s3-secret-key=REDACTED
etcd-s3-bucket=certweaver-rke2-snapshots
etcd-s3-folder=production
etcd-s3-region=us-east-1
etcd-s3-retention=28
etcd-s3-skip-ssl-verify=false
etcd-s3-insecure=false
```

CertWeaver creates a `kube-system` Secret of type
`etcd.k3s.cattle.io/s3-config-secret`, references it from RKE2, and removes
the transient file from the bootstrap node after reconciliation. Install a
Prometheus Operator before enabling the supplied certificate alert rules.
Fresh-cluster examples leave `addons.monitoring.prometheusRules` false so the
initial deployment does not depend on a CRD that has not been installed.
After installing the operator, enable the flag, reconcile the add-ons, and
verify alert evaluation and delivery before production approval.

CertWeaver currently installs the certificate control-plane components without
provisioning an issuer. Keep `addons.issuers.*.enabled` false, review and adapt
the manifests under `kubernetes/issuers`, and apply the intended issuer with
your organization-specific solver or CA credentials after deployment. Validate
both an allowed request and a policy-denied request before recording issuance
evidence. Enabling a reserved issuer flag fails validation instead of silently
skipping issuer creation.

On SELinux-enabled hosts, the HAProxy role reads the
`haproxy_connect_any` setting and requires the host security owner to have
approved the prerequisite policy before starting the service. CertWeaver
does not change SELinux booleans or enforcement. The distribution guidance
for RHEL 9 uses `haproxy_connect_any`, which permits HAProxy network access
across configured TCP ports and broadens its permissions; obtain the host
owner's approval before changing it. See
[Red Hat's HAProxy guidance](https://docs.redhat.com/en/documentation/red_hat_satellite/6.18/html/configuring_capsules_with_a_load_balancer/installing-and-configuring-the-load-balancer).
Capture the approved policy decision and AVC-free service verification in
the host-hardening evidence. A custom narrower policy needs its own reviewed
integration because the current prerequisite check expects that boolean on.

Before invoking Ansible, `certweaver deploy` requires the token, Keepalived
authentication file, and enabled RKE2 S3 configuration file to exist on the
controller. Paths in the deployment YAML resolve relative to that YAML file.
`certweaver validate` can still validate portable examples before secrets are
created; `certweaver doctor` reports missing files as failed prerequisites.

Generate each evidence bundle into a new, empty directory. Run its
`live-checks.sh` from an authorized staging controller with the intended
`KUBECONFIG`, and review and sanitize the collected output. Complete
`review.json` only after the failover, restore, issuance, trust, network,
hardening, secret management, upgrade, and incident controls have been checked.
Then run `certweaver score -c certweaver.yml --evidence DIRECTORY` as a release
gate. Recollect and review evidence after configuration or implementation
changes, or when its 30-day validity window expires. See
[the review instructions](production-readiness.md#completing-and-checking-a-review).

## Incident ownership and evidence

Before production approval, record the platform on-call, PKI authority owner,
incident commander, backup custodian, escalation contacts, and recovery-time
and recovery-point objectives in the organization's restricted operations
system. Record its reference in the reviewed evidence without copying private
contact details. During an incident, capture timestamps, affected serial
numbers and trust domains, change references, and verification results. Keep
private keys and credential values out of the incident log.

### Suspected CA key compromise

1. Declare an incident and identify which CA key, issuer, and dependent trust
   domains are affected. Preserve access and issuance audit logs.
2. Stop unauthorized issuance using the CA's access controls and the affected
   issuer path. Revoke compromised credentials and restrict access to the key
   store. The PKI authority owner decides whether the CA remains trusted.
3. Generate replacement key material in the approved key store, perform the
   required CA ceremony, and publish replacement trust through a reviewed
   trust-manager Bundle change. Verify distribution in each relying system.
4. Reissue affected workloads with new private keys and confirm the served
   certificate chains. Follow the CA's revocation process for affected
   certificates and publish updated CRL/OCSP information where applicable.
5. Remove compromised trust after the migration decision, test clients that
   should now reject it, and record any systems requiring separate trust
   updates. Close the incident only after the PKI authority owner's review.

### Leaf certificate or key compromise

Identify the issuing CA, certificate serial, affected endpoints, and owner.
Use that CA's authenticated revocation interface and confirm its revocation
status using the validation mechanism supported by the relying clients.
For cert-manager-managed workloads, configure `spec.privateKey.rotationPolicy:
Always` and request reissuance with `cmctl renew NAME -n NAMESPACE`. Verify the
new serial, key rotation, Secret delivery, and certificate served by the
application before completing the response. Preserve the ACME account identity
needed for CA operations. See the upstream
[certificate rotation guidance](https://cert-manager.io/docs/usage/certificate/)
and [ACME account guidance](https://cert-manager.io/docs/configuration/acme/).

### Cluster recovery rehearsal

Rehearse on isolated staging hosts. Record the trusted snapshot identifier,
integrity check, matching backed-up server token, pinned RKE2 version, and
recovery objectives. Stop the server services, restore the selected snapshot
on one designated server with the upstream cluster-reset restore procedure,
then rebuild peer membership according to that procedure. For a local snapshot,
disable S3 for the restore invocation. S3 credentials held in a Kubernetes
Secret are unavailable while the API server is down; prepare the approved
out-of-cluster recovery configuration. Protect tokens in files rather than
incident command transcripts. Follow
[the RKE2 restore procedure](https://docs.rke2.io/datastore/backup_restore).

After recovery, verify all three nodes, etcd health, VIP access, issuance,
trust reconciliation, and new off-host snapshot success. Compare recovered
data with the expected recovery point and record elapsed recovery time.
Keep the successful rehearsal artifacts and the incident commander's sign-off.

### Credential rotation

Inventory consumers before rotating a credential. Provision its replacement
with the least necessary access, update the approved secret system and all
consumers, validate their behavior, then revoke the old credential and confirm
that it no longer authenticates. Cover DNS solver accounts, S3 backup access,
CA administrator credentials, ACME accounts, cluster join material, and
Keepalived authentication in the rehearsal. Use each upstream system's
supported rotation process for cluster or CA material; editing a controller
file alone does not establish a completed rotation. Record references and
verification results, never credential values.
