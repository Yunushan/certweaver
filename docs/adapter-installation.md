# Installation paths and qualification

CertWeaver has 20 adapter entries. The table below describes this repository's
installation contracts. An implemented path is not evidence that an upstream
version, operating system, PKI policy or HA design has passed live qualification.
Use the registry and strict `doctor` validation for the selected profile. None of
these paths grants production approval.

`standalone` and `raw` use the same host installer. Raw means that CertWeaver does
not create Kubernetes; it does not guarantee a source-built or container-free
application. Linux package tasks target DNF-based hosts, with Rocky Linux 9 as
the intended staging baseline. Debian/Ubuntu target hosts are not implemented.
The Linux controller can run on another supported Ansible control environment.
Install its source-bound `dev` profile with `scripts/install-python-deps.py` and
the pinned Ansible collections. This includes the default Windows WinRM/NTLM
controller libraries; see [controller transport prerequisites](python-dependencies.md).

| Adapter | Single host / raw | Multiple hosts | Docker | K3s / RKE2 / existing Kubernetes |
|---|---|---|---|---|
| cert-manager | Kubernetes required | Controller replicas in reviewed values | — | Verified chart through core add-ons |
| step-ca | Verified binary + reviewed config + systemd; optional Podman Quadlet | Per-host config and external/shared CA design | Digest-bound Compose | Verified chart by default; explicit host or Podman backend also available |
| OpenBao PKI | Verified archive + reviewed config + systemd; optional Podman Quadlet | Reviewed storage, join and unseal configuration per host | Digest-bound Compose; dev mode rejected | Verified chart by default; explicit host or Podman backend also available |
| acme.sh | Verified Git commit and CLI installation | Host client on each selected host | Digest-bound Compose CLI | Host client on selected Linux nodes |
| Certbot | DNF packages and optional renewal timer | Host client on each selected host | Digest-bound Compose CLI | Host client on selected Linux nodes |
| EJBCA Community | Digest-bound Podman Quadlet; **not a bare JVM install** | Host instances with reviewed external database and cluster settings | Digest-bound Compose | Verified Community OCI chart, protected values, primary/init/sidecar image checks |
| lego | Verified release archive and CLI | Host client on each selected host | Digest-bound Compose CLI | Host client on selected Linux nodes |
| Dogtag PKI | DNF packages; explicit protected `pkispawn` configuration for CA creation | Separate per-host instance/clone configurations; no automatic CA cloning | Digest-bound Compose | — |
| FreeIPA + certmonger | Primary, pre-enrolled replica or keytab-enrolled client | Explicit roles and host settings; replica authorization required | — | — |
| CFSSL | Three verified CLI executables | CLI on each selected host; operator-managed API policy/service | Digest-bound Compose CLI | — |
| trust-manager | Kubernetes required | Reviewed controller and bundle configuration | — | Verified chart through core add-ons |
| cert-manager CSI Driver | Kubernetes required | DaemonSet/workload placement in reviewed values | — | Verified chart through core add-ons |
| dehydrated | Verified Git commit and CLI | Host client on each selected host | Digest-bound Compose CLI | Host client on selected Linux nodes |
| win-acme | Native Windows/WinRM, verified versioned archive | Same Windows playbook across selected Windows hosts | — | — |
| Posh-ACME | Native Windows/WinRM, exact module version | Same Windows playbook across selected Windows hosts | — | — |
| SPIRE | Verified release; explicit server/agent components, configs and systemd | Per-host server/agent placement; shared datastore and attestation supplied by operator | Separate digest-bound server/agent Compose services | Verified CRD and application charts |
| Boulder | Acknowledged lab-only upstream Compose from a verified Git commit | Reviewed upstream lab topology only | Guarded upstream lab Compose | — |
| Caddy | Verified binary + reviewed config + systemd | Per-host config/storage and ACME coordination required | Digest-bound Compose | Host service on selected Linux nodes |
| Traefik | Verified binary + reviewed config + systemd | Per-host config/storage; multiple ACME writers require an independently supported design | Digest-bound Compose | Verified chart; ACME resolver remains explicit |
| Lemur | Acknowledged legacy source build, hash-locked Python/npm dependencies, config and systemd | Shared external database; migrations on one nominated host | Digest-bound Compose | — |

“—” is deliberately excluded from the current CertWeaver contract, even when an
upstream project has other deployment recipes. Kubernetes-only adapters cannot
run as ordinary Docker containers without Kubernetes. Windows adapters use
`mode: windows`; Linux modes do not emulate Windows. FreeIPA's privileged
container/system integration is not represented by the restricted Compose
contract. Boulder remains prohibited in production and Lemur remains opt-in.

Managed K3s/RKE2 retain their existing production minimum of three server nodes.
A one-node nonproduction cluster is a development topology, not production HA.
Installing on several hosts does not configure application HA automatically.

## Host selection and overrides

`spec.platform.nodes` supplies the target hosts in every mode. For each adapter,
`options.<slug>.nodes` can select a nonempty subset by node name. All supplied
names and host override names must exist. `options.<slug>.hosts.<node-name>`
shallowly overrides that host's adapter options; nested objects such as
`container` are replaced in full. Keep `nodes` at the adapter level. Acquisition
preflight validates every selected host's effective backend and pins.

Native/Docker installers run serially across selected hosts. Kubernetes charts
run once on the first node/controller; include that node in any chart adapter's
selection. Host clients in Kubernetes modes are installed on those Linux hosts,
not in pods. `startServices: false` prepares service assets and pulls approved
images but does not activate the new managed native/Compose services. Helm
installation and some upstream installers can activate workloads as part of an
authorized deployment; that flag is not a general deployment dry-run. Use
Ansible check mode for planning, and retain its existing verification limits.

`options.<slug>.files` copies reviewed controller files to the selected host's
`/etc/certweaver/<slug>/<name>` with private permissions and suppressed content
diffs. Chart and host-container inputs are staged before adapter execution,
including step-ca/OpenBao chart values and Podman inputs, EJBCA, and Kubernetes
SPIRE/Traefik values. Set `valuesFile` to that exact target path when using a
staged values file; staging does not rewrite the chart's values path. Native
services stage their files after creating their service identity so the runtime
group can read approved inputs. Docker Compose stages its own inputs, and Lemur
stages runtime files after its isolated build. This routing does not generate
CA keys, initialize issuers or supply missing application policy.

## Docker profile inputs

Docker mode now uses the operator-provisioned Docker Engine and Compose v2
plugin instead of falling through to host binary/package installation. The
installer verifies `docker compose version`, renders a private managed file,
runs `config --quiet` and `pull`, and activates server services only when
requested. It does not install an unreviewed Docker repository or engine.

Each supported adapter needs `options.<slug>.container` containing:

- `image`: fully qualified `registry/repository@sha256:<64 lowercase hex>`;
  no mutable tags or short repository names;
- `command` and/or `entrypoint`: lists of literal arguments; server applications
  require an explicit command;
- optional `ports`, absolute target `envFiles`, numeric `user`, and bind `mounts`
  with absolute `source`/`target` and boolean `readOnly` (defaults to true);
- an explicit `healthcheck` for server activation: `test: [CMD, ...]`, positive
  seconds such as `interval: 10s`, `timeout: 5s`, and `retries` from 1 to 100.

No automatic host-path creation is allowed for binds. Dollar signs are escaped
for Compose so it preserves the profile's literal values without reading
controller environment variables. Commands and secrets are not printed in
Ansible diffs. This is a managed operator configuration, not an arbitrary
Compose-file import. Unsupported keys fail validation.

SPIRE can use `containers.server` and `containers.agent`, each with the above
runtime object, instead of singular `container`. Only SPIRE permits explicit
`hostPID: true`; use it only for an attestation profile that needs host process
visibility. Socket mounts, trust domain, registration, datastore and node
attestation remain reviewed inputs. OpenBao adds `IPC_LOCK` and rejects direct
development-server flags; the reviewed config must also disable development
behavior and define TLS, storage and audit controls.

The installer creates `certweaver-<slug>` CLI launchers (and SPIRE component
launchers). Client adapters are invoked with these launchers using an explicitly
reviewed command/scheduler. Pulling a CLI image does not issue certificates or
create a renewal schedule. The older `docker/compose.yml` remains a separate
manual example and is not the generated deployment contract.

## Private inputs and native services

Optional `options.<slug>.files` entries copy absolute controller `source` files
to `/etc/certweaver/<slug>/<name>`. Names must be flat; `config`, `config.py`, `config.yaml`, `config.hcl` and
`activated.json` are reserved. Modes are limited to `0400`, `0600`, `0640`.
Owner is root; native runtime groups receive only the access needed to read
their inputs. Supply full absolute paths on a Linux Ansible controller. Do not
put credential values or private keys into committed profiles.

Native step-ca, OpenBao, Caddy and Traefik accept `serviceConfigFile`, copied to
their managed private configuration path (`config.yaml` for Traefik YAML,
`config.hcl` for OpenBao HCL, `config` for step-ca JSON and Caddy). Caddy uses
JSON by default; select `configAdapter: caddyfile` for Caddyfile syntax.
Activation requires that reviewed file;
step-ca also needs target `passwordFile`. CA keys, chains, database endpoints,
DNS credentials, ACLs, TLS policy and bind/listen ports come from reviewed
configuration. The service witness detects binary/config/unit changes and
restarts on a changed selection. Native OpenBao additionally requires an HTTPS
`binaryUrl`, exact `versions.openbao` and reviewed `checksums.openbao`; it never
generates or exposes unseal/root material.

Native SPIRE requires `versions.spire`, `checksums.spire`, `components: [server]`,
`[agent]` or both, and absolute controller `serverConfigFile`/`agentConfigFile`
paths for the selected components. The server runs as `spire`, the agent as root
where host attestation requires it. Configured data directories and workload
socket permissions must agree with the managed service identities. No default
join token or production registration entries are fabricated.

FreeIPA primary creation needs `role: server`, `configureServer: true`, realm,
domain, hostname and target `directoryManagerPasswordFile`/`adminPasswordFile`.
Passwords are regular root-owned `0400`/`0600` files, 8–4096 bytes, single line.
The primary installer uses recognized interactive prompts with `pexpect`, not
password command-line arguments. If overriding packages, retain `python3-pexpect`
for the target's Ansible Python. Unknown prompts fail by timeout; validate the
selected FreeIPA version's prompts in staging. Inline password options no
longer satisfy preflight. Replica promotion requires protected pre-enrolled
`/etc/krb5.keytab` and authorization of the host in `ipaservers`. Client
enrollment needs realm/domain/server and a separate protected target
`keytabFile`; it cannot reuse `/etc/krb5.keytab` as its enrollment source.
DNS, forward/reverse records, time synchronization and replica health are
prerequisites, not automatically approved by successful package installation.

Dogtag `configure: true` requires an existing reviewed `pkispawnConfig` and
explicit activation. Clone, KRA and OCSP instance policies require separate
reviewed upstream configuration; the current automatic instance command is CA.
CFSSL installs the toolkit; expose its API only through an independently
reviewed service, authentication, policy and storage design.

## Lemur build and EJBCA chart inputs

Native Lemur needs immutable `lemur_ref`, `requirementsFile` and `configFile`.
The Python lock must contain exact versions and SHA-256 hashes, including pip,
setuptools and wheel. Includes, installer options, direct URLs and unhashed
dependencies are rejected. The reviewed source must contain `package-lock.json`.
Provision the selected revision's supported Node.js stream before installation
and verify its compatibility; the DNF defaults are not a support guarantee.
Builds use Python 3.12, an isolated unprivileged builder, `npm ci --ignore-scripts`,
explicit gulp targets, and no dependency fetching during local source install.
The final tree is frozen to root ownership using descriptor-relative operations
that reject escaping links, hard-linked regular files and special files. The
runtime user cannot modify code and the builder cannot read runtime secrets.
The completion witness is outside the builder-controlled tree.

Lemur needs a separately prepared least-privilege PostgreSQL database, encryption
keys, issuers/plugins, TLS proxy, authentication, logging and backups. Database
migrations require `runMigrations: true` plus a named `migrationHost`; they are
not run on every replica. Serial installation alone does not provide a database
migration lock across independent deployment invocations. Coordinate maintenance
and prevent concurrent deployment runs.

EJBCA in Kubernetes needs exact `versions.ejbca_chart`, SHA-256
`checksums.ejbca_chart`, image digest `versions.ejbca_image`, and a protected
root-owned target `valuesFile` (optionally staged using `files`). It uses the
current official Community OCI chart, local verified archive, a hash-bound
values snapshot and explicit primary image overrides. Rendered init/sidecar
images must also carry qualified digests; replace their chart defaults in your
values. EJBCA's external database, session replication secrets, crypto tokens,
HSM, bootstrap administration and CA ceremony require reviewed inputs. Template
inspection does not prove admission mutations or runtime image identity.

## Remaining live acceptance checks

Record results against an immutable candidate, exact OS/package versions,
chart/archive/image digests, topology and configuration hashes. Retain redacted
logs, certificates, timestamps, responsible owner and independent review.

| Scope | Required live checks |
|---|---|
| Every supported adapter/profile | Clean install; unchanged rerun; approved version/config update; failed-download/pull and partial-install recovery; reboot persistence; uninstall/rollback plan; SELinux enforcing; least-privilege file/network access; supported upstream/license/SBOM review |
| Raw/native Rocky Linux 9 | Enabled repositories and package versions; Python/Node compatibility; actual systemd startup/readiness/restart witness; service identity can read required config and cannot modify code/keys; host firewall and time synchronization |
| Docker single/multiple hosts | Engine/Compose versions; real digest resolution on each architecture; mount ownership/SELinux labels; CLI arguments and exit status; healthcheck succeeds/fails correctly; image change reconciliation; persistent state; reboot and container replacement |
| K3s / RKE2 / existing Kubernetes | Actual chart metadata/templates/CRDs; admission policies and mutated images; node/pod identity; workloads ready; network policy, RBAC, Secrets/KMS, storage and backup; rolling update/drain; failover and quorum under node/network loss; one-node development versus three-node production topology |
| ACME clients, Caddy, Traefik | Staging CA account registration; HTTP-01/DNS-01 challenge and least-privilege DNS access; SAN/wildcard and denied-name policy; renewal under shortened lifetime; safe service reload; failed-renewal alert; no competing writers or account/storage corruption |
| step-ca / OpenBao / EJBCA / Dogtag / FreeIPA / CFSSL | Offline/online CA ceremony and protected keys; approved algorithms/lifetimes/SAN/EKU; denied unauthorized issuance; enrollment and renewal; revocation/CRL/OCSP; audit integrity; backup/restore and key recovery; explicit shared state/replication/fencing; HSM checks when selected |
| FreeIPA specifically | Primary interactive prompt compatibility; no secret arguments/logs; DNS and NTP; client keytab enrollment; authorized replica CA promotion; replication, certmonger renewal and failed-renewal handling |
| SPIRE | Server/agent attestation; workload selectors; SVID issuance/rotation and denied identity; socket permissions; trust bundle rotation/federation; shared datastore and server/agent failure recovery |
| trust-manager / CSI Driver | Bundle propagation and trust removal; workload mount, rotation and restart; node drain; denied unauthorized requests; approver-policy enforcement |
| Lemur | Real selected upstream Python/npm build; frontend and web health; auth and authorization; issuer plugins; actual database migrations; inventory/import/renewal workflow; encryption-key recovery; concurrent replica behavior; maintenance-risk acceptance |
| Windows adapters | Real certificate-validated WinRM; verified archive/module acquisition; IIS/certificate store/private-key ACLs; scheduled renewal and bindings/reload; update/reboot; failure alerts; unsupported TLS/identity rejected |
| Boulder | Disposable isolated lab only; selected upstream dependency images reviewed; ACME integration and reset; proof no production exposure or production CA credentials |

The local unit and synthetic Ansible fixtures exercise input validation,
placement, byte identity, installation decisions, repeat runs and protected
application ownership. They deliberately do not contact staging hosts, run an
application container, initialize a CA, join a domain or approve production.

Upstream contracts: [SPIRE installation](https://spiffe.io/docs/latest/deploying/install-server/),
[Lemur quickstart](https://lemur.readthedocs.io/en/latest/quickstart/index.html),
[EJBCA Kubernetes deployment](https://docs.keyfactor.com/container/latest/ejbca/deploy-ca-in-kubernetes),
[FreeIPA replica setup](https://www.freeipa.org/page/V4/Replica_Setup),
[OpenBao installation](https://openbao.org/docs/install/).
