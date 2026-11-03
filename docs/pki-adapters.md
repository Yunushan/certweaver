# PKI adapter contract

Every adapter has:
- a unique registry entry;
- supported modes and targets;
- a maturity/risk classification;
- an Ansible task entry point;
- version and installation options;
- an upstream reference and license identifier;
- CI tests that ensure registry/task coverage.

`production` means reasonable for production when correctly designed and supported upstream. `advanced` means significant PKI expertise or additional architecture is expected. `lab-only` is blocked unless explicitly acknowledged. `legacy` signals maintenance or lifecycle risk and is also blocked by default.

The registry is not a claim that all tools are equivalent. trust-manager distributes trust, SPIRE issues workload identity, Caddy and Traefik combine edge proxying with ACME, and ACME clients do not replace a formal enterprise CA.

## Reviewed binary acquisition

Host installations of lego, Caddy, Traefik, standalone step-ca and the three
CFSSL executables require explicit three-component numeric release versions and
reviewed SHA-256 payload identities. Configure these under
`spec.adapters.versions` and `spec.adapters.checksums`. Linux checksum keys are
`lego`, `caddy`, `traefik`, `step_ca`, `cfssl`, `cfssljson` and `cfssl-bundle`;
values use `sha256:` followed by exactly 64 hexadecimal characters. A key ending
in `_amd64` or `_arm64` takes precedence over the common key. Every supplied
variant must be valid. Match the checksum to the actual upstream archive or
individual executable for the selected version and architecture; example pins
are deliberately not fabricated.

The Linux role requires HTTPS with certificate verification, verifies downloaded
bytes before extraction or copying, and stores payloads in a root-owned private
content-addressed cache (`/var/cache/certweaver/adapters` by default). It rechecks
file type and digest before installation. Unknown architectures fail instead of
falling back to amd64. Check mode skips acquisition and installation and does
not prove payload verification. Versions and checksums remain subject to the
actual release's acquisition, support, provenance and license reviews.

Windows win-acme requires a numeric version, HTTPS archive URL and
`checksums.win_acme` (raw SHA-256 or the same `sha256:` form). Download verification
is mandatory. An archive-content marker and executable presence control
re-extraction, so an existing `wacs.exe` no longer prevents a changed approved
archive from being installed. Posh-ACME requires `versions.posh_acme`; the role
installs and verifies that exact module version. These paths still require
native Windows/WinRM qualification. Exact version selection does not establish
package provenance or publisher trust.

Production configuration validation rejects missing binary acquisition inputs.
For other environments, ordinary template validation reports warnings so
examples can be inspected; `doctor` and `deploy` apply strict acquisition
validation before inventory generation or Ansible execution. Selecting a chart
or container installation does not invoke the standalone archive rule, and
still requires its own approved immutable identity and supply-chain evidence.

`python scripts/check-adapter-acquisition.py --json` lists source declarations
and source hashes, including unresolved identities, owners and license reviews.
It also rejects missing/optional module download checksums, explicitly disabled
TLS verification and direct URL extraction. This source inventory requires
reconciliation with the actual candidate, charts, containers, OS packages and
transitive dependencies before it can become a complete deployment inventory.

CI runs `scripts/check-adapter-download.py` in an isolated Linux environment
with root permissions for a temporary root-owned cache. It uses only temporary
localhost HTTPS certificates and synthetic payloads, with TLS verification
enabled. Its positive, cache, tampering, invalid-input and check-mode cases
exercise the actual shared Ansible helper. It neither contacts deployment hosts
nor qualifies upstream artifacts or Windows behavior.

## Container image identity and updates

The Quadlet paths now require reviewed `sha256:<64 hexadecimal characters>`
image or multi-platform index digests in `spec.adapters.versions.step_ca_image`,
`openbao_image` and `ejbca_image`. `step_ca` remains the standalone binary version;
it is separate from `step_ca_image`. The image repositories are fully qualified
as `docker.io/smallstep/step-ca`, `docker.io/openbao/openbao` and
`docker.io/keyfactor/ejbca-ce`. Rendered references use `repository@sha256:...`,
with lowercase digest characters. Version tags, including numbered tags, do not
satisfy the digest requirement. Existing tag-based configurations must be
migrated to approved digests before deployment.

The manual Compose example likewise uses required `*_IMAGE_DIGEST` variables;
see `docker/.env.example`. Its five repositories include explicit `docker.io`
registry names. The source guard rejects mutable tag syntax, optional Compose
digest inputs and ambiguous short repository names in these definitions.
Compose interpolation requires a nonempty input; operators must still validate
that the supplied value is a reviewed digest and reconcile the effective model
after any overrides. The structured `certweaver deploy` preflight and Quadlet
role additionally validate the digest syntax themselves.

When `startServices` is enabled, a changed rendered Quadlet requests a restart
after systemd reload. An unchanged unit requests `started`; an OpenBao
configuration change also requests a restart. With `startServices: false`,
the roles prepare files without activating services. Changing an approved image
identity is a service-affecting deployment and needs the profile's maintenance,
rollback and availability controls. This behavior does not independently prove
the running image identity or a safe production upgrade.

CI's `scripts/check-container-configuration.py` uses temporary files and the
actual Ansible gate, templates and source service-state expressions. It checks
initial render, repeat, changed image, repeat after change, OpenBao configuration
change and disabled activation, plus rejected missing/tag/malformed digests.
It does not execute systemd, pull images or start containers. Actual digest
resolution, architecture selection, publisher/signature trust, dependency/SBOM
and license review, runtime identity, readiness and rollback qualification
remain required for the selected deployment.

The reference forms follow the upstream [Quadlet Image contract](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
and [Compose image syntax](https://docs.docker.com/reference/compose-file/services/#image).
Compose required-variable behavior is documented in its
[interpolation specification](https://docs.docker.com/reference/compose-file/interpolation/).

## Exact Git source acquisition

acme.sh, dehydrated, Boulder and Lemur require reviewed full lowercase 40-character
Git commit identities in `versions.acme_sh_ref`, `dehydrated_ref`, `boulder_ref`
and `lemur_ref`. These fixed upstream repositories use SHA-1 Git identities;
branches, tags, abbreviations and other hash formats do not satisfy this
contract. Format validation alone does not prove that a commit exists, belongs
to the intended project, is trustworthy or is supported. Production validation,
`doctor` and `deploy` reject missing/noncanonical identities; ordinary
nonproduction template validation reports warnings.

The role acquires the selected commit over certificate-validated HTTPS into a
private root-owned path beneath `/var/cache/certweaver/adapters/git/<name>/<commit>`.
Each commit has its own checkout. New selections acquire a new path, while
already cached content is verified without contacting upstream. Git hooks and
filesystem-monitor execution are disabled during acquisition/inspection, and
submodules are not automatically fetched. Check mode skips acquisition,
verification and dependent installation and grants no source-verification proof.
The managed launcher removes inherited Git variables that can disable TLS or
redirect object/configuration state, then enforces certificate verification and
hook policy. In particular, Git treats the presence of `GIT_SSL_NO_VERIFY` as
disabling verification even when its value is `0`; it must be removed, not set
to a false-looking string. The localhost fixture deliberately supplies an
inherited bypass and requires an untrusted CA to fail before an HTTP request.

Before reuse and before dependent installation, the packaged verifier binds
the actual commit and tree-object bytes to the selected identity, checks the
configured origin, and hashes every working file against that tree. It checks
file type, executable mode and ownership; untracked/ignored payload, extra
directories, external/dangling symlinks, substituted content and unqualified
Git submodules fail. This check does not trust Git's index or file timestamps.
Limits are 100,000 tree entries, 64 MiB per object/file and 512 MiB total payload;
exceeding a limit fails rather than omitting content from verification. A dirty
or partial cached checkout is preserved and rejected, not force-reset. An
operator must investigate and remediate it through the approved change path.
Cache capacity/retention and any required upstream submodule dependencies still
need profile-specific review; cached revisions are not automatically deleted.

dehydrated links to the verified selected source. Lemur stages that source for
separately reviewed integration. Boulder retains its lab-only guard and uses a
stable Compose project name across source selections; its upstream container
definitions and dependencies still require qualification and are not covered
by the repository's manual Compose digest policy.

acme.sh installation now runs from the verified checkout and reconciles a
marker containing the selected commit and observed installed executable digest.
A changed commit, missing executable or changed executable content triggers
installation; repeated matching input leaves the executable installed. The
role sets managed `account.conf` automatic-upgrade policy to `0`, so the normal
managed installation does not silently replace the selected revision. Account
configuration is treated as secret and is not logged. The marker is an observed
executable witness, not complete installed-hook provenance, certificate-lifecycle
proof or upstream approval. Verify actual installer behavior, configuration,
hooks, cron, runtime dependencies and rollback for the approved selected commit.

The repeatable `scripts/check-git-acquisition.py` gate uses temporary localhost
HTTPS Git repositories and an authored synthetic acme.sh-compatible installer.
It covers acquisition/reuse, upgrade/rollback, installed-executable repair,
invalid/nonexistent/wrong-repository refs, changed cached content (including
preserved timestamps/index flags), ignored files, changed origin, external
symlinks, submodules, untrusted CA and check mode. It never installs an upstream
application, issues a certificate or changes a production service. Upstream
commit/signature/trust approval, real installation qualification and complete
dependency inventory remain required.

Ansible's [Git module contract](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/git_module.html)
explains why `update: false` can retain an old checkout. The content-addressed
paths and payload verification replace that behavior in these adapters.

## Verified chart acquisition

All nine repository-managed Helm installations acquire a chart archive first,
verify its supplied SHA-256 identity, check its name and literal release version,
and install from the verified local `.tgz`. A version tag or range alone is not
an archive identity. The installation commands do not use `--dependency-update`
or fall back to a remote chart reference. Chart dependencies must already be
present in the approved archive; rendered images, hooks, configuration and
runtime dependencies still require the selected profile's separate review.

| Installation | Version input | SHA-256 archive input |
|---|---|---|
| cert-manager | `spec.versions.certManager` | `spec.versions.chartChecksums.certManager` |
| approver-policy | `spec.versions.approverPolicy` | `spec.versions.chartChecksums.approverPolicy` |
| trust-manager | `spec.versions.trustManager` | `spec.versions.chartChecksums.trustManager` |
| CSI driver | `spec.versions.csiDriver` | `spec.versions.chartChecksums.csiDriver` |
| Traefik | `spec.addons.traefik.chartVersion`, otherwise `spec.versions.traefikChart` | `spec.versions.chartChecksums.traefik` |
| step-ca chart | `spec.adapters.versions.step_ca_chart` | `spec.adapters.checksums.step_ca_chart` |
| OpenBao chart | `spec.adapters.versions.openbao_chart` | `spec.adapters.checksums.openbao_chart` |
| SPIRE CRDs | `spec.adapters.versions.spire_crds_chart` | `spec.adapters.checksums.spire_crds_chart` |
| SPIRE | `spec.adapters.versions.spire_chart` | `spec.adapters.checksums.spire_chart` |

Checksum values use `sha256:` followed by 64 hexadecimal characters. They
identify the exact compressed chart archive bytes, **not the OCI manifest digest
printed by `helm pull`**. SPIRE and its CRD chart have independent versions and
hashes. Missing identities fail production validation and deployment preflight;
nonproduction template validation reports acquisition warnings. Only enabled
core charts and selected chart installation paths require these inputs.
Selecting a core-chart adapter while disabling its owning add-on fails preflight.

The five core example hashes were observed from the official sources on
2026-11-03 at their existing pinned versions, with matching chart metadata.
Those observations are candidate acquisition records; they are not independent
publisher/signature approval, a current advisory disposition or a supported
production baseline. Changing a version requires reviewing and updating its
archive identity. The examples now select Kubernetes 1.36.5 with cert-manager
1.21.3; the [managed platform baseline](platform-baseline.md) records the dated
acquisition observations and required migration review. Existing Kubernetes
1.33 clusters still require reviewed sequential minor upgrades and staging
qualification before adopting these pins.

The shared `verified_chart` role uses private root-owned content-addressed
storage under `/var/cache/certweaver/charts` and isolates Helm registry/plugin
state from ambient credentials. It rechecks cached bytes before use, repairs a
changed regular cached archive through fresh acquisition, and rejects symlinks
or archives larger than 64 MiB. Hash verification precedes local metadata
inspection. Cached matching archives can be reused without contacting upstream.
Check mode skips acquisition, metadata verification and chart installation;
it provides no archive-verification proof. Cache capacity/retention and the
actual Helm executable's acquisition remain deployment-profile obligations.

CI acquires its Helm client with pinned archive and executable hashes. The
`check-chart-acquisition.py` fixture uses that real client, the actual Ansible
role, temporary HTTPS/OCI endpoints and local `helm template` rendering. It does
not contact a Kubernetes cluster or install a release. Actual deployment,
webhook/CRD behavior, upgrades, rollback, issuer policy, signatures and complete
dependency reconciliation remain required for enterprise acceptance.

The upstream [Helm pull contract](https://helm.sh/docs/v3/helm/helm_pull/) and
[OCI chart documentation](https://helm.sh/docs/v3/topics/registries/) describe
the repository protocols and distinct manifest/chart-content identities.
