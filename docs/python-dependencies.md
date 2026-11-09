# Python dependency locks and qualification

The qualification path uses exact Python dependency versions and SHA-256 hashes.
The library's metadata retains compatibility ranges; an arbitrary downstream
`pip install certweaver` is not the hash-locked qualification path described here.
Generated pins require maintainer review and do not grant enterprise assurance.

## Profiles and source binding

| Profile | Content | Use |
|---|---|---|
| `ci/python-runtime.lock` | Complete application dependency resolution, including Python-specific transitives | Candidate installation, SBOM and vulnerability scan |
| `ci/python-build.lock` | Runtime dependencies, build-system requirements, build frontend and pip | Installed-package matrix and release builds |
| `ci/python-dev.lock` | Runtime/build inputs, development and Ansible verification tools, and the default WinRM/NTLM controller transport | Linux test/lint matrix, Ansible controllers and local development |

The lockfiles use universal environment markers. Python 3.11 resolves Ansible
Core 2.19; Python 3.12 and later resolve Core 2.21. Runtime Python versions below
3.13 additionally require `typing-extensions`. A universal resolution does not
prove execution on every platform; the declared CI matrix and recorded local
runs define the available compatibility evidence.

The development/controller profile includes `pywinrm` and its hash-locked
NTLM dependency closure. Ansible's WinRM connection plugin requires this library
on the controller; installing `ansible-core` and Windows collections alone does
not provide it. `tests/test_controller_transports.py` loads the actual plugin on
Linux and prepares a certificate-validating HTTPS/NTLM session with network calls
blocked. Additional synthetic localhost HTTPS cases require the trusted fixture
certificate to succeed and untrusted-root/hostname-mismatch cases to fail before
an HTTP request reaches the receiver. They do not authenticate to Windows or
qualify a live deployment. A network path that substitutes a different certificate
can prevent the positive fixture from passing; retain that failure as an
environment limitation and qualify an approved representative path. Do not
disable certificate validation to obtain a passing result.

For Windows profiles using WinRM, `doctor` and deployment preflight query the
selected `ansible-playbook --version`, then inspect the Python executable that
Ansible reports. They use that executable in isolated mode to load the built-in
WinRM dependency stack; a working library in a different CLI environment cannot
satisfy the check. The probe preserves the venv executable path and uses no
inventory, managed-host connection, credentials or shell command expansion.
Missing, ambiguous or failed runtime probes stop before deployment inventory
creation or replacement. Third-party diagnostic output is bounded and not
reflected into operator errors.

Every explicitly selected WinRM authentication method must be available, including
methods in a comma-separated preference list. The preflight does not silently
discard a missing Kerberos/CredSSP dependency and rely on another method. These
checks cover local library availability; collections, optional authentication OS
prerequisites, credentials, server identity and actual access still require the
profile's independent qualification.

CI runs `scripts/check-controller-preflight.py` in each Linux Python profile.
It exercises a working controller and a separate real Ansible-only environment
whose transitive dependencies are selected from the source-bound dev hash lock.
The second runtime genuinely lacks `pywinrm`. Both `doctor` and `deploy --check`
must reject it while preserving absent/existing inventory files; the fixture
permits only the two local introspection commands and rejects target execution.
Run it locally with a fresh output directory, for example
`make controller-check CONTROLLER_CHECK_OUTPUT=.certweaver/controller-check-attempt-1`.
The fixture installs the locked minimal Ansible closure into its private negative
environment; it needs access to the approved package index and retains its
diagnostic output instead of overwriting a prior run.

Use a supported Linux Ansible controller for Windows targets. The native Windows
Python test run is library/CLI evidence, not an Ansible controller qualification.
The bundled transport covers the default NTLM path and pywinrm's base transports;
Kerberos and CredSSP require separately reviewed optional Python/OS prerequisites
and their own authentication, delegation and TLS tests. Keep server certificate
validation enabled and provision the staging listener, trust chain and protected
credentials before live tests. See the official
[Ansible WinRM requirements](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/winrm_connection.html)
and [pywinrm authentication prerequisites](https://github.com/diyan/pywinrm#installation).

`ci/python-locks.json` binds all three lockfile hashes to `pyproject.toml` and
`ci/python-build.in`. A changed input, lock hash or lock path fails before pip is
invoked. The parser rejects open version ranges, nested requirements, direct
download URLs, extra indexes, editable entries and unhashed dependencies in the
committed locks. The generated candidate requirement is the one controlled
exception: its local wheel URI has an explicit SHA-256 derived from the candidate.

The manifest records the generator identity, executable hash, generation time,
PyPI index and release-age cutoff. Its `GENERATED_PINS_REQUIRE_MAINTAINER_REVIEW`
status is deliberate. A file hash detects changes relative to the checked-out
source; it is not an independent approval or upstream signature.

## Install and build

Create and activate a fresh virtual environment before installing dependencies.
For Linux development:

```sh
python3 -m venv .venv
. .venv/bin/activate
python scripts/install-python-deps.py dev --editable
ansible-galaxy collection install -r collections/requirements.yml
make lint test validate
```

For a package build, use the build profile and the full expected source commit.
The [exact-source builder and reproduction check](reproducible-packages.md) set
deterministic archive metadata and verify a second clean build:

```sh
python scripts/install-python-deps.py build
python scripts/build-package.py --commit "$EXPECTED_COMMIT"
python scripts/check-package-reproducibility.py --commit "$EXPECTED_COMMIT"
python scripts/check-wheel.py dist/*.whl
pip wheel --no-build-isolation --no-deps dist/*.tar.gz --wheel-dir rebuilt
python scripts/check-wheel.py rebuilt/*.whl
```

The installer first uses the interpreter's provisioned pip to install only the
hash-pinned pip wheel. That pinned installer installs the complete selected
profile with `--require-hashes --only-binary=:all:` from the explicit PyPI index.
An unsupported wheel/platform combination fails instead of building an unpinned
dependency from source. The interpreter/provisioned bootstrap and its supply
chain remain explicit release inputs requiring review.

Pip configuration overrides are removed and `PIP_CONFIG_FILE` is set to the
platform's null device. The pip subprocess uses Python's isolated mode; the
configuration variable remains available to pip itself. Project installation
uses `--no-deps --no-build-isolation`, followed by `pip check`. These flags prevent
a second implicit dependency resolution after the reviewed profile is installed.
See [pip's secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/).

GitHub CI, GitLab CI, `make install` and the development bootstrap use the shared
installer. Package builds and sdist rebuilds disable build dependency resolution.
The workflow contract rejects missing or conditional lock installation and a
return to direct unpinned pip/build commands.

## Candidate runtime and evidence

`scripts/qualify-release.py` validates the source-bound locks and writes a fresh
candidate requirements file inside its restricted work directory. It combines
the runtime lock with the exact local candidate wheel and its SHA-256. Pip then
installs that complete set into a new target, with hash checking, wheels only,
configuration overrides disabled and no bytecode compilation.

Installed metadata, the SBOM and the vulnerability report must still agree
exactly. Hash locking does not replace vulnerability scanning or inventory
reconciliation. The transferred qualification record binds the dependency
manifest, all locks, build input file, project metadata and installer script to
the same candidate's policy/source hashes. Publisher verification rejects
changed lock policy just as it rejects changed candidate bytes.

The package source distribution includes the dependency inputs and locks. The
runtime wheel's deployment-resource allowlist remains unchanged; lock-generation
tools and downloaded dependency wheels are not bundled into it.

## Regenerate and review

Acquire and verify uv through the maintainer's approved tool-acquisition process.
The current generator version and executable hash are recorded in the manifest;
uv is needed to regenerate locks, not to run the CI installer. Then run:

```sh
python scripts/lock-python-deps.py --uv /absolute/path/to/verified/uv
```

The default cutoff excludes releases newer than seven days, matching the
repository's dependency-update policy. Use `--exclude-newer` with an aware ISO
timestamp to reproduce an explicitly selected cutoff. The generator disables
uv/pip environment overrides and uv configuration, uses the explicit PyPI index,
requests universal hashes and refuses to build dependency sources. All three
resolutions must succeed and pass the strict lock syntax check before existing
lockfile contents are replaced. Private diagnostic logs remain in ignored
`.certweaver/lock-generation/` storage.

Review the version/hash/marker diff, publisher acquisition identities, licenses,
upstream support and advisories. Re-run the compatibility, Ansible and installed
artifact checks, and qualify the exact proposed release. Do not edit manifest
hashes to conceal changed dependency inputs or treat successful generation as
approval. Universal-resolution semantics are described in
[uv's resolution documentation](https://docs.astral.sh/uv/concepts/resolution/).

## Remaining assurance boundaries

The local locks do not freeze every interpreter, operating-system package,
container, chart, Ansible collection archive or external deployment dependency.
Those inputs still need their own approved inventory, acquisition and lifecycle
evidence. Complete licensing review, original-evidence retention, hosted CI and
authenticated independent release acceptance also remain required for enterprise
100/100.

At the previous checkpoint, two independent local Python 3.11 builds with the same declared fixture inputs
produced identical wheel bytes and identical regular-file payloads in their
source distributions. Wheel bytes also matched across the local Python
3.11–3.14 builds. Source-archive bytes differ: gzip timestamps and tar member
mtime/PAX metadata varied. That observation is preserved in
`.certweaver/dependency-locks-20261103/sdist-reproducibility-differences.json`.
This identified the normalization requirement addressed by the new exact-source
builder. Real builds and fresh-environment reconstruction now produce identical
wheel and compressed-sdist bytes on Python 3.11–3.14 for the same synthetic commit,
while preserving payloads. Approved
production inputs and authenticated independent acceptance remain required for
SUP-05; local automated reconstruction does not supply that acceptance.

Renovate's project-metadata updates do not regenerate this manifest. Regenerate
and review the complete lock set in the same dependency-change request. A stale
manifest deliberately fails CI rather than silently resolving changed inputs.

## GitLab release-verifier inputs — 2026-11-03

The build profile now declares cryptography and PyJWT for DER certificate and
RS256 ID-token verification. The regenerated universal locks retain the original
2026-10-27 dependency-age cutoff; existing runtime and development-tool pins are
unchanged, with PyJWT added to development. These are build/verification inputs,
not new product runtime requirements. Real source-security scans reconcile all
runtime/build/development lock inventories across the supported marker matrix.
Maintainer/publisher/license/support approval remains required. See the
[GitLab release contract](gitlab-release.md) and current enterprise status.
