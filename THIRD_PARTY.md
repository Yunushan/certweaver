# Third-party software

CertWeaver orchestrates, downloads, or configures independent upstream projects. Those projects are **not relicensed under 0BSD**. Their binaries, charts, containers, documentation, trademarks, and source code remain governed by their respective upstream licenses and policies.

The canonical adapter registry is `config/pki-registry.yml`. Operators must review every selected tool's license and deployment terms before use. CertWeaver does not vendor upstream binaries into this repository.

Run `python scripts/check-adapter-acquisition.py --json` to inspect source
declarations for registry adapters, downloads, Git sources, charts, images and
host packages. The report preserves unresolved identities and explicitly marks
ownership/acquisition/license reviews as pending. Registry license identifiers
are declarations, not a verified license inventory or approval to deploy.
Reconcile selected resolved artifacts, transitive dependencies and applicable
notices with the actual release before acceptance. See the
[adapter acquisition contract](docs/pki-adapters.md#reviewed-binary-acquisition).

The GitLab SAST job also runs an upstream Semgrep analyzer container and its
bundled rule packs. `ci/sast.lock.json` records the observed image/version and
rule/notice hashes, including the distinct GitLab, LGPL and LGPL/CC notice
files. This repository does not grant rights to those upstream components.
Their applicable license, rule-use and support terms require maintainer review
for the actual organization and release; a pinned digest is not that approval.
