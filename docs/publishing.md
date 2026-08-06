# Publishing to GitHub

GitHub is the canonical repository for CertWeaver:
`https://github.com/Yunushan/certweaver`.

## Repository policy

The default branch is protected with mandatory CI, security, CodeQL, and Trivy
checks; code-owner review; signed commits; linear history; conversation
resolution; and no force-push or deletion. Merged branches are deleted
automatically. Keep changes in pull requests and merge only after all required
checks are green and an approving code-owner review is recorded.

The repository uses Renovate for release-aged dependency updates. Keep the
dependency dashboard enabled and review grouped updates before merging them.

## Release procedure

Run releases from the protected `main` branch after the version in
`pyproject.toml` and the release notes have been reviewed:

```bash
git switch main
git pull --ff-only origin main
git tag -s v0.1.0 -m "CertWeaver v0.1.0"
git push origin v0.1.0
```

The tag-triggered release workflow verifies the tag/version match, builds the
wheel and source archive, creates an SBOM and SHA-256 checksums, and publishes
provenance attestation. Use a new signed `vX.Y.Z` tag for each version; never
retag an existing release.

Optional GitLab mirroring should use a separately configured private remote and
must not bypass the GitHub review and release process.

Never put deployment secrets into repository variables exposed to untrusted
pull-request pipelines. Keep deployment tokens, kubeconfigs, CA material, DNS
credentials, and recovery keys in approved encrypted systems.
