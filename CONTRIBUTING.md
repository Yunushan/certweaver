# Contributing

1. Open an issue describing the problem or adapter change.
2. Create a branch from `main`.
3. Add or update tests, documentation, and the adapter registry.
4. Run `make lint test`.
5. Submit a focused pull/merge request and complete the security checklist.

Use the [locked Python development profile](docs/python-dependencies.md) when
preparing the environment. Dependency changes must regenerate the source-bound
locks and pass the relevant Python, Ansible and installed-package checks.

Never commit private keys, API tokens, kubeconfigs, cluster join tokens, CA databases, HSM credentials, or real customer DNS names. Use placeholders in examples.

Adapters must be idempotent, version-pinnable, explicit about destructive operations, and truthful about supported targets and maturity. New adapters require a task file, registry entry, documentation, and tests.
