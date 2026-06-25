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
