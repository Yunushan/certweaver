# Adapter matrix

| # | Adapter | Primary targets | Maturity | Default? |
|---:|---|---|---|---|
| 1 | cert-manager | Kubernetes | Production | Yes |
| 2 | step-ca | Kubernetes/Linux/containers | Production | Optional internal CA |
| 3 | OpenBao PKI | Kubernetes/Linux/containers | Production | Optional |
| 4 | acme.sh | Linux/containers | Production | No |
| 5 | Certbot | Linux/containers | Production | No |
| 6 | EJBCA Community | Kubernetes/Linux/containers | Advanced | No |
| 7 | lego | Linux/containers | Production | No |
| 8 | Dogtag PKI | Linux/containers | Advanced | No |
| 9 | FreeIPA + certmonger | Linux | Production | No |
| 10 | CFSSL | Linux/containers | Advanced | No |
| 11 | trust-manager | Kubernetes | Production | Yes |
| 12 | cert-manager CSI Driver | Kubernetes | Production | Disabled by default |
| 13 | dehydrated | Linux/containers | Advanced | No |
| 14 | win-acme | Windows | Production | No |
| 15 | Posh-ACME | Windows | Production | No |
| 16 | SPIRE/SPIFFE | Kubernetes/Linux | Production | No |
| 17 | Boulder | Lab/integration | Lab-only | Blocked by default |
| 18 | Caddy Automatic HTTPS | Linux/containers | Production | No |
| 19 | Traefik ACME Resolver | Kubernetes/Linux/containers | Production | Proxy enabled; resolver off |
| 20 | Lemur | Linux/containers | Legacy | Blocked by default |

The core `approver-policy` installation is part of the hardened cert-manager profile but is not counted as one of the requested twenty adapters.
