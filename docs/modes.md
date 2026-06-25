# Deployment modes

| Mode | Cluster lifecycle | Typical target |
|---|---|---|
| `rke2-ha` | Managed | Three-plus Rocky/RHEL-like servers |
| `k3s-ha` | Managed | Smaller edge or constrained HA platform |
| `existing-kubernetes` | Unmanaged | Existing RKE2/Kubernetes/OpenShift cluster |
| `standalone` | None | Linux CA/client hosts |
| `docker` | None | Docker/Podman profiles and integration labs |
| `raw` | None | Explicit host installer tasks |
| `windows` | None | IIS/Windows certificate automation |

Changing mode is declarative, but adapters remain limited to their real upstream target platforms. The CLI rejects invalid combinations.
