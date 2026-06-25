# Network and firewall matrix

The default managed-firewall profile uses least-scope rich rules rather than opening every port globally.

| Flow | Default port(s) | Allowed source |
|---|---:|---|
| Kubernetes API VIP | TCP 8443 | `platform.network.managementCidrs` |
| RKE2/K3s registration VIP | TCP 9346 | `platform.network.managementCidrs` |
| HTTP/HTTPS ingress VIP | TCP 80/443 | `platform.network.ingressCidrs` |
| Embedded etcd peer/client | TCP 2379-2380 | Cluster server node addresses only |
| Kubernetes API backend | TCP 6443 | Cluster server node addresses only |
| RKE2 supervisor backend | TCP 9345 | Cluster server node addresses only |
| Kubelet | TCP 10250 | Cluster server node addresses only |
| Canal VXLAN | UDP 8472 | Cluster server node addresses only |
| Traefik NodePorts | TCP 30080/30443 | Co-located load-balancer node addresses only |
| VRRP | IP protocol 112 | Cluster server node addresses only |

Review CNI-specific ports before changing Canal, and add worker-node CIDRs when separating control-plane and workers. For a dedicated load balancer, allow its source addresses to the API, registration, and ingress backends instead of using the co-located peer rules.
