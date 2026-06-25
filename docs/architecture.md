# Architecture

## Control-plane topology

The default is a compact HA design: three RKE2 server nodes also accept trusted platform workloads. Embedded etcd has three voting members. HAProxy and Keepalived are co-located to avoid two extra load-balancer VMs, but a dedicated or hardware load balancer can replace the role without changing the PKI layer.

One VIP serves several TCP frontends. Co-located HAProxy deliberately uses `8443 -> 6443` and `9346 -> 9345`; binding `6443` or `9345` on the same hosts would conflict with RKE2's wildcard listeners. HTTP/HTTPS frontends target stable ingress NodePorts.

## Certificate control plane

- `cert-manager` reconciles Certificate, CertificateRequest, Issuer, ClusterIssuer, ACME Order, and Challenge resources.
- `approver-policy` decides which requests may be approved. cert-manager's automatic approver is disabled.
- `trust-manager` distributes CA trust bundles to approved namespaces/configuration targets.
- An external CA such as step-ca, OpenBao, EJBCA, Dogtag, or a public/commercial ACME CA performs issuance.
- Optional CSI Driver mounts short-lived workload credentials without ordinary TLS Secrets.

## Failure model

The cluster tolerates one RKE2 server/etcd node failure. Keepalived moves the VIP when the active node or HAProxy health check fails. HAProxy removes failed API/registration/ingress backends. Two simultaneous etcd member failures stop writes and require recovery rather than automatic operation.

## Expansion path

For larger deployments, keep three dedicated control-plane/etcd nodes and add at least three workers. Move the VIP/load balancer to two dedicated hosts or an enterprise ADC. Reserve trusted platform nodes for cert-manager and CA integration components.
