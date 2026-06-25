#!/usr/bin/env bash
set -euo pipefail
KUBECONFIG=${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}
kubectl --kubeconfig "$KUBECONFIG" get nodes
kubectl --kubeconfig "$KUBECONFIG" -n cert-manager get deploy,pod
kubectl --kubeconfig "$KUBECONFIG" get certificaterequestpolicies.policy.cert-manager.io || true
kubectl --kubeconfig "$KUBECONFIG" get bundles.trust.cert-manager.io || true
