# GitOps

Keep the desired CertWeaver configuration, pinned versions, Helm values, issuer templates, policies, and non-secret inventory metadata in Git. Store secrets in an approved encrypted system and inject them at deployment. Protect `main`, require signed reviews, run CI validation, and separate plan from apply.

For cluster add-ons, organizations may render or translate the supplied values into Flux or Argo CD resources. cert-manager must be installed exactly once per cluster and should not be hidden as an application subchart.
