# Air-gapped deployment

CertWeaver exposes URLs, images, chart references, and package repositories as variables. A production air-gap process should mirror RKE2 artifacts, container images, OCI Helm charts, RPM repositories, Python wheels, Ansible collections, and adapter binaries into approved internal registries. Populate checksums and disable every runtime fetch before deployment.

The initial reference implementation contains online defaults; it is not an air-gap bundle by itself.
