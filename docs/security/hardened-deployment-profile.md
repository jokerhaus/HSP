# Hardened Deployment Profile

The hardened deployment profile requires:

- rootless containers
- read-only root filesystem
- `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`
- dropped Linux capabilities
- isolated admin endpoints
- workload identity to reach KMS/HSM
- encrypted backups and recovery drills
- tenant-partitioned quotas, event streams, and audit scopes

Secrets and KEKs MUST NOT be shipped as static long-lived values inside config
files or container images.

Runtime KMS material and edge signing secrets MUST be injected explicitly from
the deployment secret manager. Production binaries fail closed when
`HSP_KMS_SEED` or `HSP_EDGE_SIGNING_SECRET` is missing, too short, or set to a
known local-dev default literal. AWS KMS adapters also require
`HSP_AWS_KMS_RUNTIME=live-cli`; local fallback is only allowed through the
explicit `local-dev` runtime mode for development and tests.

Services that share an encrypted store MUST use the same KMS key domain. The
reference Kubernetes manifests inject a shared `storage-kms-seed` for
`hspd`, `hsp-gw`, `hsp-s3`, and `hsp-cdn`; production deployments should map
that same boundary to one workload-identity-backed KMS/HSM key domain.
