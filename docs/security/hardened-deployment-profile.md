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

