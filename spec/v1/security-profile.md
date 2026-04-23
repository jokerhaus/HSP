# HSP v1 Security Profile

## Public Multi-Tenant Baseline

Public deployments MUST enforce:

- client-side encryption for object payloads
- server-side envelope encryption for all persisted stores
- channel-bound authorization for native and gateway operations
- segment-aware path authorization
- signed namespace mutations
- replay protection with `jti` on mutation operations
- tenant-isolated key domains, quotas, event partitions, and audit scopes

## Persisted Stores

The following stores MUST be encrypted at rest:

- chunks
- manifests
- namespace state
- event log
- audit log
- issuer and token cache
- pin and retention state
- snapshots
- backups

## Deduplication

Cross-tenant plaintext deduplication is not part of HSP v1.0.

