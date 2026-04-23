# ADR 0004: Encrypted Deduplication Boundaries

## Status

Accepted

## Decision

Do not support cross-tenant plaintext deduplication in HSP v1.0.

## Consequences

- equality leakage across tenants is not exposed through storage behavior
- ciphertext-level dedup remains possible when encryption context allows it
- tenant-scoped plaintext-aware dedup, if ever introduced, requires a separate
  extension and threat review

