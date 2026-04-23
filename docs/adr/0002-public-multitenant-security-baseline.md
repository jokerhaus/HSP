# ADR 0002: Public Multi-Tenant Security Baseline

## Status

Accepted

## Decision

For public deployments, HSP requires:

- client-side encrypted object data
- server-side encryption for every persisted store
- strict tenant key domains
- channel-bound authorization
- mandatory replay protection with `jti`
- signed namespace mutations
- no cross-tenant plaintext deduplication

## Consequences

- public servers do not receive or persist plaintext object payloads
- deduplication is limited to ciphertext-level semantics unless a future
  opt-in extension changes that after separate review
- storage, event, namespace, and backup systems must be designed for encryption
  from day one

