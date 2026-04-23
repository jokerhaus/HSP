# ADR 0003: Crypto Profile and Key Hierarchy

## Status

Accepted

## Decision

Adopt the following baseline suites:

- `Ed25519` for signatures
- `COSE_Sign1` for tokens and signed records
- `XChaCha20-Poly1305` for client-side object encryption
- `AES-256-GCM` for server-side envelope encryption
- `HPKE/X25519` for wrapped object-key distribution
- `SHA-256` for CID hashing

Key hierarchy:

- tenant master key
- per-object data key
- wrapped object-key records for authorized readers
- server-side KEK/DEK hierarchy for persisted stores

## Consequences

- plaintext keys are forbidden on disk
- rotation and rewrap procedures become first-class operational workflows
- bootstrap, INFO, and PUT_INIT must advertise crypto and key policy choices

