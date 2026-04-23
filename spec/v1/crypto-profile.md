# HSP v1 Crypto Profile

## Minimum-to-Implement Suites

- Signature: `Ed25519`
- Signed object format: `COSE_Sign1`
- Client-side object encryption: `XChaCha20-Poly1305`
- Server-side persisted-store encryption: `AES-256-GCM`
- Key wrapping for authorized readers: `HPKE/X25519`
- CID hashing: `SHA-256`

## Key Hierarchy

- one tenant master key per tenant
- one object data key per object
- wrapped object keys for reader distribution
- one or more server-side KEK/DEK layers per persisted store

## Key Handling Rules

- plaintext keys MUST NOT be written to disk
- object keys MUST be stored only in wrapped form
- rotation and rewrap MUST be supported without protocol ambiguity

