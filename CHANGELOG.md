# Changelog

## v0.1.0 - 2026-04-23

First public HSP release.

### Added

- Native HSP runtime with QUIC-oriented protocol contracts.
- HTTP/3 gateway with shared service, auth, and policy behavior.
- S3-like storage surface through `hsp-s3`.
- CDN-like edge distribution through `hsp-cdn`.
- Ciphertext-first public profile with client-side encryption assumptions.
- Envelope encryption for persisted stores.
- Capability auth, channel binding, replay protection, and granular admin
  scopes.
- Namespace binding, listing, signed mutations, events, and replay support.
- Existence and integrity metadata without object download through `HEAD` and
  JSON metadata endpoints.
- Prometheus metrics and structured, secret-aware logs for storage operations.
- Go SDK and `hspctl` surfaces.
- Black-box conformance harness covering native, gateway, S3-like, and CDN-like
  paths.
- CI gates for Rust tests, `clippy`, `cargo audit`, Go tests, `govulncheck`,
  conformance, SBOM, and dependency review.

### Security

- Public profile remains ciphertext-only.
- Plaintext edge serving is limited to the separate `trusted-edge-v1` profile
  and remains opt-in.
- Cross-tenant plaintext deduplication is not supported.
- `PUT_CHUNK` now verifies the declared chunk CID against the received
  ciphertext bytes before storage.

### Known Release Boundary

- External security sign-off is still required before claiming strict
  production approval.
- Operator-run staging or production drills are still required for deployment
  sign-off.
