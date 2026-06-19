# Changelog

## v0.1.2 - 2026-06-19

Security fix release for the HSP core, S3-like service, CDN edge, CI, and
release pipeline.

### Security

- Fixed CDN namespace cache-hit authorization bypass by forcing scoped
  namespace delivery through the shared service authorization path.
- Fixed native `SUBSCRIBE` filter authorization so every requested filter is
  independently checked.
- Fixed upload quota bypass by validating actual ciphertext chunk length
  against `PUT_CHUNK.chunk_length`, manifest `stored_len`, and chunk limits.
- Enforced `CapabilityClaims.storage_classes` during upload authorization.
- Added bounded request-body reads for native, gateway, S3-like, and CDN
  request paths.
- Hardened object lock:
  - ordinary writers can no longer clear legal hold.
  - active retention cannot be shortened without `admin.repair`.
  - active compliance retention cannot be shortened or cleared.
  - `CopyObject` now respects destination legal hold and retention.
- Fixed header SigV4 body binding by verifying `x-amz-content-sha256` against
  the received request body.
- Preserved empty object-key segments in S3 path-style routing.
- Added a bounded S3 backing-store response reader.
- Removed the direct `rustls-pemfile` dependency and replaced it with a minimal
  certificate-only PEM parser for custom CA bundles.
- Updated Go release baseline to `go1.25.11`.
- Pinned CI GitHub Actions and security tools to immutable SHAs or explicit
  versions.
- Pinned Docker base images by digest and converted Kubernetes examples to
  digest-form workload images.

### Tests

- Added regression coverage for storage-class policy, chunk length mismatch,
  multi-filter subscription authorization, object-lock bypass attempts,
  `CopyObject` destination lock enforcement, SigV4 payload mismatch, CDN body
  rejection, and S3 path-style empty key segments.

### Upgrade Notes

- Operators must use Go `1.25.11+` for SDK/CLI validation.
- Release bundles now require a preinstalled pinned Syft binary instead of
  downloading and executing a remote installer.
- Kubernetes example image digests are placeholders and must be replaced with
  the actual published image digests for the target release.

## v0.1.1 - 2026-06-01

Security-hardening and owner-operated production readiness release.

### Security

- Required explicit runtime KMS and edge signing secrets.
- Rejected known legacy default runtime secrets.
- Tightened S3/CDN scoped authorization and edge token behavior.
- Added durable encrypted replay markers.
- Added release-evidence and internal owner-operated sign-off docs.

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
