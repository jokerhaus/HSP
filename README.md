# HSP

HSP (Hybrid Storage Protocol) is a secure storage protocol and reference
implementation for teams that need an object store they can trust, observe, and
extend. In simple terms: HSP lets an application upload files, read them back,
share them through S3-like and CDN-like services, and still keep the public
profile ciphertext-only.

## What Problem HSP Solves

Most applications start with a simple storage provider: upload a file, store a
URL, download it later. That works until the product needs stronger guarantees:

- files must stay encrypted in storage
- tenants must not be able to see each other's data
- the backend must verify that an object exists and is intact without
  downloading the whole file
- operators need metrics and logs from the storage layer itself
- existing tools still expect S3-style buckets and object keys
- downloads need CDN-style delivery without turning the edge into a plaintext
  data leak

HSP is built for that point. It gives you a storage core, a native protocol,
an HTTP/3 gateway, an S3-like surface, and a CDN-like edge layer that all share
the same auth, policy, encryption, and tenant-isolation rules.

## Plain-Language Examples

### Media App

A chat or social app stores images and videos through HSP. The app encrypts
the media before upload. HSP stores only ciphertext, returns a stable content
ID, and lets the backend check:

```json
{
  "exists": true,
  "size_bytes": 1786060,
  "ciphertext_size_bytes": 1786200,
  "integrity_hash": "sha256-...",
  "cid": "sha256-...",
  "encryption_profile_id": "ping-media-v1",
  "key_policy_id": "ping-media-default"
}
```

The backend can verify the object without downloading the bytes again.

### SaaS Tenant Storage

Each customer gets isolated namespaces and keys. One tenant cannot confirm or
read another tenant's objects. Logs, metrics, cache keys, and replay protection
all carry tenant context.

### S3-Compatible Integration

Existing internal tools can use bucket/key semantics through `hsp-s3`:

```bash
aws --endpoint-url http://localhost:8081 s3 cp ./photo.enc s3://media/photos/1.enc
aws --endpoint-url http://localhost:8081 s3 ls s3://media/photos/
```

The compatibility is for HTTP/auth/object behavior. In the public profile, HSP
still serves ciphertext, not plaintext.

### CDN-Like Delivery

`hsp-cdn` can serve immutable objects by CID and mutable bucket/key routes. CID
routes can be cached aggressively. Namespace or bucket/key routes use shorter
TTL and purge on mutation events, so stale bindings do not live forever at the
edge.

## What You Get By Using HSP

- A Rust reference server for the native HSP protocol.
- An HTTP/3 gateway for clients that want HTTP semantics.
- S3-like object storage compatibility through `hsp-s3`.
- CDN-like edge delivery through `hsp-cdn`.
- Client-side encryption first in the public profile.
- Envelope encryption for persisted internal stores.
- Capability-based auth, channel binding, replay protection, and signed
  namespace mutations.
- `HEAD` and metadata APIs for cheap existence and integrity checks.
- Prometheus metrics and structured, secret-aware logs from the storage layer.
- Go SDK and CLI surfaces for integration and diagnostics.
- A black-box conformance harness for native, gateway, S3-like, and CDN-like
  behavior.

## Security Baseline

This bootstrap adopts a hardened `public multi-tenant` security baseline with:

- Rust as the primary implementation language for the native server, gateway,
  parser surfaces, auth engine, crypto profile wiring, and conformance harness.
- Go as the required SDK and CLI deliverable surface.
- Mandatory client-side encryption for object data in the public profile.
- Mandatory server-side envelope encryption for every persisted store.
- Channel-bound authorization, replay protection, and segment-aware path
  authorization.

## Repository Layout

- `spec/`: normative protocol addenda, security profile, and registries.
- `docs/`: ADRs, threat model, versioning, release, and operator guidance.
- `crates/`: Rust protocol core crates.
- `server/`: Rust reference server entrypoint (`hspd`).
- `gateway/`: Rust HTTP/3 gateway entrypoint (`hsp-gw`).
- `gateway/hsp-cdn/`: Rust CDN edge runtime for immutable CID and mutable
  bucket/key delivery.
- `server/hsp-s3/`: Rust S3-like compatibility runtime.
- `conformance/`: Rust conformance harness bootstrap.
- `sdk/go/`: Go SDK packages.
- `cli/`: Go CLI bootstrap.
- `deploy/`: hardened deployment manifests and guidance.
- `testdata/`: golden data for security and protocol fixtures.

## Distribution Layer

The distribution layer extends HSP with two additional services:

- `hsp-s3`: bucket and object semantics over an S3-like HTTP surface
- `hsp-cdn`: ciphertext-first edge delivery over immutable CID routes and
  mutable bucket/key routes

Both services share the same Rust service, auth, and policy layer as the native
HSP runtime. In the public profile they remain ciphertext-only: clients upload
and download ciphertext, and plaintext assembly stays outside the server/edge
boundary.

## Metadata And Observability

HSP exposes a cheap existence and integrity path so storage clients do not have
to download objects just to verify them:

- Native/gateway `HEAD` returns HSP integrity headers including
  `x-hsp-exists`, `x-hsp-deleted`, `x-hsp-cid`, `x-hsp-integrity-hash`,
  `x-hsp-size-bytes`, `x-hsp-ciphertext-size-bytes`,
  `x-hsp-encryption-profile-id`, and `x-hsp-key-policy-id`.
- Gateway JSON metadata endpoints are available at
  `/v1/objects/cid/{cid}/metadata?tenant_id=...` and
  `/v1/objects/namespace/{namespace}/{path}/metadata?tenant_id=...`.
- `integrity_hash` is the canonical HSP object integrity hash
  (`object_cid == manifest_cid` in this release) and is computed from the
  deterministic manifest that commits the ciphertext chunk CIDs.

Production observability is first-class and secret-aware:

- `GET /metrics` exposes Prometheus text metrics for `put`, `get`, `delete`,
  `auth_denied`, `kms_error`, `integrity_error`, latency sums, and object-size
  sums.
- `GET /v1/observability/logs` returns recent structured, secret-redacted log
  records for debugging.
- Both observability endpoints require capability auth with
  `admin.metrics.read` or `admin.audit.read`.

## Toolchains

- Rust stable with `rustfmt` and `clippy`
- Go 1.25.9 via `go.work` / module `toolchain` directives

## Release Gates

Production release candidates are expected to pass the same baseline locally
and in CI:

- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo audit`
- `GOTOOLCHAIN=go1.25.9+auto go work sync`
- `go test ./sdk/go/... ./cli/hspctl/...`
- `govulncheck ./...` in `sdk/go` and `cli/hspctl`
- `cargo run -p hsp-conformance`

Release artifacts also include:

- SPDX JSON SBOM generated by Syft
- dependency-review PR gate results
- `cargo audit` and `govulncheck` reports
- `hsp-conformance` JSON report
- release evidence bundle under [docs/release-evidence](docs/release-evidence)

## Bootstrap Commands

```bash
./scripts/bootstrap-local.sh
```

Rust tooling is required for the Rust workspace commands. The Go modules are
kept separate through `go.work`.
