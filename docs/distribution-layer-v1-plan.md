# HSP Distribution Layer v1 Plan

> Status note (April 20, 2026): this v1 document reflects the original slice.
> Current completion status for later waves is tracked in
> `docs/hsp-100-completion-status.md`.

## Status

This document defines the first implementation slice for the distribution
layer that sits on top of the existing HSP core. It introduces two new thin
services:

- `hsp-s3`: an S3-like HTTP compatibility surface
- `hsp-cdn`: an edge delivery surface for immutable CID delivery and mutable
  namespace delivery

The public profile remains `E2EE-first` and `ciphertext-first`. The server and
edge services MUST NOT assemble or serve plaintext object data.

## Scope

The first implementation slice covers:

- bucket lifecycle with `bucket = namespace`
- object CRUD mapped onto HSP manifests, chunks, and namespace bindings
- ciphertext object ingest and export
- multipart upload staging and completion
- dual auth translation:
  - HSP capability token
  - AWS SigV4 header auth
  - AWS-style presigned URL auth
- short-lived CDN edge token auth
- immutable CID delivery
- mutable namespace delivery with short-lived cache headers
- encrypted persisted stores for registry, multipart, and distribution
  metadata

The following items remain outside this first slice:

- legacy S3 ACLs
- website hosting
- replication
- lifecycle rules
- object lock or legal hold
- plaintext edge delivery
- trusted-edge decryption
- cloud-specific KMS/HSM adapters
- full AWS ecosystem parity

## Security Boundaries

- All persisted data written by the distribution layer MUST use the same
  envelope-encryption model as the existing HSP stores.
- Tenant isolation remains authoritative in the shared Rust service layer.
- Cross-tenant plaintext dedup remains unsupported.
- `hsp-s3` and `hsp-cdn` MUST reuse shared Rust policy and auth decisions
  instead of implementing separate allow/deny logic.
- Namespace mutations created by the distribution layer MUST still be signed.
  The implementation may use an internal namespace-authority signer, but the
  resulting records must be verified by the same issuer-registry path used by
  the HSP core.
- Mutating distribution requests MUST remain request-bound:
  - HSP capability auth uses a canonical request proof
  - SigV4 and presigned URLs use their canonical request signature
  - CDN edge tokens are short-lived and request-scoped

## Data Model

- `bucket` maps to canonical HSP `namespace`
- `object key` maps to canonical HSP `path`
- `tenant` comes from the authenticated principal, not the bucket name
- `object_cid == manifest_cid` remains the canonical object identity in this
  stage
- `ETag`, `Content-Length`, conditional validators, and range semantics are
  defined over ciphertext object identity

## Persisted Stores

The distribution layer adds new encrypted stores:

- `bucket-registry`
- `distribution-metadata`
- `multipart-sessions`
- `multipart-parts`
- `presign-audit`

These stores are tenant-scoped and use the same envelope-encryption baseline as
`chunks`, `manifests`, `events`, `audit`, and namespace state.

## Object Ingest Model

`PutObject` and `CompleteMultipartUpload` ingest ciphertext bytes into HSP by:

1. Constructing a deterministic HSP `Manifest`
2. Chunking ciphertext into bounded chunk refs
3. Calling `PUT_INIT`
4. Uploading all ciphertext chunks through `PUT_CHUNK`
5. Finalizing through `PUT_COMMIT`
6. Publishing or updating the namespace binding for `bucket/key`

In public profile, the distribution layer never sees plaintext payloads and
does not derive plaintext metadata.

## Read Model

- `GET` and `HEAD` by bucket/key resolve the namespace binding through the
  shared service layer
- `GET` by CID streams ciphertext reconstructed from chunked HSP storage
- range reads operate over the ciphertext object stream
- `manifest-only` remains available through HSP-native surfaces, but S3-like
  and CDN delivery remain object-stream focused

## CDN Cache Model

- CID routes are immutable and cacheable for a long TTL
- namespace routes are mutable and cacheable only for a short TTL
- namespace cache entries must never be shared across tenants
- auth-sensitive responses are not cacheable unless the signed policy allows it
- `hsp-cdn` runs a background invalidation worker that polls tenant event streams
  and purges namespace cache entries on `namespace.bound`,
  `namespace.unbound`, `namespace.tombstoned`, and `object.committed` events

## Operator Notes

Deployments should place `hsp-s3` and `hsp-cdn` as separate services that share
the HSP storage root, KMS identity, issuer registry, and namespace authority
signer. TLS termination may happen at the service itself or at the edge, but
request auth validation and object data handling remain ciphertext-only in
either topology.
