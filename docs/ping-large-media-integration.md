# Ping large media integration notes

## Context

Ping uses HSP as the storage/encryption layer for messenger media. Ping must support
large video uploads up to 2 GiB without forcing Ping backend or HSP distribution
services to materialize whole objects in memory.

## Local integration changes

- `crates/hsp-distribution/src/lib.rs`
  - `complete_multipart_upload` no longer concatenates all uploaded parts into one
    full-object buffer before committing.
  - Multipart completion now builds a fixed-size HSP chunk manifest from uploaded
    S3-compatible parts and commits chunks through `put_init`, `put_chunk`, and
    `put_commit`.
  - The multipart roundtrip test now crosses 1 MiB HSP chunk boundaries so S3 parts
    and HSP chunks are verified as separate concepts.

## Documentation to update upstream

- `docs/releases/*`: mention multipart completion no longer assembles full objects
  in memory.
- `docs/upgrade/*`: document that Ping-style large media uploads should use
  S3-compatible multipart upload and bounded part sizes.
- Distribution/S3 API docs: clarify memory expectations:
  - Upload parts are bounded by the S3 request body limit.
  - CompleteMultipartUpload is manifest/chunk based for ciphertext uploads.
  - Trusted-edge plaintext multipart still requires a separate streaming encryption
    design before being used for very large plaintext uploads.

## Follow-up work

- Add true streaming or range-first download support across distribution/S3 gateway
  so large media playback does not materialize whole objects.
- Add release evidence for 1.5-2 GiB multipart upload and range playback.
