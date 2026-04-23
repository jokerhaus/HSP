# Conformance

The Rust conformance harness is the black-box compatibility entrypoint for:

- canonicalization and CID vectors
- auth and replay behavior
- gateway/native parity
- encrypted storage profile checks
- path authorization edge cases
- S3-like compatibility smoke:
  - `ListObjectsV2`
  - `CopyObject`
  - `DeleteObjects`
  - multipart create/upload/complete/abort
  - replication smoke
- CDN read-path coverage:
  - immutable CID delivery
  - mutable bucket/key delivery
  - `HEAD`
  - `Range`
  - namespace cache invalidation after rebinding
- adversarial negative matrix:
  - SigV4 header canonicalization edge cases
  - presign duplicate-parameter rejection
  - tenant cache isolation
  - stale namespace binding protection
