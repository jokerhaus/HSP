# Compatibility Matrix

## Evidence Source

- Primary source: `cargo run -p hsp-conformance`
- Date: `2026-04-23`

## Surface Coverage

| Surface | Operation set | Status | Evidence |
| --- | --- | --- | --- |
| Native HSP | `SETTINGS`, `INFO`, `PUT_INIT`, `PUT_CHUNK`, `PUT_COMMIT`, namespace `GET`, `LIST`, `SUBSCRIBE` | pass | conformance `native` + top-level `checks` |
| HTTP/3 gateway | `INFO`, namespace `HEAD/GET`, `LIST`, events | pass | conformance `gateway` + top-level `checks` |
| S3-like | `CreateBucket`, `PutObject`, `GetObject`, `HeadObject`, `Get/PutObjectAcl`, `ListObjectsV2`, `CopyObject`, `DeleteObjects`, multipart lifecycle, `replication-run` | pass | conformance `distribution_compatibility` + `distribution.checks` |
| CDN | bucket/key `GET/HEAD`, immutable CID `GET`, `Range`, tenant cache isolation, namespace rebind invalidation | pass | conformance `distribution_negative` + `distribution.checks` |

## Adversarial Matrix

| Scenario | Expected outcome | Status |
| --- | --- | --- |
| stale SigV4 `X-Amz-Date` | `invalid_sigv4` | pass |
| future SigV4 `X-Amz-Date` | `invalid_sigv4` | pass |
| mismatched credential-scope date | `invalid_sigv4` | pass |
| unsorted `SignedHeaders` | `invalid_sigv4` | pass |
| missing `host` in `SignedHeaders` | `invalid_sigv4` | pass |
| duplicate signed header | `invalid_sigv4` | pass |
| duplicate presign query parameter | `invalid_presign` | pass |
| tenant cache isolation | no cached cross-tenant reuse | pass |
| CDN range read | `206` with `Content-Range` | pass |
| stale namespace binding after rebind | first read after invalidation is `MISS` and returns fresh ciphertext | pass |
| repeated near-expiry presign replay | valid ciphertext delivery inside allowed window | pass |

## Measured Local Benchmarks

- `replication_run`: `23 ms`
- `cdn_namespace_rebind_visibility`: `1626 ms`
- `presign_near_expiry_roundtrip`: `17 ms`

## Remaining Acceptance Work

- parity should be re-run in CI artifacts for every release candidate
- operator environments still need their own evidence for latency, queue depth,
  and restart behavior under realistic tenant load
