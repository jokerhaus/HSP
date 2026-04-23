# HSP Product Overview

## Short Version

HSP is our own secure storage layer. It gives applications a way to store,
read, verify, and distribute files while keeping the public storage path
ciphertext-only.

Think of it as a storage system that combines ideas from:

- S3: buckets, object keys, uploads, downloads, listing
- CDN: fast edge delivery and cache behavior
- secure protocol design: encryption, signed mutations, replay protection,
  tenant isolation, and integrity checks

The main difference is that HSP is built around security and verification from
the start, instead of adding them later as separate wrappers.

## Why We Need It

An application like Ping should not have to download a whole file just to know
whether storage contains the right object. It should be able to ask HSP:

- does this object exist?
- how large is it?
- what is its ciphertext size?
- what is its integrity hash?
- which encryption profile was used?
- is this object deleted or tombstoned?

HSP now answers those questions directly through metadata APIs.

## What HSP Does

### Stores Objects

The application uploads encrypted bytes. HSP stores chunks and a manifest. The
manifest becomes the object identity.

Result:

- stable CID for the object
- chunk-level integrity
- encrypted persisted storage
- namespace or bucket/key lookup

### Verifies Objects Without Downloading

Instead of reading the full object, the application can request metadata:

```http
GET /v1/objects/namespace/media/photos/1.enc/metadata?tenant_id=tenant-alpha
```

Example response:

```json
{
  "exists": true,
  "deleted": false,
  "size_bytes": 1786060,
  "ciphertext_size_bytes": 1786200,
  "integrity_hash": "sha256-...",
  "cid": "sha256-...",
  "created_at_ms": 1776900000000,
  "encryption_profile_id": "ping-media-v1",
  "key_policy_id": "ping-media-default"
}
```

This is useful for migrations, health checks, upload confirmation, and backend
debugging.

### Serves Existing S3-Like Workflows

Tools that understand buckets and object keys can talk to `hsp-s3`. Internally,
HSP still maps bucket/key into tenant-aware namespaces and paths.

Example:

```bash
aws --endpoint-url http://localhost:8081 s3 cp ./video.enc s3://media/videos/1.enc
```

### Serves CDN-Like Download Paths

`hsp-cdn` can serve:

- immutable CID URLs for long cache lifetimes
- mutable bucket/key URLs for shorter TTL and purge-on-change behavior

The edge stays ciphertext-first in the public profile.

### Gives Operators Visibility

HSP exposes its own operational signals:

- `put`
- `get`
- `delete`
- `auth_denied`
- `kms_error`
- `integrity_error`
- latency
- object sizes
- tenant and namespace labels
- status code and outcome

Prometheus endpoint:

```http
GET /metrics
```

Structured logs endpoint:

```http
GET /v1/observability/logs
```

Both require admin capability scopes.

## What We Get When We Use HSP

- Cheaper verification: no full download just to check size/hash.
- Better security: ciphertext-first public storage path.
- Better isolation: tenant-aware keys, cache, paths, events, and metrics.
- Better debugging: HSP tells us what storage itself is doing.
- Better compatibility: S3-like surface for common tooling.
- Better distribution: CDN-like edge behavior tied to HSP events.
- Better control: protocol, auth, policy, and storage semantics are ours.

## What HSP Is Not

- It is not a full AWS S3 clone.
- It is not a generic CDN replacement.
- It does not serve plaintext in the public profile.
- It does not remove the need for external security review before strict
  production approval.

## Simple Mental Model

```text
Application
  -> encrypts file
  -> uploads ciphertext to HSP
  -> receives CID and metadata
  -> verifies object through HEAD/metadata
  -> serves downloads through HSP gateway, S3-like API, or CDN-like edge
```

HSP becomes the secure storage foundation. The application can focus on product
logic instead of rebuilding storage encryption, object verification, cache
purge, replay protection, and operational visibility by itself.
