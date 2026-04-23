# HSP CDN Purge Failure Runbook

## Symptoms

- stale namespace content served after `namespace.bound/unbound/tombstoned`.
- purge worker cursor not advancing.
- repeated `cursor_expired` / `invalid_cursor`.

## Immediate Actions

1. Confirm tenant-scoped impact and affected namespace paths.
2. Force short TTL mode for namespace routes.
3. Trigger manual purge for affected keys.

## Diagnostic Steps

- Verify event stream health:
  - `SUBSCRIBE` path available
  - replay window still includes last checkpoint
- Inspect cursor store:
  - per-tenant cursor present
  - cursor parse/decode succeeds
- Validate cache key isolation:
  - no cross-tenant key collisions

## Recovery

1. If cursor is stale:
   - drop tenant cursor
   - restart worker from current tail
2. If replay gap detected:
   - trigger tenant-wide namespace invalidation
   - rebuild cache via fresh origin reads
3. If worker backpressure:
   - scale purge workers
   - cap hot-key refresh concurrency

## Preventive Controls

- Monitor purge queue depth and cursor age.
- Alert when namespace invalidation latency exceeds threshold.
- Periodically run namespace mutation replay drills.
