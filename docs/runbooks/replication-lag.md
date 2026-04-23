# HSP Replication Lag Runbook

## Symptoms

- `replication-status` shows stale `last_run_ms`.
- `failed_objects` increasing.
- destination bucket missing recent objects.

## Fast Checks

1. Validate replication config exists and is enabled.
2. Confirm source/destination bucket ACL and policy alignment.
3. Check worker health and queue depth.
4. Verify KMS and encrypted-store latency budget.

## Mitigation

- If lag is moderate:
  - increase replication worker parallelism
  - reduce batch size for hot tenants
- If lag is critical:
  - prioritize affected tenant prefixes
  - temporarily disable low-priority lifecycle transitions
  - throttle non-essential copy operations

## Recovery Workflow

1. Snapshot current replication cursor/checkpoint.
2. Run targeted replay by source bucket + prefix.
3. Validate copied object count and error decline.
4. Compare source/destination list checksums.

## Failure Modes

- `replication_failed`:
  - inspect latest error code/category
  - retry with backoff
  - quarantine poison paths after threshold
- `replication_lagging`:
  - emit alert if lag exceeds SLO window
  - escalate to SEV-2 when tenant-visible

## Exit Criteria

- Lag below agreed threshold for 3 consecutive windows.
- No growth in `failed_objects`.
- Conformance parity checks pass for affected bucket pair.
