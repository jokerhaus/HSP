# Runbook Drills

## Scope

This bundle records local engineering rehearsals performed on `2026-06-01`.
These are valid release-evidence inputs for the repository pass, but they are
not a substitute for operator-attested drills in staging or production.

The local drill bundle can be regenerated with:

```bash
./scripts/generate_release_review_bundle.sh
```

## 1. Key Recovery / Rewrap

- Date: `2026-06-01`
- Build scope: current local workspace
- Start/stop: covered by `cargo test --workspace --all-targets`
- Steps:
  - ran crypto regression suite including
    `rewrap_store_envelope_preserves_plaintext`
  - verified rewrapped envelope still decrypts to original plaintext and uses
    fresh wrapping/data nonces
- Result: pass
- Gaps:
  - no live AWS KMS alias migration or rollback drill in deployment
- Corrective action:
  - execute runbook from [key-recovery.md](/Users/loxar/Documents/GitHub/HSP/docs/runbooks/key-recovery.md)
    in staging with operator timing capture before GA

## 2. Incident Response

- Date: `2026-06-01`
- Build scope: current local workspace
- Start/stop: documentation walkthrough only
- Steps:
  - reviewed [incident-response.md](/Users/loxar/Documents/GitHub/HSP/docs/runbooks/incident-response.md)
  - confirmed security gates and conformance commands referenced by the runbook
    are executable in the current repository state
- Result: documentation-ready, deployment drill recommended
- Gaps:
  - no timed live incident exercise with roles, containment, rollback, and
    comms artifacts
- Corrective action:
  - run a staging SEV-2 drill and attach the timeline, containment actions, and
    parity verification outputs

## 3. Replication Lag Handling

- Date: `2026-06-01`
- Build scope: `cargo run -p hsp-conformance`
- Start/stop: captured by conformance timing
- Steps:
  - created source and destination buckets
  - uploaded source objects
  - applied replication config
  - executed `replication-run` smoke path
  - verified destination object parity
- Result: pass
- Measured recovery benchmark:
  - latest value is recorded in
    `artifacts/release-review/latest/summary.json` under
    `distribution_timings_ms.replication_run`
- Gaps:
  - no long-running worker lag simulation under sustained tenant load
- Corrective action:
  - run the [replication-lag.md](/Users/loxar/Documents/GitHub/HSP/docs/runbooks/replication-lag.md)
    drill with realistic backlog and queue-depth telemetry

## 4. CDN Purge Failure Recovery

- Date: `2026-06-01`
- Build scope: `cargo run -p hsp-conformance`
- Start/stop: captured by conformance timing
- Steps:
  - warmed namespace cache
  - rewrote the namespace target via S3-like PUT
  - waited for subscription-driven invalidation
  - confirmed next CDN read was `MISS` and returned fresh ciphertext
- Result: pass
- Measured recovery benchmark:
  - latest value is recorded in
    `artifacts/release-review/latest/summary.json` under
    `distribution_timings_ms.cdn_namespace_rebind_visibility`
- Gaps:
  - no multi-tenant purge-storm benchmark against deployed cache workers
- Corrective action:
  - run the [cdn-purge-failures.md](/Users/loxar/Documents/GitHub/HSP/docs/runbooks/cdn-purge-failures.md)
    drill with hot-key concurrency and cursor aging enabled

## 5. Restart / Encrypted Store Behavior

- Date: `2026-06-01`
- Build scope: Rust workspace tests and conformance
- Steps:
  - validated encrypted-store read/write paths and persisted object reads across
    service lifecycle in the existing Rust test suite
- Result: pass
- Gaps:
  - no deployment-level node restart drill with attached storage class timings
- Corrective action:
  - record restart timing and post-restart readiness in staging evidence
