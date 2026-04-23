# HSP Incident Response Runbook

## Scope

This runbook covers production incidents on `hspd`, `hsp-gw`, `hsp-s3`, and `hsp-cdn`
for public multi-tenant deployments.

## Severity Levels

- `SEV-1`: tenant-wide outage, cross-tenant data risk, auth bypass suspicion.
- `SEV-2`: partial outage, elevated error rates, degraded upload/read path.
- `SEV-3`: non-critical regression with viable workaround.

## Immediate Actions (first 15 minutes)

1. Open incident channel and assign roles:
   - Incident Commander
   - Communications Lead
   - Investigation Lead
2. Freeze non-emergency deploys.
3. Confirm blast radius:
   - affected surfaces (`native`, `gateway`, `s3`, `cdn`)
   - affected tenants
   - first-seen timestamp and release version
4. Enable protective controls if needed:
   - tighten rate limits
   - disable `trusted-edge-v1` profile
   - temporarily disable presign minting

## Triage Checklist

- Control plane healthy: `INFO`, readiness, liveness.
- Auth path healthy:
  - token verification errors
  - SigV4/presign failures
  - replay cache pressure
- Storage path healthy:
  - encrypted store read/write failures
  - KMS latency/error spikes
  - event log append failures
- CDN path healthy:
  - cache poisoning indicators
  - purge backlog
  - hot-object amplification

## Containment Patterns

- Suspected auth bypass:
  - revoke affected issuer keys
  - disable presign and edge tokens for impacted tenants
  - force `public-ciphertext` access profile only
- Suspected data leak:
  - isolate impacted tenant partitions
  - disable cross-surface delivery for affected routes
  - preserve forensic logs and event snapshots
- KMS instability:
  - fail closed on mutation paths
  - preserve read-only access where policy allows

## Recovery

1. Apply mitigation patch or rollback.
2. Verify parity checks:
   - native/gateway/s3/cdn error semantics
   - metadata redaction guarantees
3. Re-enable features gradually:
   - tenant-by-tenant
   - with elevated monitoring windows

## Post-Incident

- Publish incident report within 24 hours:
  - trigger, blast radius, timeline, root cause
  - what worked / what failed
  - action items with owners and due dates
- Run regression set:
  - `cargo test --workspace --all-targets`
  - `go test ./...` in `sdk/go` and `cli/hspctl`
  - `cargo run -p hsp-conformance`
