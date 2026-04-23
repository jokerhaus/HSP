# HSP Key Recovery And Rewrap Runbook

## Scope

Recovery and rotation for:

- envelope keys for persisted stores
- wrapped object keys used by trusted-edge flows
- issuer signing keys for capability validation

## Preconditions

- Incident ticket and approved change window.
- Backup of encrypted stores and event journal.
- Confirmed access to workload identity and AWS KMS permissions.

## Recovery Modes

## 1) KMS key alias migration

1. Provision new KMS key and alias.
2. Update service config:
   - `HSP_AWS_KMS_KEY_ALIAS`
   - `HSP_AWS_KMS_REGION`
   - `HSP_AWS_KMS_RUNTIME=live-cli`
3. Restart one canary instance for each service.
4. Validate encrypted read/write roundtrip.
5. Roll out to full fleet.

## 2) Envelope rewrap (store records)

1. Pause lifecycle/replication workers.
2. Run rewrap batch per store kind and tenant partition:
   - read envelope
   - decrypt with old key
   - encrypt with new key
   - write atomically
3. Record per-batch checkpoints.
4. Resume workers and verify tail consistency.

## 3) Issuer key compromise

1. Remove compromised key from issuer registry.
2. Publish new key id and rotate token minting.
3. Invalidate active presign/edge tokens where required.
4. Confirm failed validation for old tokens and success for new tokens.

## Rollback

- If rewrap errors exceed threshold:
  - stop job
  - restore last successful checkpoint
  - switch services to previous alias
- Never partially re-enable write traffic without checkpoint integrity confirmation.

## Evidence

Capture in incident artifact bundle:

- alias/version before and after
- tenant/store batch checkpoints
- failure samples and resolution
- post-recovery conformance and smoke results
