# Owner-Operated Security Sign-Off

## Status

- Date: `2026-06-01`
- Scope: owner-operated HSP deployments used by the project owner in first-party projects
- Decision: accepted for owner-operated production use after local security gates and conformance pass
- Commit baseline: generated from the release branch merged into `main`

## What This Sign-Off Means

This is an internal owner sign-off, not an independent third-party audit. It is
intended for deployments where the project owner controls the applications,
operators, secrets, KMS configuration, network exposure, and incident response.

For this scope, the repository is considered release-ready when the mandatory
security gates pass and the operator follows the hardened deployment profile.

## Required Controls For Use

- `public` profile remains ciphertext-only.
- `trusted-edge-v1` remains opt-in per bucket or prefix and must not be enabled
  by default.
- Runtime secrets must be provided through workload identity or Kubernetes
  secrets, never hardcoded defaults.
- `HSP_KMS_SEED` and `HSP_EDGE_SIGNING_SECRET` must be unique per environment.
- All services that share encrypted storage must use the same storage KMS key
  domain.
- S3/CDN public access must use scoped capability, SigV4/presign, or edge-token
  policy; anonymous access is not the baseline.
- Release gates in `security-gates.md` must pass for the deployed commit.

## Accepted Residual Risk

- No independent external pentest has been performed.
- Cloud KMS live behavior still depends on the operator's AWS IAM and workload
  identity configuration.
- Performance and recovery timings from local conformance are not substitutes
  for staging or production capacity measurements.

## Not Approved By This Sign-Off

- Selling HSP as a third-party public storage SaaS without an independent
  security review.
- Enabling trusted-edge plaintext delivery for untrusted tenants without a
  separate review.
- Reusing development secrets or local-dev KMS material in production.

## Next Review Trigger

Repeat this sign-off before any release that changes auth, authorization,
SigV4/presign handling, KMS behavior, encryption formats, CDN cache keys,
trusted-edge plaintext delivery, or persisted storage layout.
