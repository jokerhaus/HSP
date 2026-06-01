# External Review

## Status

- Repository-side preparation: complete
- Current local handoff bundle: `artifacts/release-review/latest`
- Independent external security sign-off: not performed
- Owner-operated internal sign-off: complete for first-party deployments; see
  [owner-security-signoff.md](/Users/loxar/Documents/GitHub/HSP/docs/release-evidence/owner-security-signoff.md)

## Tracking Workflow

- Open a review ticket from
  [.github/ISSUE_TEMPLATE/security-review.md](/Users/loxar/Documents/GitHub/HSP/.github/ISSUE_TEMPLATE/security-review.md)
- Generate the handoff bundle with:

```bash
./scripts/generate_release_review_bundle.sh
```

- Attach:
  - SBOM artifact
  - `cargo audit` report
  - `govulncheck` reports
  - `hsp-conformance` JSON report
  - release-evidence bundle

## Required Review Scope

- SigV4 and presign canonicalization
- CDN cache poisoning resistance and tenant isolation
- `trusted-edge-v1` controls
- AWS KMS provider usage model
- encrypted persisted stores and recovery posture

## Completion Criteria

- no open `P0` or `P1` findings
- every `P2+` finding is either fixed or explicitly accepted with owner and
  rationale
- README, SECURITY, and release status docs are updated after review closure

## Final GA Gate

Owner-operated `production 100%` is tracked in
[owner-security-signoff.md](/Users/loxar/Documents/GitHub/HSP/docs/release-evidence/owner-security-signoff.md).
Independent third-party/public SaaS GA still requires this document to be
updated with reviewer identity, date, scope, findings summary, and disposition.
