# Security Policy

## Supported Security Baseline

The repository targets the `public multi-tenant` profile as the default release
baseline. Security-sensitive changes must preserve:

- TLS 1.3 over QUIC for native transport
- mandatory encryption at rest for all persisted stores
- mandatory client-side encryption for object data in the public profile
- channel-bound authorization for public deployments
- replay protection on mutation operations
- segment-aware path authorization
- auditable namespace mutation proofs

## Reporting

Until a public disclosure address is provisioned, treat this repository as
private-security-review only. Do not publish exploit details in public issues.

Required artifacts before public release:

- threat model
- dependency review
- SPDX JSON SBOM
- `cargo audit` report
- `govulncheck` reports for `sdk/go` and `cli/hspctl`
- `hsp-conformance` JSON report
- black-box negative corpus report for native/gateway/s3/cdn parity
- drill evidence bundle under `docs/release-evidence/`
- fuzzing report
- static analysis output
- independent security review

Mandatory security gates for release candidates:

- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo audit`
- `GOTOOLCHAIN=go1.25.11+auto go work sync`
- `go test ./sdk/go/... ./cli/hspctl/...`
- `govulncheck ./...` in `sdk/go` and `cli/hspctl`
- `cargo run -p hsp-conformance`
