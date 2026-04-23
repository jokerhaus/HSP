# Contributing

## Ground Rules

- Use ADRs for transport, cryptography, authorization, CID, or gateway parity
  changes.
- Do not widen the public MVP beyond the documented scope.
- Any change touching canonicalization, CID rules, token claims, or encrypted
  storage requires updated golden vectors and tests.

## Local Checks

```bash
./scripts/bootstrap-local.sh
```

## Code Style

- Rust: safe Rust by default, keep `unsafe` forbidden at the workspace level.
- Go: keep SDK and CLI typed, explicit, and wire-compatible with the spec.
- Docs: prefer normative language (`MUST`, `SHOULD`, `MAY`) for protocol text.
