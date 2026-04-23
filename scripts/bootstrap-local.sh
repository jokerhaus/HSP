#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[hsp] go test"
go test ./sdk/go/... ./cli/hspctl/...

if command -v cargo >/dev/null 2>&1 && cargo -V >/dev/null 2>&1; then
  echo "[hsp] cargo fmt --check"
  cargo fmt --check
  echo "[hsp] cargo clippy --workspace --all-targets -- -D warnings"
  cargo clippy --workspace --all-targets -- -D warnings
  echo "[hsp] cargo test --workspace"
  cargo test --workspace
else
  echo "[hsp] Rust toolchain unavailable; skipped Rust checks" >&2
fi
