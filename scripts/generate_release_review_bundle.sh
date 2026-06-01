#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
OUT_DIR="${1:-$ROOT_DIR/artifacts/release-review/$TIMESTAMP}"
LATEST_LINK="$ROOT_DIR/artifacts/release-review/latest"
LOG_FILE="$OUT_DIR/driver.log"

mkdir -p "$OUT_DIR"

log() {
  printf '[hsp-release] %s\n' "$*" | tee -a "$LOG_FILE"
}

run_step() {
  local name="$1"
  shift
  log "running ${name}"
  (
    cd "$ROOT_DIR"
    "$@"
  ) 2>&1 | tee "$OUT_DIR/${name}.log"
}

run_shell_step() {
  local name="$1"
  local script="$2"
  log "running ${name}"
  (
    cd "$ROOT_DIR"
    bash -lc "$script"
  ) 2>&1 | tee "$OUT_DIR/${name}.log"
}

ensure_govulncheck() {
  GOVULNCHECK_BIN="$(go env GOPATH)/bin/govulncheck"
  if [[ ! -x "$GOVULNCHECK_BIN" ]]; then
    run_shell_step "install-govulncheck" \
      'GOTOOLCHAIN=go1.25.10+auto go install golang.org/x/vuln/cmd/govulncheck@latest'
  fi
  GOVULNCHECK_BIN="$(go env GOPATH)/bin/govulncheck"
}

ensure_syft() {
  if command -v syft >/dev/null 2>&1; then
    SYFT_BIN="$(command -v syft)"
    return 0
  fi
  if [[ -x "$ROOT_DIR/bin/syft" ]]; then
    SYFT_BIN="$ROOT_DIR/bin/syft"
    return 0
  fi

  mkdir -p "$ROOT_DIR/bin"
  run_shell_step "install-syft" \
    "curl -sSfL https://get.anchore.io/syft | sh -s -- -b \"$ROOT_DIR/bin\""
  SYFT_BIN="$ROOT_DIR/bin/syft"
}

write_summary() {
  local out_dir="$1"
  python3 - "$out_dir" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
report = json.loads((out_dir / "hsp-conformance-report.json").read_text())

def bool_at(*path):
    node = report
    for key in path:
        node = node[key]
    return bool(node)

def get_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=out_dir.parents[2],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"

summary = {
    "generated_at": subprocess.check_output(["date", "-Iseconds"], text=True).strip(),
    "git_commit": get_commit(),
    "artifacts": {
        "cargo_test": "cargo-test.log",
        "cargo_clippy": "cargo-clippy.log",
        "cargo_audit": "cargo-audit.log",
        "go_test_sdk": "go-test-sdk.log",
        "go_test_cli": "go-test-cli.log",
        "govulncheck_sdk": "govulncheck-sdk.log",
        "govulncheck_cli": "govulncheck-cli.log",
        "conformance_json": "hsp-conformance-report.json",
        "sbom_spdx_json": "hsp-source.spdx.json",
    },
    "checks": report.get("checks", {}),
    "distribution_negative": report.get("distribution_negative", {}),
    "distribution_timings_ms": report.get("distribution_timings_ms", {}),
}
(out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

lines = [
    "# External Review Request Bundle",
    "",
    f"- Generated at: `{summary['generated_at']}`",
    f"- Git commit: `{summary['git_commit']}`",
    "",
    "## Included artifacts",
    "",
    "- `cargo-test.log`",
    "- `cargo-clippy.log`",
    "- `cargo-audit.log`",
    "- `go-test-sdk.log`",
    "- `go-test-cli.log`",
    "- `govulncheck-sdk.log`",
    "- `govulncheck-cli.log`",
    "- `hsp-conformance-report.json`",
    "- `hsp-source.spdx.json`",
    "- `summary.json`",
    "",
    "## Conformance highlights",
    "",
]
for key, value in sorted(report.get("checks", {}).items()):
    lines.append(f"- `{key}`: `{value}`")
lines.extend(
    [
        "",
        "## Distribution timings (ms)",
        "",
    ]
)
for key, value in sorted(report.get("distribution_timings_ms", {}).items()):
    lines.append(f"- `{key}`: `{value}`")
lines.extend(
    [
        "",
        "## Remaining human-only step",
        "",
        "- Owner-operated deployments may proceed after internal sign-off; independent external review remains recommended for third-party/public SaaS exposure.",
    ]
)
(out_dir / "external-review-request.md").write_text("\n".join(lines) + "\n")
PY
}

log "output directory: $OUT_DIR"

ensure_govulncheck
ensure_syft
export ROOT_DIR OUT_DIR GOVULNCHECK_BIN SYFT_BIN

run_step "cargo-fmt-check" cargo fmt --check
run_shell_step "go-work-sync" 'GOTOOLCHAIN=go1.25.10+auto go work sync'
run_step "cargo-test" cargo test --workspace --all-targets
run_step "cargo-clippy" cargo clippy --workspace --all-targets -- -D warnings
run_shell_step "cargo-audit" \
  'env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo audit'
run_shell_step "go-test-sdk" \
  'cd sdk/go && GOTOOLCHAIN=go1.25.10+auto go test ./...'
run_shell_step "go-test-cli" \
  'cd cli/hspctl && GOTOOLCHAIN=go1.25.10+auto go test ./...'
run_shell_step "govulncheck-sdk" \
  "cd sdk/go && \"$GOVULNCHECK_BIN\" ./..."
run_shell_step "govulncheck-cli" \
  "cd cli/hspctl && \"$GOVULNCHECK_BIN\" ./..."

log "running hsp-conformance"
(
  cd "$ROOT_DIR"
  cargo run -p hsp-conformance > "$OUT_DIR/hsp-conformance-report.json"
) 2>&1 | tee "$OUT_DIR/hsp-conformance.log"

log "generating SPDX SBOM with syft"
(
  cd "$ROOT_DIR"
  "$SYFT_BIN" "dir:$ROOT_DIR" \
    --exclude '**/target/**' \
    --exclude '**/artifacts/**' \
    --exclude '**/.git/**' \
    --exclude '**/bin/**' \
    -o "spdx-json=$OUT_DIR/hsp-source.spdx.json"
) 2>&1 | tee "$OUT_DIR/syft-sbom.log"

write_summary "$OUT_DIR"

mkdir -p "$(dirname "$LATEST_LINK")"
rm -f "$LATEST_LINK"
ln -s "$OUT_DIR" "$LATEST_LINK"

ARCHIVE_PATH="${OUT_DIR}.tar.gz"
log "packaging review bundle"
tar -C "$(dirname "$OUT_DIR")" -czf "$ARCHIVE_PATH" "$(basename "$OUT_DIR")"

log "bundle ready at $OUT_DIR"
log "latest symlink updated: $LATEST_LINK"
log "archive ready at $ARCHIVE_PATH"
