#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  pwd
)"

cd "$ROOT_DIR"

if command -v git >/dev/null 2>&1; then
  GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
else
  GIT_SHA="unknown"
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="dist/security-assessment-${TS}-${GIT_SHA}"
mkdir -p "${OUT_DIR}/logs"

pick_cargo() {
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    echo "${HOME}/.cargo/bin/cargo"
    return 0
  fi
  echo "cargo"
}

CARGO_BIN="$(pick_cargo)"

run_and_capture() {
  local name="$1"
  shift
  echo "running: $*" >"${OUT_DIR}/logs/${name}.cmd"
  # Capture stdout/stderr to an artifact for external review.
  "$@" >"${OUT_DIR}/logs/${name}.out" 2>&1
}

{
  echo "timestamp_utc=${TS}"
  echo "git_sha_short=${GIT_SHA}"
  echo "uname=$(uname -a || true)"
  echo "node=$(node --version 2>/dev/null || true)"
  echo "pnpm=$(pnpm --version 2>/dev/null || true)"
  echo "cargo=$("${CARGO_BIN}" --version 2>/dev/null || true)"
  echo "rustc=$(rustc --version 2>/dev/null || true)"
} >"${OUT_DIR}/meta.txt"

run_and_capture rust_fmt "${CARGO_BIN}" fmt --all -- --check
run_and_capture rust_clippy "${CARGO_BIN}" clippy --all-targets --all-features -- -D warnings
run_and_capture rust_test "${CARGO_BIN}" test --all

if command -v pnpm >/dev/null 2>&1; then
  run_and_capture node_gen pnpm -r gen
  run_and_capture node_lint pnpm -r lint
  run_and_capture node_test pnpm -r test
fi

tar -C dist -czf "${OUT_DIR}.tar.gz" "$(basename "${OUT_DIR}")"
echo "wrote ${OUT_DIR}.tar.gz"
