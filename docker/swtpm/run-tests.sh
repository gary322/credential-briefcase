#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/tmp/swtpm-state"
mkdir -p "${STATE_DIR}"

# Start a software TPM over TCP so `tpm2-tools` can connect via a simple TCTI string.
swtpm socket \
  --tpm2 \
  --tpmstate "dir=${STATE_DIR}" \
  --ctrl "type=tcp,port=2322" \
  --server "type=tcp,port=2321" \
  --flags "not-need-init,startup-clear" &
SWTPM_PID="$!"

cleanup() {
  if [[ -n "${SWTPM_PID:-}" ]]; then
    kill "${SWTPM_PID}" >/dev/null 2>&1 || true
    wait "${SWTPM_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

TCTI="swtpm:port=2321"
export TPM2TOOLS_TCTI="${TCTI}"
export BRIEFCASE_TPM2_TCTI="${TCTI}"

# swtpm can take a moment to accept connections in CI; block until tpm2-tools can talk to it.
for _ in $(seq 1 50); do
  if tpm2_getcap properties-fixed >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
tpm2_getcap properties-fixed >/dev/null

cargo test -p briefcase-keys --features tpm2
