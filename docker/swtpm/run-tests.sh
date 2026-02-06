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
  --flags "not-need-init,startup-clear" \
  --daemon

TCTI="swtpm:port=2321"
export TPM2TOOLS_TCTI="${TCTI}"
export BRIEFCASE_TPM2_TCTI="${TCTI}"

cargo test -p briefcase-keys --features tpm2
