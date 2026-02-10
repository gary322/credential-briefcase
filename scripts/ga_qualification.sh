#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  pwd
)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  scripts/ga_qualification.sh [--mode ci|release] [--dist-dir DIR] [--label LABEL] [--aag-addr ADDR]

Creates GA qualification evidence artifacts under dist/:

  - provider-contract-<label>.json
  - security-assessment-<label>.tar.gz              (release mode only)
  - ga-qualification-<label>.tar.gz                 (logs + metadata)
  - ga-qualification-<label>.json                   (summary)

Notes:
  - This script treats secrets as sensitive and avoids printing them.
  - Provider contract is executed against a locally started agent-access-gateway.
EOF
}

MODE="ci"
DIST_DIR="dist"
LABEL=""
AAG_ADDR="127.0.0.1:19099"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --dist-dir)
      DIST_DIR="$2"
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --aag-addr)
      AAG_ADDR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${MODE}" in
  ci|release) ;;
  *)
    echo "invalid --mode: ${MODE} (expected ci|release)" >&2
    exit 2
    ;;
esac

sanitize_label() {
  # Keep artifact paths stable and safe across filesystems and CI.
  # Only allow: A-Z a-z 0-9 . _ -
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | tr -s '_' | sed 's/^_\\+//; s/_\\+$//'
}

git_sha_short() {
  if command -v git >/dev/null 2>&1; then
    git rev-parse --short HEAD 2>/dev/null || echo unknown
    return 0
  fi
  echo unknown
}

timestamp_utc() {
  date -u +%Y%m%dT%H%M%SZ
}

pick_cargo() {
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    echo "${HOME}/.cargo/bin/cargo"
    return 0
  fi
  echo "cargo"
}

profile_id() {
  python3 - <<'PY'
import re
from pathlib import Path

txt = Path("crates/briefcase-core/src/types.rs").read_text()
m = re.search(r'COMPATIBILITY_PROFILE_VERSION:\s*&str\s*=\s*"([^"]+)"', txt)
if not m:
    raise SystemExit("could not find COMPATIBILITY_PROFILE_VERSION")
print(m.group(1))
PY
}

if [[ -z "${LABEL}" ]]; then
  if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
    LABEL="${GITHUB_REF_NAME}"
  else
    LABEL="local-$(timestamp_utc)-$(git_sha_short)"
  fi
fi
LABEL="$(sanitize_label "${LABEL}")"

mkdir -p "${DIST_DIR}"

OUT_DIR="${DIST_DIR}/ga-qualification-${LABEL}"
LOG_DIR="${OUT_DIR}/logs"
mkdir -p "${LOG_DIR}"

CARGO_BIN="$(pick_cargo)"

CURRENT_STEP=""
FAILED_STEP=""
FAILED_EXIT_CODE=""
AAG_PID=""

set_step() {
  local name="$1"
  CURRENT_STEP="${name}"
  echo "${CURRENT_STEP}" >"${OUT_DIR}/current_step.txt"
  echo "step: ${name}"
}

run_and_capture() {
  local name="$1"
  shift

  set_step "${name}"

  # Store a reproducible command line without secrets (secrets are passed via env).
  printf '%q ' "$@" >"${LOG_DIR}/${name}.cmd"
  echo >>"${LOG_DIR}/${name}.cmd"

  if "$@" >"${LOG_DIR}/${name}.out" 2>&1; then
    return 0
  else
    local ec="$?"
    FAILED_STEP="${name}"
    FAILED_EXIT_CODE="${ec}"
    echo "${FAILED_STEP}" >"${OUT_DIR}/failed_step.txt"
    echo "${FAILED_EXIT_CODE}" >"${OUT_DIR}/failed_exit_code.txt"
    echo "ERROR: step ${name} failed (exit ${ec}); see ${LOG_DIR}/${name}.out" >&2
    return "${ec}"
  fi
}

wait_for_health() {
  local url="$1"
  # CI runners can take a while to compile the provider gateway before it starts responding.
  local tries="${2:-240}"
  for _ in $(seq 1 "${tries}"); do
    if curl -fsS --connect-timeout 2 --max-time 3 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup_gateway() {
  if [[ -n "${AAG_PID}" ]]; then
    kill "${AAG_PID}" >/dev/null 2>&1 || true
    wait "${AAG_PID}" >/dev/null 2>&1 || true
  fi
}

emit_evidence_bundle() {
  local exit_code="$1"

  # Record failure context for humans without printing sensitive outputs.
  if [[ "${exit_code}" != "0" ]]; then
    {
      echo "exit_code=${exit_code}"
      if [[ -n "${FAILED_STEP}" ]]; then
        echo "failed_step=${FAILED_STEP}"
      elif [[ -n "${CURRENT_STEP}" ]]; then
        echo "failed_step=${CURRENT_STEP}"
      fi
    } >>"${OUT_DIR}/meta.txt" 2>/dev/null || true
  fi

  # Package logs/metadata into a single evidence bundle, even on failures.
  tar -C "${DIST_DIR}" -czf "${DIST_DIR}/ga-qualification-${LABEL}.tar.gz" "$(basename "${OUT_DIR}")" >/dev/null 2>&1 || true

  # Emit a machine-readable summary alongside the detailed evidence tarball.
  if command -v python3 >/dev/null 2>&1; then
    python3 - "${DIST_DIR}" "${DIST_DIR}/ga-qualification-${LABEL}.json" <<'PY' || true
import json
from pathlib import Path
import sys

dist = Path(sys.argv[1])
out = Path(sys.argv[2])
label = out.stem.removeprefix("ga-qualification-")

compat = None
try:
    txt = Path("crates/briefcase-core/src/types.rs").read_text()
    import re
    m = re.search(r'COMPATIBILITY_PROFILE_VERSION:\s*&str\s*=\s*"([^"]+)"', txt)
    compat = m.group(1) if m else None
except Exception:
    compat = None

meta_path = dist / f"ga-qualification-{label}" / "meta.txt"
meta = {}
if meta_path.exists():
    for line in meta_path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            meta[k.strip()] = v.strip()

failed_step = None
failed_step_path = dist / f"ga-qualification-{label}" / "failed_step.txt"
if failed_step_path.exists():
    failed_step = failed_step_path.read_text().strip() or None

exit_code = None
exit_code_path = dist / f"ga-qualification-{label}" / "failed_exit_code.txt"
if exit_code_path.exists():
    try:
        exit_code = int(exit_code_path.read_text().strip())
    except Exception:
        exit_code = None

artifacts = []
for p in [
    dist / f"provider-contract-{label}.json",
    dist / f"security-assessment-{label}.tar.gz",
    dist / f"ga-qualification-{label}.tar.gz",
]:
    if p.exists():
        artifacts.append(str(p.relative_to(dist)))

doc = {
    "label": label,
    "mode": meta.get("mode"),
    "generated_at_utc": meta.get("timestamp_utc"),
    "git_sha_short": meta.get("git_sha_short"),
    "compatibility_profile": compat,
    # Defensive: treat any recorded failed_step as a failure, even if exit_code parsing went sideways.
    "status": "failed" if (failed_step is not None) or (exit_code not in (None, 0)) else "ok",
    "failed_step": failed_step,
    "exit_code": exit_code,
    "artifacts": artifacts,
}
out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
  fi

  if [[ "${exit_code}" == "0" ]]; then
    echo "ok: wrote ${DIST_DIR}/ga-qualification-${LABEL}.json"
    echo "ok: wrote ${DIST_DIR}/ga-qualification-${LABEL}.tar.gz"
  else
    echo "error: wrote ${DIST_DIR}/ga-qualification-${LABEL}.json"
    echo "error: wrote ${DIST_DIR}/ga-qualification-${LABEL}.tar.gz"
  fi
}

on_exit() {
  local ec="$?"
  trap - EXIT
  set +e
  cleanup_gateway
  emit_evidence_bundle "${ec}"
  exit "${ec}"
}
trap on_exit EXIT

{
  echo "timestamp_utc=$(timestamp_utc)"
  echo "git_sha_short=$(git_sha_short)"
  echo "mode=${MODE}"
  echo "compatibility_profile=$(profile_id)"
  echo "uname=$(uname -a || true)"
  echo "cargo=$("${CARGO_BIN}" --version 2>/dev/null || true)"
  echo "rustc=$(rustc --version 2>/dev/null || true)"
  echo "node=$(node --version 2>/dev/null || true)"
  echo "pnpm=$(pnpm --version 2>/dev/null || true)"
} >"${OUT_DIR}/meta.txt"

# Always run doc/support matrix validation (fast, required).
run_and_capture validate_support_matrix bash scripts/validate_support_matrix.sh

# Always run doc-vs-code profile drift guard (fast, required).
run_and_capture docs_profile_consistency "${CARGO_BIN}" test -p briefcase-core --test docs_profile_consistency

# Provider gateway conformance (machine-readable compatibility report).
#
# Avoid passing secrets in command line args; use env vars instead.
#
# NOTE: For CI/release this uses a fixed local address; override via --aag-addr if needed.
AAG_BASE_URL="http://${AAG_ADDR}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

{
  echo "starting local agent-access-gateway at ${AAG_BASE_URL}"
  # Build first to avoid the health check racing a cold `cargo run` compile on CI runners.
  run_and_capture agent_access_gateway_build "${CARGO_BIN}" build -p agent-access-gateway

  AAG_BIN="${TARGET_DIR}/debug/agent-access-gateway"
  if [[ ! -x "${AAG_BIN}" ]]; then
    echo "ERROR: expected agent-access-gateway binary at ${AAG_BIN}" >&2
    exit 1
  fi

  # "test-secret" is used only for local conformance and is not printed elsewhere.
  set_step agent_access_gateway_run
  AAG_SECRET="test-secret" \
    RUST_LOG="info,hyper=warn,reqwest=warn" \
    "${AAG_BIN}" --addr "${AAG_ADDR}" \
    >"${LOG_DIR}/agent-access-gateway.out" 2>&1 &
  AAG_PID="$!"

  set_step agent_access_gateway_health
  if ! wait_for_health "${AAG_BASE_URL}/health"; then
    echo "agent-access-gateway failed health check; see ${LOG_DIR}/agent-access-gateway.out" >&2
    exit 1
  fi
} >"${LOG_DIR}/provider_contract_bootstrap.out" 2>&1

PROVIDER_REPORT="${DIST_DIR}/provider-contract-${LABEL}.json"
set_step provider_contract
PROVIDER_ADMIN_SECRET="test-secret" \
  PROVIDER_BASE_URL="${AAG_BASE_URL}" \
  "${CARGO_BIN}" run -q -p briefcase-conformance --bin provider-contract -- --base-url "${AAG_BASE_URL}" --run-revocation \
  1>"${PROVIDER_REPORT}" \
  2>"${LOG_DIR}/provider-contract.err"

# Shut down the gateway now (avoid hanging the script on background tasks).
cleanup_gateway
AAG_PID=""

if [[ "${MODE}" == "release" ]]; then
  # For the final GA tag, require an explicit, named sign-off record.
  if [[ "${LABEL}" == "v1.0.0" ]]; then
    run_and_capture ga_signoff_check bash scripts/check_ga_signoff.sh docs/GA_SIGNOFF_v1.0.0.md
  fi

  # Produce a reproducible bundle for external security review.
  #
  # This intentionally captures full stdout/stderr output into an artifact tarball.
  run_and_capture security_assessment bash scripts/run_security_assessment.sh

  # Rename the newest security-assessment tarball to a stable, label-based name.
  set_step security_assessment_rename
  SECURITY_TAR=""
  if command -v python3 >/dev/null 2>&1; then
    SECURITY_TAR="$(
      python3 - <<'PY'
import glob
import os
from pathlib import Path

paths = [Path(p) for p in glob.glob("dist/security-assessment-*.tar.gz")]
if not paths:
    raise SystemExit("")
paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
print(paths[0])
PY
    )"
  fi

  if [[ -z "${SECURITY_TAR}" || ! -f "${SECURITY_TAR}" ]]; then
    echo "ERROR: missing dist/security-assessment-*.tar.gz output from run_security_assessment.sh" >&2
    exit 1
  fi

  mv "${SECURITY_TAR}" "${DIST_DIR}/security-assessment-${LABEL}.tar.gz"

  # Full suite harnesses (docker-based).
  run_and_capture enterprise_e2e bash docker/enterprise/run-tests.sh
  run_and_capture x402_harness bash docker/x402-harness/run-tests.sh
  run_and_capture lightning_harness bash docker/lightning-regtest/run-tests.sh all

  # Hardware-custody contract harnesses (docker-based).
  #
  # In CI we prefer host-installed dependencies to avoid pulling a full Rust toolchain image,
  # which can exceed runner disk limits. Locally, Docker remains a convenient fallback.
  if [[ "$(uname)" == "Linux" ]] && command -v softhsm2-util >/dev/null 2>&1; then
    run_and_capture pkcs11_tests bash docker/softhsm/run-tests.sh
  else
    run_and_capture pkcs11_build docker build -f docker/softhsm/Dockerfile -t agentic-auth-softhsm .
    run_and_capture pkcs11_tests docker run --rm -v "${ROOT_DIR}:/workspace" -w /workspace agentic-auth-softhsm bash docker/softhsm/run-tests.sh
  fi

  if [[ "$(uname)" == "Linux" ]] && command -v swtpm >/dev/null 2>&1 && command -v tpm2_getcap >/dev/null 2>&1; then
    run_and_capture tpm2_tests bash docker/swtpm/run-tests.sh
  else
    run_and_capture tpm2_build docker build -f docker/swtpm/Dockerfile -t agentic-auth-swtpm .
    run_and_capture tpm2_tests docker run --rm -v "${ROOT_DIR}:/workspace" -w /workspace agentic-auth-swtpm bash docker/swtpm/run-tests.sh
  fi

  # Browser extension E2E (Playwright).
  #
  # This is intentionally kept in the release qualification path so tags are gated on it.
  if command -v pnpm >/dev/null 2>&1; then
    run_and_capture extension_build pnpm -C apps/briefcase-extension build
    run_and_capture extension_playwright_install pnpm -C apps/briefcase-extension exec playwright install --with-deps chromium
    run_and_capture extension_e2e pnpm -C apps/briefcase-extension test:e2e
  else
    echo "WARNING: pnpm missing; skipping extension e2e" >"${LOG_DIR}/extension_e2e.skip"
  fi
fi

# Evidence bundle + summary are produced by the EXIT trap (success or failure).
