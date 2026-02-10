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
  scripts/security_review_packet.sh --label LABEL [--dist-dir DIR] [--out FILE]

Builds a single tarball for external reviewers containing:
  - release evidence artifacts (if present in dist/)
  - GA qualification + security assessment bundles
  - key docs (threat model, profile, releasing, ops)

This script does not run tests; run `scripts/ga_qualification.sh --mode release` first.
EOF
}

DIST_DIR="dist"
LABEL=""
OUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist-dir)
      DIST_DIR="$2"
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --out)
      OUT_FILE="$2"
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

if [[ -z "${LABEL}" ]]; then
  echo "ERROR: missing --label" >&2
  usage >&2
  exit 2
fi

if [[ -z "${OUT_FILE}" ]]; then
  OUT_FILE="${DIST_DIR}/security-review-packet-${LABEL}.tar.gz"
fi

mkdir -p "${DIST_DIR}"

declare -a include=()

add_if_exists() {
  local p="$1"
  if [[ -f "${p}" ]]; then
    include+=("${p}")
  fi
}

# Evidence artifacts (best-effort; may not exist in local dev).
add_if_exists "${DIST_DIR}/release-manifest-${LABEL}.json"
add_if_exists "${DIST_DIR}/sbom-${LABEL}.spdx.json"
add_if_exists "${DIST_DIR}/provider-contract-${LABEL}.json"
add_if_exists "${DIST_DIR}/security-assessment-${LABEL}.tar.gz"
add_if_exists "${DIST_DIR}/ga-qualification-${LABEL}.json"
add_if_exists "${DIST_DIR}/ga-qualification-${LABEL}.tar.gz"
add_if_exists "${DIST_DIR}/SHA256SUMS.txt"

# Key docs for reviewers.
add_if_exists "SECURITY.md"
add_if_exists "docs/RELEASING.md"
add_if_exists "docs/COMPATIBILITY_PROFILE.md"
add_if_exists "docs/SUPPORT_MATRIX.md"
add_if_exists "docs/THREAT_MODEL.md"
add_if_exists "docs/OPERATIONS.md"
add_if_exists "docs/ARCHITECTURE.md"
add_if_exists "docs/POLICY.md"

if [[ "${LABEL}" == "v1.0.0" ]]; then
  add_if_exists "docs/GA_SIGNOFF_v1.0.0.md"
fi

if [[ ${#include[@]} -eq 0 ]]; then
  echo "ERROR: nothing to package (dist dir is empty?)" >&2
  echo "hint: run: bash scripts/ga_qualification.sh --mode release --label ${LABEL}" >&2
  exit 1
fi

tar -czf "${OUT_FILE}" "${include[@]}"
echo "ok: wrote ${OUT_FILE}"
