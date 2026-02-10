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
  scripts/check_ga_signoff.sh <SIGNOFF_FILE>

Fails if the sign-off file is missing or still contains placeholders.
EOF
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

FILE="$1"
if [[ ! -f "${FILE}" ]]; then
  echo "ERROR: missing sign-off file: ${FILE}" >&2
  exit 1
fi

if command -v rg >/dev/null 2>&1; then
  has_placeholder() { rg -n -F -q "$1" "${FILE}"; }
else
  has_placeholder() { grep -n -F -q "$1" "${FILE}"; }
fi

if has_placeholder "REPLACE_ME_"; then
  echo "ERROR: ${FILE} contains REPLACE_ME placeholders; fill in names/dates/artifacts before tagging" >&2
  exit 1
fi

echo "ok: sign-off file appears filled: ${FILE}"
