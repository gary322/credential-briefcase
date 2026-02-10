#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  pwd
)"
cd "$ROOT_DIR"

if command -v rg >/dev/null 2>&1; then
  search() { rg -F -q "$1" "$2"; }
else
  search() { grep -F -q "$1" "$2"; }
fi

PROFILE="$(
  python3 - <<'PY'
import re
from pathlib import Path

txt = Path("crates/briefcase-core/src/types.rs").read_text()
m = re.search(r'COMPATIBILITY_PROFILE_VERSION:\s*&str\s*=\s*"([^"]+)"', txt)
if not m:
    raise SystemExit("could not find COMPATIBILITY_PROFILE_VERSION in crates/briefcase-core/src/types.rs")
print(m.group(1))
PY
)"

for f in docs/SUPPORT_MATRIX.md docs/COMPATIBILITY_PROFILE.md docs/RELEASING.md; do
  if ! search "${PROFILE}" "$f"; then
    echo "ERROR: ${f} does not mention current profile id: ${PROFILE}" >&2
    exit 1
  fi
done

for f in docs/OPERATIONS.md; do
  for s in scripts/run_security_assessment.sh scripts/validate_support_matrix.sh scripts/release_manifest.sh; do
    if ! search "$(basename "$s")" "$f"; then
      echo "ERROR: ${f} does not reference $(basename "$s")" >&2
      exit 1
    fi
    if [[ ! -f "$s" ]]; then
      echo "ERROR: missing script referenced by docs: $s" >&2
      exit 1
    fi
  done
done

if ! search "/v1/diagnostics/security:" openapi/briefcased.yaml; then
  echo "ERROR: openapi/briefcased.yaml missing /v1/diagnostics/security path" >&2
  exit 1
fi

echo "ok: profile=${PROFILE}"
