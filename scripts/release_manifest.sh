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
  scripts/release_manifest.sh [--dist-dir DIR] [--out FILE]
  scripts/release_manifest.sh --verify MANIFEST.json [--dist-dir DIR]

Generates or verifies a machine-readable release evidence manifest.

Defaults:
  --dist-dir dist
  --out      dist/release-manifest.json
EOF
}

DIST_DIR="dist"
OUT_FILE=""
VERIFY_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist-dir)
      DIST_DIR="$2"
      shift 2
      ;;
    --out)
      OUT_FILE="$2"
      shift 2
      ;;
    --verify)
      VERIFY_FILE="$2"
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

if [[ -z "${OUT_FILE}" ]]; then
  OUT_FILE="${DIST_DIR}/release-manifest.json"
fi

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
    return 0
  fi
  python3 - "$f" <<'PY'
import hashlib
from pathlib import Path
import sys
p = Path(sys.argv[1])
h = hashlib.sha256()
with p.open("rb") as fp:
    for chunk in iter(lambda: fp.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PY
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

if [[ -n "${VERIFY_FILE}" ]]; then
  if [[ ! -f "${VERIFY_FILE}" ]]; then
    echo "ERROR: missing manifest: ${VERIFY_FILE}" >&2
    exit 1
  fi

  while IFS=$'\t' read -r rel want; do
    [[ -z "${rel}" ]] && continue
    if [[ ! -f "${DIST_DIR}/${rel}" ]]; then
      echo "ERROR: missing artifact: ${DIST_DIR}/${rel}" >&2
      exit 1
    fi
    got="$(sha256_file "${DIST_DIR}/${rel}")"
    if [[ "${got}" != "${want}" ]]; then
      echo "ERROR: sha256 mismatch for ${rel}: want=${want} got=${got}" >&2
      exit 1
    fi
  done < <(python3 - "$VERIFY_FILE" <<'PY'
import json
from pathlib import Path
import sys
m = json.loads(Path(sys.argv[1]).read_text())
for a in m.get("artifacts", []):
    p = a.get("path")
    h = a.get("sha256")
    if p and h:
        print(f"{p}\t{h}")
PY
  )

  echo "ok: verified ${VERIFY_FILE}"
  exit 0
fi

mkdir -p "${DIST_DIR}"

GIT_SHA="unknown"
if command -v git >/dev/null 2>&1; then
  GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
fi

RUST_VERSION="$(
  python3 - <<'PY'
import re
from pathlib import Path
lines = Path("Cargo.toml").read_text().splitlines()
in_section = False
for line in lines:
    if line.strip() == "[workspace.package]":
        in_section = True
        continue
    if in_section and line.strip().startswith("[") and line.strip().endswith("]"):
        break
    if in_section:
        m = re.match(r'\s*version\s*=\s*"([^"]+)"\s*$', line)
        if m:
            print(m.group(1))
            raise SystemExit(0)
raise SystemExit("could not find [workspace.package].version in Cargo.toml")
PY
)"

NODE_VERSION="$(
  python3 - <<'PY'
import json
from pathlib import Path
print(json.loads(Path("package.json").read_text())["version"])
PY
)"

PROFILE="$(profile_id)"

# If the output file is inside DIST_DIR, avoid self-referential hashing by excluding it.
OUT_REL=""
if [[ "${OUT_FILE}" == "${DIST_DIR}/"* ]]; then
  OUT_REL="${OUT_FILE#${DIST_DIR}/}"
fi

# Build manifest JSON using bash for portability.
{
  echo "{"
  echo "  \"generated_at_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"git_sha\": \"${GIT_SHA}\","
  echo "  \"version\": {"
  echo "    \"rust\": \"${RUST_VERSION}\","
  echo "    \"node\": \"${NODE_VERSION}\""
  echo "  },"
  echo "  \"compatibility_profile\": \"${PROFILE}\","
  echo "  \"artifacts\": ["
  first=1
  while IFS= read -r rel; do
    [[ -z "$rel" ]] && continue
    if [[ -n "${OUT_REL}" && "${rel}" == "${OUT_REL}" ]]; then
      continue
    fi
    sha="$(sha256_file "${DIST_DIR}/${rel}")"
    if [[ $first -eq 0 ]]; then
      echo "    ,"
    fi
    first=0
    echo "    {\"path\": \"${rel}\", \"sha256\": \"${sha}\"}"
  done < <(cd "${DIST_DIR}" && find . -maxdepth 2 -type f | sed 's#^./##' | LC_ALL=C sort)
  echo ""
  echo "  ]"
  echo "}"
} >"${OUT_FILE}"

echo "wrote ${OUT_FILE}"
