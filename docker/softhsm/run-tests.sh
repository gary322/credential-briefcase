#!/usr/bin/env bash
set -euo pipefail

TOKENDIR="/tmp/softhsm-tokens"
CONF="/tmp/softhsm2.conf"

mkdir -p "${TOKENDIR}"
echo "directories.tokendir = ${TOKENDIR}" > "${CONF}"

export SOFTHSM2_CONF="${CONF}"

TOKEN_LABEL="Briefcase Test"
SO_PIN="0000"
USER_PIN="1234"

softhsm2-util --init-token --free --label "${TOKEN_LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}"

MODULE=""
for p in \
  "/usr/lib/softhsm/libsofthsm2.so" \
  "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" \
  "/usr/local/lib/softhsm/libsofthsm2.so" \
  ; do
  if [ -f "${p}" ]; then
    MODULE="${p}"
    break
  fi
done

if [ -z "${MODULE}" ]; then
  echo "SoftHSM PKCS#11 module not found" >&2
  exit 1
fi

export BRIEFCASE_PKCS11_MODULE="${MODULE}"
export BRIEFCASE_PKCS11_TOKEN_LABEL="${TOKEN_LABEL}"
export BRIEFCASE_PKCS11_USER_PIN="${USER_PIN}"

cargo test -p briefcase-keys --features pkcs11
cargo test -p briefcase-control-plane --features pkcs11
