#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="deploy/docker-compose.enterprise.yml"

ADMIN_TOKEN="admin-test-token"
AUDITOR_TOKEN="auditor-test-token"
SIGNING_SEED_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

DB_URL="postgres://briefcase:briefcase@127.0.0.1:54329/briefcase_control_plane"
BASE_URL="http://127.0.0.1:9797"

CP_PID=""

cleanup() {
  if [ -n "${CP_PID}" ]; then
    kill "${CP_PID}" >/dev/null 2>&1 || true
    wait "${CP_PID}" >/dev/null 2>&1 || true
  fi
  docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[enterprise] starting postgres..."
docker compose -f "${COMPOSE_FILE}" up -d postgres

echo "[enterprise] waiting for postgres..."
for i in $(seq 1 60); do
  if docker compose -f "${COMPOSE_FILE}" exec -T postgres pg_isready -U briefcase -d briefcase_control_plane >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[enterprise] building control plane..."
PATH="$HOME/.cargo/bin:$PATH" cargo build -p briefcase-control-plane

echo "[enterprise] starting control plane..."
export CONTROL_PLANE_BIND_ADDR="127.0.0.1:9797"
export CONTROL_PLANE_PUBLIC_BASE_URL="${BASE_URL}"
export CONTROL_PLANE_DATABASE_URL="${DB_URL}"
export CONTROL_PLANE_ADMIN_TOKEN="${ADMIN_TOKEN}"
export CONTROL_PLANE_AUDITOR_TOKEN="${AUDITOR_TOKEN}"
export CONTROL_PLANE_POLICY_SIGNING_KEY_SEED_B64="${SIGNING_SEED_B64}"

./target/debug/briefcase-control-plane >/tmp/briefcase-control-plane.log 2>&1 &
CP_PID="$!"

echo "[enterprise] waiting for control plane health..."
HEALTH_OK="0"
for i in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    HEALTH_OK="1"
    break
  fi
  sleep 1
done
if [ "${HEALTH_OK}" != "1" ]; then
  echo "[enterprise] control plane failed to become healthy"
  tail -n 200 /tmp/briefcase-control-plane.log || true
  exit 1
fi

echo "[enterprise] running device enrollment + DPoP sync harness..."
PATH="$HOME/.cargo/bin:$PATH" cargo run -p briefcase-conformance --bin enterprise-control-plane-harness -- --base-url "${BASE_URL}"
