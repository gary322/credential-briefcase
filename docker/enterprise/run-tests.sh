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

echo "[enterprise] setting policy..."
curl -fsS \
  -H "authorization: Bearer ${ADMIN_TOKEN}" \
  -H "content-type: application/json" \
  -d '{"policy_text":"permit(principal, action, resource);","budgets":{"read":3000000,"write":0,"admin":0}}' \
  "${BASE_URL}/v1/admin/policy" >/tmp/enterprise-policy.json

echo "[enterprise] enrolling device..."
DEVICE_ID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
curl -fsS \
  -H "authorization: Bearer ${ADMIN_TOKEN}" \
  -H "content-type: application/json" \
  -d "{\"device_id\":\"${DEVICE_ID}\",\"device_name\":\"ci-device\",\"device_pubkey_b64\":\"AA\"}" \
  "${BASE_URL}/v1/admin/devices/enroll" >/tmp/enterprise-enroll.json

DEVICE_TOKEN="$(python3 - <<'PY'
import json
with open("/tmp/enterprise-enroll.json","r",encoding="utf-8") as f:
  v=json.load(f)
print(v["device_token"])
PY
)"

echo "[enterprise] fetching policy as device..."
curl -fsS \
  -H "authorization: Bearer ${DEVICE_TOKEN}" \
  "${BASE_URL}/v1/devices/${DEVICE_ID}/policy" >/tmp/enterprise-policy-device.json

echo "[enterprise] uploading receipts..."
python3 - <<'PY' >/tmp/enterprise-receipts.json
import hashlib, json, datetime

def sha256_hex_concat(a: str, b: bytes) -> str:
  h = hashlib.sha256()
  h.update(a.encode("utf-8"))
  h.update(b)
  return h.hexdigest()

prev = "0"*64
receipts = []
for rid in [1,2]:
  event = {"kind":"tool_call","tool_id":"echo","decision":"allow","cost_usd":0.0}
  # Compact JSON, stable key order.
  event_json = json.dumps(event, separators=(",",":"), ensure_ascii=False)
  h = sha256_hex_concat(prev, event_json.encode("utf-8"))
  ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z")
  receipts.append({
    "id": rid,
    "ts": ts,
    "prev_hash_hex": prev,
    "hash_hex": h,
    "event": event,
  })
  prev = h

print(json.dumps({"receipts": receipts}, separators=(",",":"), ensure_ascii=False))
PY

curl -fsS \
  -H "authorization: Bearer ${DEVICE_TOKEN}" \
  -H "content-type: application/json" \
  --data-binary @/tmp/enterprise-receipts.json \
  "${BASE_URL}/v1/devices/${DEVICE_ID}/receipts" >/tmp/enterprise-upload.json

echo "[enterprise] auditing receipts..."
curl -fsS \
  -H "authorization: Bearer ${AUDITOR_TOKEN}" \
  "${BASE_URL}/v1/audit/receipts?device_id=${DEVICE_ID}&limit=10&offset=0" >/tmp/enterprise-audit.json

python3 - <<'PY'
import json
with open("/tmp/enterprise-audit.json","r",encoding="utf-8") as f:
  v=json.load(f)
assert isinstance(v.get("receipts"), list)
assert len(v["receipts"]) >= 2
print("[enterprise] ok")
PY
