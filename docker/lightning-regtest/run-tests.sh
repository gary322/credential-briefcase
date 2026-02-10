#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/docker/lightning-regtest/docker-compose.yml"
PROJECT="agentic-auth-lightning"
MODE="${1:-all}"
WAIT_SECS="${WAIT_SECS:-240}"

DEFAULT_PROJECT_DIR="$ROOT/docker/lightning-regtest"
if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${CI:-}" = "true" ]; then
  # Keep Unix domain socket paths short (CLN JSON-RPC) to avoid `SUN_LEN` limits.
  PROJECT_DIR="${BRIEFCASE_LIGHTNING_PROJECT_DIR:-/tmp/agentic-auth-lightning}"
else
  PROJECT_DIR="${BRIEFCASE_LIGHTNING_PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
fi
DATA_DIR="$PROJECT_DIR/.data"

# Prefer rustup-managed toolchains when available (avoids PATH picking up a
# system-installed Rust).
export PATH="$HOME/.cargo/bin:$PATH"

case "$MODE" in
  all|lnd|cln) ;;
  *)
    echo "usage: $0 [all|lnd|cln]" >&2
    exit 2
    ;;
esac

# NOTE: Core Lightning's JSON-RPC is a Unix domain socket. When running the regtest nodes
# inside Docker Desktop on macOS, that socket is not reachable from the host filesystem, so the
# CLN backend integration test cannot run. We still run the LND backend locally on macOS and keep
# the full `all` mode for Linux CI.
if [ "$(uname -s)" = "Darwin" ]; then
  if [ "$MODE" = "all" ]; then
    echo "Darwin detected: CLN unix RPC sockets in Docker Desktop are not reachable from the host; running LND-only." >&2
    MODE="lnd"
  elif [ "$MODE" = "cln" ]; then
    echo "Darwin detected: skipping CLN mode (requires Linux/unix socket reachability)." >&2
    exit 0
  fi
fi

dc() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --project-directory "$PROJECT_DIR" "$@"
}

cleanup() {
  if [ "${KEEP_STACK:-}" = "1" ]; then
    echo "KEEP_STACK=1: leaving regtest stack running" >&2
    return 0
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$PROJECT_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/bitcoin" \
  "$DATA_DIR/lnd-alice" \
  "$DATA_DIR/lnd-bob" \
  "$DATA_DIR/cln-carol/bitcoin/regtest" \
  "$DATA_DIR/cln-dave/bitcoin/regtest"

dc up -d

wait_for() {
  local desc="$1"
  shift

  for _ in $(seq 1 "$WAIT_SECS"); do
    # Run in a subshell with errexit disabled so a failing probe never aborts
    # the harness (we want retries instead).
    if ( set +e; "$@" >/dev/null 2>&1 ); then
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for: $desc" >&2
  dc ps >&2 || true
  dc logs --no-color --tail=200 >&2 || true
  return 1
}

BITCOIN_CLI=(dc exec -T bitcoind bitcoin-cli -datadir=/data -regtest -rpcuser=rpcuser -rpcpassword=rpcpass)

wait_for "bitcoind rpc" "${BITCOIN_CLI[@]}" getblockchaininfo

wait_for "lnd-alice rpc" dc exec -T lnd-alice lncli --network=regtest getinfo
wait_for "lnd-bob rpc" dc exec -T lnd-bob lncli --network=regtest getinfo

wait_for "cln-carol rpc" dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc getinfo
wait_for "cln-dave rpc" dc exec -T cln-dave lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc getinfo

# Initialize miner wallet and mature coinbase.
${BITCOIN_CLI[@]} createwallet miner >/dev/null 2>&1 || true
MINER_ADDR="$(${BITCOIN_CLI[@]} -rpcwallet=miner getnewaddress | tr -d '\r')"
${BITCOIN_CLI[@]} -rpcwallet=miner generatetoaddress 110 "$MINER_ADDR" >/dev/null

wait_for "lnd-alice synced" bash -lc 'docker compose -p agentic-auth-lightning -f "'"$COMPOSE_FILE"'" exec -T lnd-alice lncli --network=regtest getinfo | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get(\"synced_to_chain\") else 1)"'
wait_for "lnd-bob synced" bash -lc 'docker compose -p agentic-auth-lightning -f "'"$COMPOSE_FILE"'" exec -T lnd-bob lncli --network=regtest getinfo | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get(\"synced_to_chain\") else 1)"'

wait_for "lnd-alice macaroon" dc exec -T lnd-alice sh -lc 'test -f /root/.lnd/data/chain/bitcoin/regtest/admin.macaroon'
wait_for "lnd-bob macaroon" dc exec -T lnd-bob sh -lc 'test -f /root/.lnd/data/chain/bitcoin/regtest/admin.macaroon'

# The LND containers create `tls.cert` and macaroons as root with restrictive
# permissions. The integration tests read these files from the host-mounted
# volume, so ensure they are readable in CI.
dc exec -T --user root lnd-alice sh -lc 'chmod a+rx /root/.lnd || true; chmod a+r /root/.lnd/tls.cert || true; chmod -R a+rX /root/.lnd/data || true'
dc exec -T --user root lnd-bob sh -lc 'chmod a+rx /root/.lnd || true; chmod a+r /root/.lnd/tls.cert || true; chmod -R a+rX /root/.lnd/data || true'

cln_carol_synced() {
  dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc getinfo | python3 -c 'import json,sys; obj=json.load(sys.stdin); sys.exit(0 if not obj.get("warning_bitcoind_sync") else 1)'
}
cln_dave_synced() {
  dc exec -T cln-dave lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc getinfo | python3 -c 'import json,sys; obj=json.load(sys.stdin); sys.exit(0 if not obj.get("warning_bitcoind_sync") else 1)'
}
cln_carol_funded() {
  dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc listfunds | python3 -c 'import json,sys; obj=json.load(sys.stdin); outs=obj.get("outputs", []); ok=any(o.get("status") == "confirmed" for o in outs); sys.exit(0 if ok else 1)'
}
wait_for "cln-carol synced" cln_carol_synced
wait_for "cln-dave synced" cln_dave_synced

wait_for "lnd-alice newaddress" dc exec -T lnd-alice lncli --network=regtest newaddress p2wkh
wait_for "lnd-bob newaddress" dc exec -T lnd-bob lncli --network=regtest newaddress p2wkh
wait_for "cln-carol newaddr" dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc newaddr
wait_for "cln-dave newaddr" dc exec -T cln-dave lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc newaddr

json_get() {
  local key="$1"
  python3 -c 'import json,sys,functools; key=sys.argv[1]; obj=json.load(sys.stdin); cur=functools.reduce(lambda c,p: c[p], key.split("."), obj); print(cur)' "$key"
}

retry_json_field() {
  local desc="$1"
  local key="$2"
  shift 2

  local last_out=""
  for _ in $(seq 1 "$WAIT_SECS"); do
    # Capture stdout (expected JSON) but keep stderr visible for debugging.
    last_out="$("$@" || true)"
    if v="$(printf '%s' "$last_out" | json_get "$key" 2>/dev/null | tr -d '\r')"; then
      if [ -n "$v" ]; then
        echo "$v"
        return 0
      fi
    fi
    sleep 1
  done

  echo "timeout waiting for: $desc" >&2
  if [ -n "$last_out" ]; then
    echo "$last_out" >&2
  fi
  return 1
}

# Fund node wallets.
ALICE_ADDR="$(retry_json_field "lnd-alice address" address dc exec -T lnd-alice lncli --network=regtest newaddress p2wkh)"
BOB_ADDR="$(retry_json_field "lnd-bob address" address dc exec -T lnd-bob lncli --network=regtest newaddress p2wkh)"
CAROL_ADDR="$(retry_json_field "cln-carol address" bech32 dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc newaddr)"
DAVE_ADDR="$(retry_json_field "cln-dave address" bech32 dc exec -T cln-dave lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc newaddr)"

${BITCOIN_CLI[@]} -rpcwallet=miner sendtoaddress "$ALICE_ADDR" 1 >/dev/null
${BITCOIN_CLI[@]} -rpcwallet=miner sendtoaddress "$BOB_ADDR" 1 >/dev/null
${BITCOIN_CLI[@]} -rpcwallet=miner sendtoaddress "$CAROL_ADDR" 1 >/dev/null
${BITCOIN_CLI[@]} -rpcwallet=miner sendtoaddress "$DAVE_ADDR" 1 >/dev/null
${BITCOIN_CLI[@]} -rpcwallet=miner generatetoaddress 6 "$MINER_ADDR" >/dev/null

wait_for "cln-carol synced (post-funding)" cln_carol_synced
wait_for "cln-dave synced (post-funding)" cln_dave_synced
wait_for "cln-carol funded" cln_carol_funded

# LND channel: alice -> bob.
BOB_PUB="$(retry_json_field "lnd-bob pubkey" identity_pubkey dc exec -T lnd-bob lncli --network=regtest getinfo)"
dc exec -T lnd-alice lncli --network=regtest connect "${BOB_PUB}@lnd-bob:9735" >/dev/null 2>&1 || true
dc exec -T lnd-alice lncli --network=regtest openchannel --node_key="$BOB_PUB" --local_amt=200000 --sat_per_vbyte=1
${BITCOIN_CLI[@]} -rpcwallet=miner generatetoaddress 6 "$MINER_ADDR" >/dev/null
lnd_channel_active() {
  dc exec -T lnd-alice lncli --network=regtest listchannels | python3 -c 'import json,sys; obj=json.load(sys.stdin); chs=obj.get("channels", []); sys.exit(0 if any(c.get("active") is True for c in chs) else 1)'
}
wait_for "lnd channel active" lnd_channel_active

# CLN channel: carol -> dave.
DAVE_PUB="$(retry_json_field "cln-dave pubkey" id dc exec -T cln-dave lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc getinfo)"
dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc connect "$DAVE_PUB" cln-dave 9735 >/dev/null 2>&1 || true
dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc fundchannel "$DAVE_PUB" 200000
${BITCOIN_CLI[@]} -rpcwallet=miner generatetoaddress 6 "$MINER_ADDR" >/dev/null
cln_channel_active() {
  # CLN v24+ no longer includes channel state in `listpeers` by default.
  dc exec -T cln-carol lightning-cli --network=regtest --lightning-dir=/root/.lightning --rpc-file=/root/.lightning/lightning-rpc listpeerchannels "$DAVE_PUB" | python3 -c 'import json,sys; obj=json.load(sys.stdin); ok=any(ch.get("state") == "CHANNELD_NORMAL" for ch in obj.get("channels", [])); sys.exit(0 if ok else 1)'
}
wait_for "cln channel active" cln_channel_active

# Build helper with Lightning features and run the L402 tests.
export CARGO_TARGET_DIR="/tmp/agentic-auth-lightning-target"
export RUST_TEST_THREADS=1

HELPER_FEATURES="l402-lnd,l402-cln"
if [ "$MODE" = "lnd" ]; then
  HELPER_FEATURES="l402-lnd"
elif [ "$MODE" = "cln" ]; then
  HELPER_FEATURES="l402-cln"
fi

(cd "$ROOT" && cargo build -p briefcase-payment-helper --features "$HELPER_FEATURES")
export BRIEFCASE_TEST_PAYMENT_HELPER="$CARGO_TARGET_DIR/debug/briefcase-payment-helper"

export BRIEFCASE_TEST_LND_PAYER_GRPC_ENDPOINT="https://localhost:10009"
export BRIEFCASE_TEST_LND_PAYER_TLS_CERT_FILE="$DATA_DIR/lnd-alice/tls.cert"
export BRIEFCASE_TEST_LND_PAYER_MACAROON_FILE="$DATA_DIR/lnd-alice/data/chain/bitcoin/regtest/admin.macaroon"

export BRIEFCASE_TEST_LND_PAYEE_GRPC_ENDPOINT="https://localhost:11009"
export BRIEFCASE_TEST_LND_PAYEE_TLS_CERT_FILE="$DATA_DIR/lnd-bob/tls.cert"
export BRIEFCASE_TEST_LND_PAYEE_MACAROON_FILE="$DATA_DIR/lnd-bob/data/chain/bitcoin/regtest/admin.macaroon"

export BRIEFCASE_TEST_CLN_PAYER_RPC_SOCKET="$DATA_DIR/cln-carol/lightning-rpc"
export BRIEFCASE_TEST_CLN_PAYEE_RPC_SOCKET="$DATA_DIR/cln-dave/lightning-rpc"

case "$MODE" in
  all)
    (cd "$ROOT" && cargo test -p briefcased --features l402-lnd,l402-cln l402_)
    ;;
  lnd)
    (cd "$ROOT" && cargo test -p briefcased --features l402-lnd l402_lnd_)
    ;;
  cln)
    (cd "$ROOT" && cargo test -p briefcased --features l402-cln l402_cln_)
    ;;
esac
