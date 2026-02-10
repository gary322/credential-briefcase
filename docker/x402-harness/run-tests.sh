#!/usr/bin/env bash
set -euo pipefail

# Deterministic x402 v2 harness:
# - builds the payment helper
# - runs the briefcased integration test that exercises PAYMENT-REQUIRED/PAYMENT-SIGNATURE headers

# Use an isolated target dir so local runs on non-Linux hosts don't get confused by mixed artifacts.
export CARGO_TARGET_DIR="/tmp/agentic-auth-target"

cargo build -p briefcase-payment-helper

export BRIEFCASE_TEST_PAYMENT_HELPER="${CARGO_TARGET_DIR}/debug/briefcase-payment-helper"

# Deterministic dev key (do NOT use in production).
export BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX="0000000000000000000000000000000000000000000000000000000000000001"

cargo test -p briefcased x402_v2_token_mint_via_helper
