# Credential Briefcase dev tasks.
#
# `just` is optional; CI does not depend on it. Install: https://github.com/casey/just

set dotenv-load := true

default:
  @just --list

ci:
  @just rust-ci
  @just node-ci

rust-ci:
  PATH="$HOME/.cargo/bin:$PATH" cargo fmt --all -- --check
  PATH="$HOME/.cargo/bin:$PATH" cargo clippy --all-targets --all-features -- -D warnings
  PATH="$HOME/.cargo/bin:$PATH" cargo test --all

node-ci:
  # No-op if the monorepo has no Node workspace yet.
  @if [ -f package.json ]; then \
    corepack enable; \
    pnpm install --frozen-lockfile; \
    pnpm -r gen; \
    git diff --exit-code; \
    pnpm -r lint; \
    pnpm -r test; \
  else \
    echo "node-ci: skipped (no package.json)"; \
  fi

gen:
  @if [ -f package.json ]; then \
    corepack enable; \
    pnpm install --frozen-lockfile; \
    pnpm -r gen; \
  else \
    echo "gen: skipped (no package.json)"; \
  fi

# PKCS#11 / SoftHSM integration tests (Linux container).
test-pkcs11:
  docker build -f docker/softhsm/Dockerfile -t credential-briefcase-softhsm .
  docker run --rm -v {{invocation_directory()}}:/workspace -w /workspace credential-briefcase-softhsm bash docker/softhsm/run-tests.sh

# TPM2 / swtpm integration tests (Linux container).
test-tpm2:
  docker build -f docker/swtpm/Dockerfile -t credential-briefcase-swtpm .
  docker run --rm -v {{invocation_directory()}}:/workspace -w /workspace credential-briefcase-swtpm bash docker/swtpm/run-tests.sh

# x402 v2 (stablecoin) integration harness.
test-x402:
  docker build -f docker/x402-harness/Dockerfile -t credential-briefcase-x402 .
  docker run --rm -v {{invocation_directory()}}:/workspace -w /workspace credential-briefcase-x402 bash docker/x402-harness/run-tests.sh

# L402 (Lightning) regtest harness.
test-lightning:
  bash docker/lightning-regtest/run-tests.sh all

test-l402-lnd:
  bash docker/lightning-regtest/run-tests.sh lnd

test-l402-cln:
  bash docker/lightning-regtest/run-tests.sh cln

# Enterprise control plane (Postgres) e2e harness.
test-enterprise:
  bash docker/enterprise/run-tests.sh
