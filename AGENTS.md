# Agent Instructions (Repository Local)

This repo implements an **agentic auth ("credential briefcase")** system where the **LLM/agent runtime is untrusted** and must never receive raw secrets.

## Hard Rules

- Do not print/log/store raw secrets:
  - OAuth refresh tokens, access tokens
  - capability tokens
  - private key seeds
  - payment proofs or Lightning preimages
- Prefer using `briefcase_core::Sensitive<T>` for values that could be accidentally logged.
- Keep the trust boundary explicit:
  - `briefcased` owns secrets/keys/payments/policy/audit.
  - `mcp-gateway` is the only agent-facing MCP surface.
  - CLI/UI are admin surfaces; they must not proxy secrets back to the agent.

## Quality Gates (Required)

Before declaring work “done”, ensure all of these pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Security Checklist (When Modifying Network/Tools)

- Any new outbound HTTP must be:
  - deny-by-default and explicitly allowed by config/policy
  - redirect-disabled
  - HTTPS-only unless loopback/localhost
- Any new tool must:
  - define strict JSON Schema input validation
  - have an explicit output firewall strategy
  - be categorized (`read`/`write`/`admin`) so policy/budgets apply
- If you touch capability tokens:
  - preserve PoP binding and replay defenses in the reference gateway
  - update `docs/CAPABILITY_TOKENS.md` and add tests

## Payments

Payments are abstracted behind `crates/briefcase-payments`:

- The default backend is a demo HTTP flow for local testing.
- Production integration should use the command helper backend (`BRIEFCASE_PAYMENT_HELPER`).

## Risk Scoring

Risk scoring is **non-authoritative**:

- It may require approval.
- It must never override allow/deny policy decisions.
