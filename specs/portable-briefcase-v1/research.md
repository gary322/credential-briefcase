---
spec: portable-briefcase-v1
phase: research
created: 2026-02-06T10:02:10+00:00
---

# Research: portable-briefcase-v1

## Goal

Ship v1 credential briefcase per the repo architecture docs (secrets, OAuth, VC, payments rails, UI)

## Executive summary

- Feasibility: **High** (for a local-first reference implementation with demo OAuth/VC/payment rails).
- Key constraints:
  - The **LLM is untrusted**: no raw secrets must be exposed to the agent runtime or logged.
  - Local-first: daemon should be **local-only by default** (Unix socket on Unix) and protect all APIs with a local auth token.
  - CI quality bar from day one: `cargo fmt`, `clippy -D warnings`, tests, cross-platform builds.
  - Rust toolchain pinned (`rust-toolchain.toml`): avoid deps that require a newer MSRV.
- Risks:
  - OAuth onboarding UX + redirect flows are easy to get subtly wrong; v1 uses a demo provider + CLI-based PKCE loopback.
  - "Real" x402/L402 integrations are ecosystem-moving targets; v1 keeps them as reference/demo rails behind stable interfaces.
  - Keyring availability differs across Linux distros/CI; provide encrypted-file fallback and an explicit memory backend for tests/dev.

## Codebase scan

### Relevant existing components

- `apps/briefcased` — daemon: policy/budget enforcement, approvals, connector runtime, receipts.
- `apps/mcp-gateway` — single agent-facing tool surface (stdio JSON-RPC subset).
- `apps/briefcase-cli` — trusted admin client for onboarding/approvals/receipts.
- `apps/briefcase-ui` — local UI proxy (approvals/receipts/provider status).
- `apps/agent-access-gateway` — provider reference: OAuth + VC + payments + capability issuance.
- `crates/briefcase-secrets` — secret store abstraction (keyring/file/memory) used by the daemon.
- `crates/briefcase-policy` — Cedar policy wrapper; decisions are authoritative.
- `crates/briefcase-receipts` — hash-chained receipts in SQLite with `verify_chain()`.

### Patterns to follow

- Daemon API design: `apps/briefcased/src/app.rs` uses typed request/response structs in `crates/briefcase-api`.
- Storage: SQLite via `tokio-rusqlite` (`apps/briefcased/src/db.rs`) with `CREATE TABLE IF NOT EXISTS` migrations.
- Safe output shaping: tool-level JSON Schema validation + output firewall allowlist (`apps/briefcased/src/tools.rs`).

### Gaps / missing pieces

- Multi-provider registry + dynamic tools/connectors (v1 currently ships a demo provider + fixed tools).
- Strong isolation (egress allowlists, sandboxing) and risk scoring (classifier) are planned; v1 includes strict validation and approval/budget gates.
- PoP/DPoP binding for capabilities is planned; v1 uses bearer JWTs for clarity.
- Real x402/L402 integrations are not implemented; v1 provides a demo challenge/proof architecture.

## External research (optional)

- `docs/ARCHITECTURE.md` — end-to-end architecture and security invariants.

## Open questions

- Should v1 standardize a VC format (JWT-VC vs SD-JWT VC) or keep the entitlement as a provider-defined JWT profile?
- Should the daemon support remote MCP server routing in v1, or ship that as v1.1 behind a connector plugin interface?
- What is the expected packaging/distribution target (Homebrew, Winget, Docker, etc) for first release?

## Sources

- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
