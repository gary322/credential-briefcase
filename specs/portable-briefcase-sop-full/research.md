---
spec: portable-briefcase-sop-full
phase: research
created: 2026-02-06T13:58:08+00:00
---

# Research: portable-briefcase-sop-full

## Goal

Implement full sop.txt briefcase (extension, mobile signer, hardware keys, remote MCP routing, real x402/L402, revocation, AI policy compiler, enterprise control plane)

## Executive summary

- Feasibility: **Medium**.
- Rationale:
  - The current repo already ships a production-grade v0.1 reference daemon/gateway/policy/budgets/receipts/payments interface.
  - The remaining SOP items are multi-platform and require building new trust boundaries (browser + mobile + hardware keys) and new protocol compliance (full MCP + OAuth discovery), plus real payment rails.

## What Exists Today (v0.1.x)

- `apps/briefcased`: local daemon with policy/budget/approval/receipt enforcement; secrets remain inside daemon boundary.
- `apps/mcp-gateway`: minimal MCP-like stdio JSON-RPC surface for agents.
- `apps/briefcase-cli`: trusted admin CLI for onboarding/approvals/receipts.
- `apps/briefcase-ui`: local UI proxy for approvals/receipts/provider status.
- `apps/agent-access-gateway`: provider reference gateway with demo OAuth/VC and demo 402 challenge flows.
- `crates/briefcase-secrets`: secret stores (keyring/file/memory).
- `crates/briefcase-payments`: payment challenge parsing + demo HTTP + command-helper backends.
- `crates/briefcase-identity`: `did:key` (Ed25519) seed derivation.
- `crates/briefcase-policy`: Cedar wrapper implementing allow/deny + derived "require approval".
- `crates/briefcase-receipts`: hash-chained receipts in SQLite + verification.

## Key constraints (must not regress)

- **LLM untrusted**: no raw secrets (OAuth refresh tokens, private keys, payment preimages) ever reach agent runtime, MCP gateway, or logs.
- **Deterministic enforcement**: policy engine decisions must remain authoritative; "AI" layers can only tighten or propose changes.
- **Local-first by default**: daemon should not listen on TCP by default; local IPC preferred; remote/enterprise is opt-in.
- **Cross-platform**: macOS/Linux/Windows CI must stay green; extension/mobile builds gated with platform-appropriate CI.
- **Protocol correctness**: full MCP compliance (2025-06+), OAuth discovery (RFC 9728), DPoP (RFC 8707) where used.

## Big gaps vs sop.txt (work to do)

- **Browser extension**: secure UX for onboarding, approvals, receipts; safe bridging to the local daemon.
- **Mobile signer**: hardware-backed signing + out-of-band approvals; pairing and secure transport.
- **Hardware-backed keys**: real non-exportable keys in Secure Enclave/TPM/HSM; migrate PoP + DID where possible.
- **Full MCP**: transport compliance (stdio + HTTP SSE/streamable HTTP), OAuth auth discovery, and remote MCP routing as a client.
- **Strong tool isolation**: per-tool deny-by-default filesystem/network; per-tool egress allowlists; sandboxed execution.
- **Real payments**:
  - **x402** stablecoin rails (wallet integration, signing, settlement).
  - **L402** Lightning rails (invoice payment against an LND/CLN backend).
- **Revocation**: VC status lists, OAuth revocation, capability revocation lists, key rotation flows.
- **AI layers**: policy compiler, consent copilot, anomaly detection (non-authoritative).
- **Enterprise control plane**: org policy distribution, centralized audit ingestion, RBAC, HSM-backed custody option.

## Codebase scan

### Relevant existing components

- `apps/briefcased/src/app.rs` — enforcement point (schema validation, policy/budgets/approvals, receipts).
- `apps/briefcased/src/provider.rs` — auth strategy selection (VC > OAuth > payment) + PoP signing (v0.1).
- `apps/mcp-gateway/src/main.rs` — agent-facing surface (must evolve to full MCP).
- `apps/agent-access-gateway/src/main.rs` — provider-side ref (must evolve to real rails + revocation).
- `crates/briefcase-secrets` — extensible secret custody boundary; extend to hardware keys.
- `crates/briefcase-payments` — already supports “command helper” pattern; can host real rails out-of-process.

### Patterns to follow

- Enforce-only-in-daemon: `apps/briefcased/src/app.rs` is the single choke point for budgets/policy/approvals/receipts.
- Avoid leaking secrets in errors/logs: `crates/briefcase-core/src/sensitive.rs`.
- “Demo first, then swap” interfaces: `crates/briefcase-payments::PaymentBackend`.

### Gaps / missing pieces

- Full MCP transport + auth discovery compliance — required for remote MCP routing.
- Secure browser->daemon bridging — required for real-world OAuth onboarding UX.
- Hardware key abstraction — required for PoP and DID signing without exportable keys.
- Sandbox runtime — required for “deny by default” filesystem/network at tool level.

## External research (optional)

- MCP Authorization spec (2025-06-18): OAuth 2.1 + discovery via RFC 9728, DPoP via RFC 8707. (source: `sop.txt` links)
- MCP transports (2025-03-26+, 2025-11-25): stdio + SSE + streamable HTTP; batching removed in 2025-06. (source: `sop.txt` links)
- x402: HTTP 402 micropayment flow with standardized headers/fields; reference implementations exist. (source: `sop.txt` links)
- L402: LSAT-style macaroon + invoice; verify preimage; bind to API requests. (source: `sop.txt` links)
- VC/DID: W3C VC Data Model 2.0; status checking required for revocation. (source: `sop.txt` links)

## Open questions

- Mobile signer stack: native (Swift/Kotlin) vs Flutter/React Native with native modules for secure enclave/keystore.
- Hardware key algorithm: keep Ed25519 where software-only, but use P-256 for Secure Enclave/TPM (Ed25519 often unsupported).
- Enterprise control plane scope for OSS v1: minimal reference vs feature-complete (RBAC, policy, receipts, HSM).
- Remote MCP transport: start with streamable HTTP (preferred) vs SSE; both needed for compatibility.

## Sources

- `sop.txt`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/CAPABILITY_TOKENS.md`
- MCP spec links referenced by `sop.txt`
