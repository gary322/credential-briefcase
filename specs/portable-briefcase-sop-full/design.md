# Design: portable-briefcase-sop-full

## Overview

Evolve the current v0.1 reference implementation into a full SOP-complete product by:

1. upgrading the MCP gateway + client stack to full spec compliance (transports + auth discovery),
2. introducing strong tool isolation via a sandbox runtime with deny-by-default egress and filesystem,
3. adding first-class key custody with hardware-backed signers (Secure Enclave/TPM/HSM) and optional mobile signer,
4. integrating real x402 stablecoin payments and real L402 Lightning payments behind stable interfaces,
5. implementing revocation/status checks for OAuth/VC/capabilities,
6. shipping browser extension + mobile signer UX for onboarding/approvals,
7. providing an enterprise control plane reference.

## Architecture

### Component diagram (target)

```mermaid
graph TB
  Agent[Untrusted agent runtime] --> MCPGW[mcp-gateway (MCP server)]
  MCPGW --> Daemon[briefcased (enforcement)]

  Ext[Browser extension] --> NMH[Native messaging host]
  NMH --> Daemon

  Mobile[Mobile signer] --> Daemon
  CP[Enterprise control plane] --> Daemon
  Daemon --> CP

  Daemon --> Sandbox[Tool sandbox runtime]
  Daemon --> Secrets[Secret store + key custody]
  Daemon --> DB[(SQLite metadata)]
  Daemon --> Receipts[(Receipt chain)]

  Daemon --> RemoteMCP[Remote MCP servers]
  Daemon --> ProviderGW[Agent Access Gateway (provider ref)]
  ProviderGW --> UpstreamAPI[Upstream APIs/tools]

  Daemon --> PayHelper[Payment helper (optional)]
```

### Key components (new/expanded)

- `apps/mcp-gateway`: upgrade to full MCP spec surface; supports stdio + HTTP transports; never stores secrets.
- `apps/briefcased`: remains the enforcement point; adds remote MCP client routing, sandbox execution, key custody integration, revocation, enterprise sync.
- `apps/briefcase-extension` (new): approvals + onboarding + receipts UX; OAuth login helper; never sees refresh tokens.
- `apps/native-messaging-host` (new): minimal local bridge between extension and daemon (no secrets); enforces origin + user session.
- `apps/briefcase-mobile-signer` (new): out-of-band approval/signing; hardware-backed keys on mobile; optional but supported.
- `apps/briefcase-control-plane` (new): deployable reference server for enterprise policy distribution and receipt ingestion with RBAC.
- `crates/briefcase-mcp` (new): MCP protocol implementation (client + server, shared types, transports, auth).
- `crates/briefcase-sandbox` (new): sandbox runtime (WASM-first) with explicit host capabilities.
- `crates/briefcase-keys` (new): key custody and signing abstraction with platform backends and remote signer.
- `crates/briefcase-revocation` (new): VC status checks, OAuth revoke integration, capability denylist profiles.
- `crates/briefcase-ai` (new): non-authoritative policy suggestions/consent summaries/anomaly detection interfaces.

## Data model / state (additive to v0.1)

- `devices`
  - `device_id`, `display_name`, `enrolled_at`, `signer_kind`, `public_keys`, `last_seen_at`
- `key_handles`
  - `key_id`, `kind` (identity|pop|payments), `backend` (software|se|tpm|pkcs11|mobile), `handle_blob`, `created_at`
- `oauth_accounts`
  - `provider_id`, `auth_server_url`, `client_id`, `scopes`, `refresh_token_secret_id`, `revoked_at`
- `capability_cache`
  - `provider_id`, `resource`, `token_jwt`, `expires_at`, `cnf/thumbprint`, `revoked_at`
- `vc_store`
  - `provider_id`, `vc_jwt`, `expires_at`, `status_url`, `status_cache`, `revoked_at`
- `tool_sandbox_manifests`
  - `tool_id`, `runtime` (builtin|wasm), `allowed_domains`, `allowed_paths`, `max_bytes`, `risk_level`
- `revocations`
  - `kind` (oauth|vc|cap), `subject_id`, `ts`, `reason`
- control plane (server-side)
  - org/users/roles/policy bundles, receipt ingestion tables, device enrollment tokens.

## Interfaces / APIs

### Daemon local admin API (trusted surfaces only)

- Existing endpoints stay; new endpoints added:
  - `POST /v1/pairing/start` -> returns QR payload for mobile signer enrollment (ephemeral).
  - `GET /v1/pairing/status` -> enrollment status.
  - `GET /v1/approvals/stream` (SSE) -> approvals queue updates for UI/extension.
  - `POST /v1/policy/compile` -> AI-assisted proposal (returns diff, never applies automatically).
  - `POST /v1/policy/apply` -> applies a confirmed policy bundle.
  - `POST /v1/revocations/{kind}/{id}` -> revoke locally and (when supported) remote.
  - `POST /v1/control-plane/enroll` -> device enroll to control plane.
  - `POST /v1/control-plane/push-receipts` -> upload receipts.

Errors
- Stable error codes: `invalid_args`, `denied`, `approval_required`, `budget_exceeded`, `oauth_required`, `revoked`, `sandbox_violation`, `upstream_error`.

### Browser extension <-> daemon bridge

- Transport: browser native messaging -> `apps/native-messaging-host` -> daemon local API.
- Auth:
  - host verifies it is running under the current OS user.
  - daemon issues a short-lived session token to the host, bound to a per-installation key.
  - host never persists long-lived bearer tokens; it requests a fresh session token on startup.

### Mobile signer <-> daemon

- Pairing:
  - daemon generates one-time pairing token + ephemeral key; displays QR.
  - mobile app scans QR and establishes mutually authenticated channel (mTLS or Noise).
  - daemon stores device public key handle and signer policy (what requires mobile confirmation).
- Runtime:
  - daemon sends signing requests (approve / PoP / policy apply) to the mobile app.
  - mobile app returns signatures; daemon verifies and proceeds.
  - push notifications are optional; polling supported for local-only setups.

### Remote MCP routing

- `briefcased` is the MCP client for remote MCP servers.
- `mcp-gateway` lists tools aggregated from:
  - local tool registry,
  - sandboxed installed tools,
  - remote MCP tool lists (with provenance and policy labels).
- The Briefcase enforces:
  - tool allow/deny,
  - per-remote-server auth discovery + token acquisition,
  - egress allowlists and response firewalling.

### Provider auth discovery (OAuth)

- Implement OAuth protected resource metadata discovery (RFC 9728) as required by MCP authorization guidance.
- Support DPoP (RFC 8707) for token binding when configured.

## Strong tool isolation (sandbox model)

- Default runtime: WASM modules executed in `wasmtime`.
- No ambient access:
  - no filesystem unless pre-opened directories are explicitly configured,
  - no direct sockets; network only via host calls which enforce allowlists and attach auth.
- Host APIs (capabilities):
  - `http_request(provider_id|url, method, headers, body)` with egress checks + size caps + redirect disabled.
  - `kv_get/kv_put` for per-tool storage (namespaced, quota limited).
  - `request_approval(summary)` to trigger approval gating (daemon remains authoritative).

## Hardware-backed keys (key custody model)

- Introduce `Signer` abstraction:
  - `sign(bytes) -> signature`
  - `public_key() -> JWK/bytes`
  - key handles are non-exportable when backend supports it.
- Backends:
  - Apple Security framework: Secure Enclave (P-256) when available; Keychain as fallback.
  - Windows CNG/NCrypt: TPM-backed keys when available.
  - Linux TPM2: via `tpm2-tss` / `tss-esapi` with `swtpm` for CI.
  - PKCS#11: HSM support + SoftHSM for CI.
  - Mobile signer: remote signing over paired channel.
- Update PoP and capability binding:
  - prefer standardized DPoP (JWT header) for HTTP requests when interacting with OAuth-protected resources,
  - keep the current custom PoP headers only for legacy/demo compatibility.

## Payments (real rails)

- Keep `PaymentBackend` but add production-grade implementations:
  - x402 stablecoin backend:
    - parse/payment-requirement profiles per x402 spec,
    - pay via wallet backend (local wallet, CDP, or enterprise-managed helper),
    - store non-sensitive receipts; never store raw private keys in daemon unless explicitly configured.
  - L402 backend:
    - parse challenge (macaroon + invoice),
    - pay invoice via configured Lightning backend (LND/CLN),
    - return preimage securely; preimage never leaves daemon boundary.

## Revocation and status checks

- OAuth:
  - support RFC7009-style token revocation where providers expose it,
  - support local “forget provider” which deletes refresh tokens from the secret store.
- VC:
  - support status-list based revocation checks; cache with TTL; fail closed or require approval when status unknown (configurable).
- Capabilities:
  - provider gateway maintains denylist by `jti`,
  - briefcased handles 401/403 signals as revocation, forces refresh.

## AI layers (non-authoritative)

- `briefcase-ai` provides:
  - policy compiler: proposes Cedar diffs from natural language + tool metadata.
  - consent copilot: summarizes approval request in plain language.
  - anomaly detection: scans receipts for spikes, new domains, tool output poisoning patterns.
- Enforcement rules:
  - AI may only propose config changes; application requires explicit user confirmation (and optionally mobile signer).
  - AI risk scoring may only tighten by requiring approval.

## Enterprise control plane (reference)

- Components:
  - control plane API (RBAC, device enrollment, policy bundles, receipt ingestion),
  - optional remote custody service (HSM/Vault integration) exposed behind `briefcase-keys`.
- Transport:
  - mTLS between devices and control plane; OIDC for admin UI.
- Policy:
  - policies versioned and signed; clients verify signatures before applying.

## Failure modes & error handling (examples)

- Remote MCP auth fails -> tool call returns `oauth_required` with an onboarding URL; receipt records attempt.
- Sandbox violates egress rules -> tool call denied with `sandbox_violation`; receipt records blocked domain/path.
- Payment backend unreachable -> tool call denied or approval-required depending on policy; receipt records.
- Revocation status unknown -> require approval or deny (configurable) and receipt records.

## Performance considerations

- Sandbox overhead:
  - keep a warm pool of WASM instances per tool with strict memory caps.
- Remote MCP:
  - cache tool list and capabilities with TTL; refresh on auth changes or failure.
- Receipts:
  - append-only and batched; control plane uploads done asynchronously with backpressure.

## Test strategy (maps to requirements)

- Unit
  - protocol parsing (MCP frames, x402/L402 challenges), key-handle serialization, policy compiler diff format, revocation logic.
- Integration
  - remote MCP proxy against local stub servers for each transport.
  - OAuth discovery + PKCE with local auth servers.
  - sandbox enforcement tests (egress, FS, size caps).
  - x402 testnet via local chain simulation or provider sandbox; L402 via regtest nodes.
  - SoftHSM + swtpm tests for HSM/TPM backends.
- E2E
  - agent -> `mcp-gateway` -> `briefcased` -> remote MCP tool with OAuth discovery.
  - extension-driven onboarding and approvals.
  - mobile signer confirmation required for policy changes and high-risk tool calls.
  - enterprise: device enroll -> policy push -> receipts upload -> auditor view.

## Rollout / migration plan

- Additive DB migrations: introduce new tables with `CREATE TABLE IF NOT EXISTS`.
- Keep v0.1 flows working:
  - custom PoP headers remain supported for the demo gateway,
  - `mcp-gateway` can keep stdio transport while adding HTTP transport.
- Gate new features behind config flags with secure defaults.
