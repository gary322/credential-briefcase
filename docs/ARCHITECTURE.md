# Architecture

## Goal

Provide a "credential briefcase" where:

- the LLM is untrusted
- secrets are not exposed to the agent runtime
- tool calls are policy-bounded and auditable

## Reference vs GA contract

This repo contains both:

- **GA contract surfaces**: `briefcased` (enforcement + custody) and `mcp-gateway` (the only agent-facing MCP surface).
- **Reference implementations** (useful in production, but not the cross-vendor contract itself):
  - `agent-access-gateway` (provider-side reference gateway)
  - `briefcase-control-plane` (enterprise reference control plane)

The cross-component interoperability contract is the **Agentic Auth Compatibility Profile** (`aacp_v1`) defined in `docs/COMPATIBILITY_PROFILE.md` and enforced most strictly in `BRIEFCASE_PROFILE_MODE=ga`.

## Components

1. `briefcased` (daemon, enforcement point)

- Holds secrets/credentials (OS keychain by default; encrypted-file fallback).
- Holds signing keys behind an abstraction with hardware-backed backends where available (PKCS#11/TPM2/Secure Enclave/Windows CNG; optional remote signer in enterprise mode).
- Enforces Cedar policy (allow/deny + approval gating) and budgets.
- Runs non-authoritative risk scoring (can require approval, never bypass policy).
- Enforces per-tool isolation (WASM sandbox + deny-by-default egress/filesystem allowlists).
- Routes tool execution to:
  - provider HTTP APIs and/or
  - remote MCP servers (as an MCP client), while keeping policy/receipts centralized.
- Stores tamper-evident receipts (hash chained).

2. `mcp-gateway`

- The only MCP server the agent connects to.
- Supports MCP over stdio and Streamable HTTP.
- Lists tools and forwards tool calls to `briefcased`.
- Redacts/serializes results for agent consumption and attaches provenance metadata.

3. `briefcase-cli`
- Lists tools, triggers calls, handles approvals, inspects receipts.

3.5. `briefcase-ui`
- Local web UI that proxies to the daemon (approvals + receipts + provider status).

4. `briefcase-extension` + `native-messaging-host`

- MV3 extension UI for onboarding and approvals.
- Uses a hardened native messaging host to reach the daemon without putting secrets in the browser.

5. `briefcase-mobile-signer` (iOS/Android)

- Out-of-band approval signer for high-risk actions.
- Uses platform key custody (Secure Enclave / Keystore) where possible.

6. `agent-access-gateway` (provider reference)
- Challenges with HTTP 402 (demo x402/l402).
- Supports OAuth 2.1 + PKCE (demo).
- Issues a demo VC entitlement (JWT) and accepts it for capability issuance.
- Issues short-lived capability tokens (JWT).
- Optionally binds capabilities to a client key (PoP) and enforces replay defenses.
- Meters usage.

7. `briefcase-control-plane` (enterprise reference)

- Central policy distribution (signed bundles) and receipt ingestion/query.
- Optional remote custody signer service.

## Data Flow (Happy Path)

1. Agent calls `tools/call` on `mcp-gateway`.
2. Gateway forwards to `briefcased` via local IPC with a session token:
   - Unix: domain socket (default)
   - Windows: named pipe (default)
   - TCP loopback is supported as a fallback (`BRIEFCASE_TCP_ADDR`)
3. Daemon validates args, evaluates policy and budgets, runs sandboxed execution, and executes connector.
4. Daemon stores a receipt and returns a redacted result with provenance.

## Approval Flow

1. Policy decision requires approval.
2. Daemon creates an approval request and returns `approval_required`.
3. User approves:
   - `kind=local`: via extension/CLI/UI using the daemon auth token.
   - `kind=mobile_signer`: via a paired mobile signer (signature-based auth).
   This yields an `approval_token`.
4. Tool call is retried with the `approval_token`.
   - On MCP, pass this as `tools/call` `approvalToken`.

## Provider Auth Strategy

For tools that call a provider connector, the daemon prefers:

1. VC entitlement (fetch capability with `x-vc-jwt`)
2. OAuth refresh token (refresh access token, then fetch capability)
3. Micropayment challenge (x402 / l402 demo), then fetch capability

The agent only ever receives redacted tool outputs and provenance; raw secrets remain inside the daemon.

## Compatibility Profile

The platform exposes a versioned compatibility profile (`aacp_v1`) and runtime mode:

- `reference`
- `staging`
- `ga`

Mode/profile can be discovered via daemon APIs:

- `GET /v1/identity`
- `GET /v1/profile`
- `GET /v1/diagnostics/compat`

See `docs/COMPATIBILITY_PROFILE.md` for normative requirements.
