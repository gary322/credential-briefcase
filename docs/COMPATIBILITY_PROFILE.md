# Agentic Auth Compatibility Profile (AACP) v1

This document defines the production compatibility contract between:

- agent-facing MCP gateways
- the Briefcase daemon (`briefcased`)
- provider gateways / protected APIs

The current profile identifier is:

- `aacp_v1`

## Profile modes

Runtime mode is configured with `BRIEFCASE_PROFILE_MODE`:

- `reference`: development-first behavior
- `staging`: pre-GA hardening validation
- `ga`: strict production behavior

Clients may discover active mode and profile via:

- `GET /v1/identity`
- `GET /v1/profile`
- `GET /v1/diagnostics/compat`

## Profile scope (what this document governs)

This profile defines compatibility for behaviors that cross trust boundaries or affect interoperability:

- `briefcased` daemon REST API semantics for approvals, retries, receipts, and tool execution.
- `mcp-gateway` MCP `initialize` capabilities and the `approvalToken` retry semantics for `tools/call`.
- Provider gateways issuing capability tokens (claims, PoP binding, replay behavior) and stable error signaling.
- Control plane policy bundle signing + delivery semantics (including compatibility guards).
- Remote MCP server gating in `ga` mode (compatibility profile discovery and strict enforcement).

Out of scope (not profile governed):

- UI/CLI ergonomics and output formatting.
- Browser extension packaging details.
- Mobile signer UI flows and store/distribution.

## Normative requirements

1. Trust boundary
- Raw refresh tokens, access tokens, capability tokens, key seeds, payment proofs/preimages MUST NOT be returned to agent-facing surfaces.
- Outbound provider/MCP execution MUST happen in `briefcased` after policy, risk, budget, and schema checks.

2. Approvals
- Approval decisions MUST be bound to `{tool_id, args}`.
- Tool retries MUST provide the approval token in `ToolCall.approval_token` (daemon API) or MCP `tools/call` `approvalToken`.

3. Capability and PoP
- Capability tokens SHOULD be short-lived and caveated.
- DPoP-bound capabilities MUST use `cnf.jkt`.
- When a capability is DPoP-bound, protected resource calls MUST include a valid DPoP proof.
- Provider gateways SHOULD advertise the profile via `x-briefcase-compatibility-profile: aacp_v1` on responses.

4. Replay defense
- DPoP and payment replay caches MUST reject duplicate proof identifiers/nonces within validity windows.
- Replay rejection errors MUST be deterministic and auditable.

5. Output and audit
- Tool output to agents MUST pass output firewall policy.
- Every tool execution attempt MUST create a receipt entry with decision metadata.

## Error conventions

Profile consumers SHOULD treat these as stable classes:

- auth missing/invalid
- approval required
- compatibility profile mismatch
- denied by policy/budget/risk
- invalid arguments/schema
- replay detected
- capability revoked/expired

## Versioning

- Backward-compatible additions may be introduced within `aacp_v1`.
- Breaking changes require a new profile id (for example `aacp_v2`).

## GA vs reference behavior

This document is the **compatibility contract** for `ga` mode.

- In `ga` mode:
  - The MUST requirements in this document are enforced.
  - Incompatible peers are rejected with stable diagnostics (mismatch is not silently tolerated).
- In `reference` / `staging` modes:
  - Some checks may be relaxed for developer ergonomics and experimentation.
  - Implementations should still aim to follow this document so the drift guard tests stay meaningful.

Any behavior not described here should be treated as **non-contractual** unless explicitly marked otherwise in docs.

## Support and deprecation policy

- A profile id (for example `aacp_v1`) is supported for the lifetime of the supported release lines documented in `docs/SUPPORT_MATRIX.md`.
- Deprecation process:
  - Breaking changes MUST introduce a new profile id (for example `aacp_v2`).
  - Deprecations MUST be announced at least one minor release before removal.
  - Deprecations MUST include a migration path and explicit timeline in release notes.
