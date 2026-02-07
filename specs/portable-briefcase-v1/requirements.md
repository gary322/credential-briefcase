# Requirements: portable-briefcase-v1

## Goal

Ship an open-source, production-grade reference implementation of the "credential briefcase" architecture where an untrusted LLM can use tools without ever receiving raw secrets, while all tool execution is policy/budget gated and auditable.

## Users / personas

- Individual user: uses local-first tools with safe credential custody and clear approvals.
- Provider developer: wants a reference "agent access gateway" that can be deployed in front of an API/tool server.
- (Future) Enterprise admin: wants org policy + audits; not a v1 deliverable beyond a deployable reference.

## User stories

### US-1: Safe Tool Use With Audits

**As a** user
**I want** the agent to call tools without handling secrets
**So that** prompt injection and tool-chain issues cannot leak raw credentials

Acceptance criteria
- AC-1.1: The agent can only connect to a single MCP server surface (gateway).
- AC-1.2: Tool calls are schema-validated, policy/budget evaluated, and produce a tamper-evident receipt.
- AC-1.3: Tool outputs returned to the agent can be field-filtered via an allowlist.

### US-2: Approvals And Budgets

**As a** user
**I want** risky or write actions to require approvals
**So that** the agent cannot perform unintended actions

Acceptance criteria
- AC-2.1: Write tools require approval by default.
- AC-2.2: Budget overruns require approval.
- AC-2.3: Approvals are bound to `{tool_id,args}` and expire.

### US-3: Provider Onboarding Without Secret Leakage

**As a** user
**I want** to onboard a provider via OAuth/VC/payments without copy/pasting secrets into an agent
**So that** credentials stay in the briefcase boundary

Acceptance criteria
- AC-3.1: OAuth refresh tokens are stored only in the daemon secret store.
- AC-3.2: A stored VC entitlement can be used to obtain a short-lived capability token.
- AC-3.3: When no entitlement or OAuth exists, the daemon can fall back to a micropayment challenge (demo rails in v1).

### US-4: Usable Admin UX

**As a** user
**I want** a CLI and basic UI for approvals and receipts
**So that** I can operate the system without touching databases or logs

Acceptance criteria
- AC-4.1: CLI can list/call tools, list/approve approvals, list/verify receipts, and do OAuth/VC onboarding.
- AC-4.2: UI can list approvals, approve requests, and view recent receipts.

## Functional requirements (FR)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| FR-1 | Briefcase daemon enforces schema + policy + budgets + approvals on every tool call | High | E2E tests + receipts |
| FR-2 | Secrets stored via keyring backend by default; encrypted-file fallback supported | High | Unit/integration tests |
| FR-3 | OAuth onboarding stores refresh token only inside daemon | High | Integration test |
| FR-4 | VC entitlement storage + use for capability issuance | Medium | Integration test |
| FR-5 | Single MCP gateway forwards tool calls to daemon | High | Gateway integration test |
| FR-6 | Local UI proxies to daemon for approvals/receipts | Medium | Manual smoke + unit tests |
| FR-7 | Receipt hash chain verifiable via daemon API | High | Unit + integration tests |

## Non-functional requirements (NFR)

| ID | Category | Target | Notes |
|----|----------|--------|-------|
| NFR-1 | Security | No raw secrets in agent responses/logging | Use `Sensitive<T>` + no secret-returning endpoints |
| NFR-2 | Reliability | Deterministic policy enforcement | Cedar decisions authoritative |
| NFR-3 | Performance | Tool call overhead low (local IPC) | Unix socket by default |
| NFR-4 | Portability | Builds on macOS/Linux/Windows CI | GitHub Actions matrix |
| NFR-5 | Maintainability | Clear boundaries + test coverage | Workspace crates + docs |

## Out of scope / non-goals (v1)

- Full enterprise control plane (HSM fleet, org-wide RBAC).
- Real on-chain wallet/account abstraction in core.
- Full remote MCP server routing/virtualization (planned behind connector interface).
- Real x402 stablecoin / real Lightning node integrations (v1 ships demo rails and a stable interface boundary).

## Assumptions

- Local machine boundary is trusted; daemon auth token file is protected by OS permissions.
- The reference provider gateway is allowed to be a demo implementation; production deployments will replace it.

## Dependencies

- Rust toolchain pinned (`rust-toolchain.toml`).
- Cedar policy engine pinned for MSRV compatibility.

## Success metrics

- CI green (fmt + clippy `-D warnings` + tests) on all OSes.
- Demonstrable flows:
  - payment-based tool call
  - OAuth login + VC issuance + tool call without payment
  - approvals + receipts verification
