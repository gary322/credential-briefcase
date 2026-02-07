# Requirements: portable-briefcase-sop-full

## Goal

Ship the full credential-briefcase system as an open-source, production-ready codebase:

- the LLM/agent runtime is untrusted and never receives raw secrets,
- a local (or enterprise-managed) Briefcase owns credentials, keys, payments, policy enforcement, and audit receipts,
- the agent connects only to a single MCP gateway which routes tool calls through the Briefcase using caveated capability tokens,
- the system includes a browser extension + mobile signer, hardware-backed keys, full MCP auth discovery + remote routing, strong tool isolation, real x402/L402 rails, revocation, AI policy compiler/cosent UX/anomaly detection, and an enterprise control plane reference.

## Users / personas

- Individual user (local-first).
- Provider developer (wants a reference "agent access gateway" and capability profile).
- Enterprise admin / security team (central policy + audits + device/user management).

## User stories

### US-1: Untrusted Agent, One MCP Surface

**As a** user
**I want** the agent to connect only to one MCP server surface and never handle secrets
**So that** prompt injection/tool chaining cannot exfiltrate credentials or payment proofs

Acceptance criteria
- AC-1.1: The agent connects only to `mcp-gateway` (no direct remote MCP connections from the agent runtime).
- AC-1.2: No raw secrets ever appear in gateway responses or logs (refresh tokens, private keys, payment preimages).
- AC-1.3: Every tool call produces a verifiable, tamper-evident receipt.

### US-2: Secure Approvals UX (Browser + Mobile)

**As a** user
**I want** approvals to be delivered to a safe UI (extension/web UI) and optionally require mobile signer confirmation
**So that** expensive or risky actions need explicit consent

Acceptance criteria
- AC-2.1: Write tools require approval by default; approvals are bound to `{tool_id,args}` and expire.
- AC-2.2: High-risk approvals can be configured to require a mobile-signer confirmation.
- AC-2.3: Approvals show what data will be accessed, what will be stored, and estimated cost.

### US-3: Hardware-Backed Key Custody

**As a** user
**I want** identity and PoP signing keys to be hardware-backed when available
**So that** key material is non-exportable and device-bound

Acceptance criteria
- AC-3.1: On supported platforms, keys are created and used via Secure Enclave / TPM / HSM and are non-exportable.
- AC-3.2: When hardware keys are unavailable, software keys use encrypted-at-rest storage and explicit warnings are surfaced.
- AC-3.3: PoP is enforced for capability usage when configured; replay defenses are validated by tests.

### US-4: Full MCP Compliance + Remote MCP Routing

**As a** user
**I want** to use remote MCP servers without my agent connecting to them directly
**So that** policies and receipts still apply to remote tools

Acceptance criteria
- AC-4.1: `mcp-gateway` and the Briefcase support MCP transports used in the spec (stdio and HTTP variants).
- AC-4.2: Authorization follows MCP spec guidance and supports OAuth 2.1 discovery (RFC 9728) and DPoP (RFC 8707) when used.
- AC-4.3: Remote tools can be proxied, policy gated, and audited as if local.

### US-5: Strong Tool Isolation

**As a** user
**I want** per-tool deny-by-default filesystem and network with explicit allowlists
**So that** a compromised tool or prompt-injected chain cannot access unexpected resources

Acceptance criteria
- AC-5.1: Tools run in a sandbox that has no ambient filesystem or network access by default.
- AC-5.2: Each tool declares allowed egress domains and filesystem access; violations fail closed and are receipted.
- AC-5.3: Tool isolation is enforced cross-platform with a consistent security posture (best-effort where OS limits apply).

### US-6: Real Micropayments (x402 + L402)

**As a** user
**I want** the Briefcase to pay for gated tools via stablecoin x402 or Lightning L402
**So that** I can use pay-per-call tools under explicit budgets

Acceptance criteria
- AC-6.1: x402 flow can complete against a real wallet backend (testnet + mainnet-configurable) and retries with valid proofs.
- AC-6.2: L402 flow can complete against at least one Lightning backend (LND or Core Lightning) and retries with macaroon+preimage.
- AC-6.3: Budgets cap spend; overruns require approval; spend receipts include payment rail metadata (without secrets).

### US-7: Revocation That Works

**As a** user
**I want** to revoke access quickly across OAuth, VC entitlements, and capability tokens
**So that** compromise recovery is practical

Acceptance criteria
- AC-7.1: OAuth refresh token revocation is supported (where provider supports it) and is surfaced in UI/CLI.
- AC-7.2: VC status is checked (status list / revocation mechanism) and cached safely.
- AC-7.3: Capability tokens are short-lived and can be revoked server-side; the Briefcase respects revocation signals.

### US-8: AI-Assisted Policy and Consent (Non-Authoritative)

**As a** user
**I want** natural-language policy suggestions and plain-language approval explanations
**So that** policies and approvals are understandable and usable

Acceptance criteria
- AC-8.1: AI outputs can only propose policy diffs; users must confirm before changes apply.
- AC-8.2: The enforcement engine never relies on AI outputs for allow decisions; AI can only tighten (require approval).
- AC-8.3: Anomaly detection flags suspicious patterns (spend spikes, new domains, tool output poisoning signals) in the UI.

### US-9: Enterprise Control Plane (Reference)

**As an** enterprise admin
**I want** a deployable control plane for policy distribution and audit ingestion
**So that** teams can manage budgets, approvals, and compliance centrally

Acceptance criteria
- AC-9.1: Devices enroll, receive policy/budget configs, and submit receipts to the control plane.
- AC-9.2: RBAC exists for policy editors vs auditors vs operators.
- AC-9.3: Optional remote custody mode supports HSM/Vault-backed signing and secrets storage.

## Functional requirements (FR)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| FR-1 | Full MCP server compliance in `mcp-gateway` (stdio + HTTP transports) | High | Conformance tests + integration tests |
| FR-2 | Briefcase acts as MCP client to remote MCP servers and proxies tools | High | E2E: agent -> gateway -> briefcased -> remote MCP |
| FR-3 | OAuth discovery via RFC 9728 + MCP auth flow support | High | Integration tests against local OAuth test servers |
| FR-4 | Browser extension (MV3) for onboarding + approvals + receipts | High | Extension e2e tests + manual packaging smoke |
| FR-5 | Mobile signer app for approvals + signing, with secure pairing | High | Mobile integration tests + simulated signer tests |
| FR-6 | Hardware-backed key manager (Secure Enclave/TPM/HSM) with software fallback | High | Platform integration tests + mock HSM tests |
| FR-7 | Strong per-tool sandbox with deny-by-default FS/network + allowlists | High | Sandbox enforcement tests + escape regression suite |
| FR-8 | Real x402 stablecoin backend behind `PaymentBackend` | High | Testnet integration tests + mocks |
| FR-9 | Real L402 Lightning backend behind `PaymentBackend` | High | Regtest integration tests + mocks |
| FR-10 | Revocation: OAuth revoke, VC status, capability denylist | High | Unit + integration tests |
| FR-11 | AI policy compiler + consent copilot + anomaly detection (non-authoritative) | Medium | Unit tests + red-team prompt test corpus |
| FR-12 | Enterprise control plane reference with RBAC and audit ingestion | Medium | Docker e2e tests + load tests |

## Non-functional requirements (NFR)

| ID | Category | Target | Notes |
|----|----------|--------|-------|
| NFR-1 | Security | No raw secrets in agent boundary or logs | Verify with log-scanning tests and e2e harness |
| NFR-2 | Security | Least privilege by default | Deny-by-default sandbox + local-only IPC |
| NFR-3 | Reliability | Tool calls fail closed | Policy/budget/egress violations deny; receipts still appended |
| NFR-4 | Performance | p95 tool-call overhead < 50ms local-only (excluding network) | Measure via benchmarks |
| NFR-5 | Portability | macOS/Linux/Windows build+test green | CI matrix required |
| NFR-6 | Observability | Structured logs + traces + metrics | OpenTelemetry spans for tool call chain |

## Out of scope / non-goals (explicit)

- Full account-abstraction wallet (EIP-4337) in core; keep as a pluggable payment helper and reference docs.
- Full MCP protocol fuzzing for every transport in v1; focus on message parsing and auth flows first.

## Assumptions

- Users can install a native daemon and (optionally) a browser extension/mobile app.
- Providers implement OAuth and/or 402 challenges; the provider reference gateway remains a reference, not a hosted service.
- Enterprise control plane can be shipped as a Docker-compose/Kubernetes-deployable reference.

## Dependencies

- MCP spec (authorization + transports) and their RFC dependencies (RFC 9728, RFC 8707).
- x402 reference implementation and wallet backend APIs.
- Lightning node APIs (LND/CLN).
- Platform key APIs (Apple Security framework, Windows CNG/NCrypt, TPM2 stack, PKCS#11).

## Success metrics

- End-to-end conformance and flows all pass in CI:
  - agent -> MCP gateway -> briefcased -> remote MCP tool under OAuth discovery
  - paid tool call via real x402 testnet backend under budget caps
  - paid tool call via L402 regtest backend under budget caps
  - mobile-signer required approval flow works end-to-end
  - receipt chain verifies and anomaly detector flags injected outputs in test corpus
