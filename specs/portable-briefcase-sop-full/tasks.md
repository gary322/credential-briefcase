# Tasks: portable-briefcase-sop-full

## Overview

This spec is intentionally broad. Execution should be split into sub-specs, but the checklist below is the complete end-to-end plan so nothing is “hand-waved away”.

POC-first workflow:
1. Make it work (POC)
2. Refactor
3. Tests
4. Quality gates
5. (Optional) PR/release lifecycle

## Task format

For each task, include:

- **Do**: exact steps
- **Files**: paths to create/modify
- **Done when**: explicit success criteria
- **Verify**: command(s) or manual checks

## Phase 0: Monorepo Readiness For Multi-Platform Apps

- [x] 0.1 Add unified task runner + versioning conventions
  - **Do**: introduce `justfile` (or `taskfile.yml`) for cross-language commands; define versioning strategy for Rust + extension + mobile + control plane.
  - **Files**: `justfile`, `docs/RELEASING.md`, `Cargo.toml`
  - **Done when**: `just ci` runs fmt/clippy/tests for Rust and placeholder steps for other components.
  - **Verify**: `just ci`

- [x] 0.2 Add Node workspace for extension/control-plane UI
  - **Do**: add `package.json`, `pnpm-workspace.yaml`, `apps/briefcase-extension/`, `apps/control-plane-ui/` (optional), lint/test skeleton.
  - **Files**: `package.json`, `pnpm-workspace.yaml`, `apps/briefcase-extension/*`
  - **Done when**: CI can run `pnpm -r lint` and `pnpm -r test` (even if minimal).
  - **Verify**: `corepack enable && pnpm -r lint && pnpm -r test`

- [x] 0.3 Add OpenAPI for daemon admin API + generated clients
  - **Do**: define `openapi/briefcased.yaml` and generate TS client for extension and optional mobile.
  - **Files**: `openapi/briefcased.yaml`, `apps/briefcase-extension/src/gen/*`, `crates/briefcase-api/*`
  - **Done when**: API schema is source-of-truth and generation is deterministic.
  - **Verify**: `just gen && git diff --exit-code`

- [x] 0.4 Quality checkpoint
  - **Verify**: `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test --all`

## Phase 1: Full MCP Compliance + Remote MCP Routing

- [x] 1.1 Implement `crates/briefcase-mcp` (protocol + transports)
  - **Do**: implement MCP message types and both server+client primitives; support stdio transport and HTTP transport(s) required by spec; add conformance test harness.
  - **Files**: `crates/briefcase-mcp/*`, `apps/mcp-gateway/*`, `apps/briefcased/*`
  - **Done when**: `mcp-gateway` passes conformance tests for `initialize`, `tools/list`, `tools/call`, error handling, and transport framing.
  - **Verify**: `cargo test -p briefcase-mcp`
  - _Reqs: FR-1_

- [x] 1.2 Upgrade `apps/mcp-gateway` to spec-compliant behavior
  - **Do**: replace the minimal JSON-lines loop with `briefcase-mcp` server implementation; add HTTP transport; ensure no batching assumptions.
  - **Files**: `apps/mcp-gateway/src/main.rs`
  - **Done when**: gateway supports both stdio and HTTP transports; behavior matches conformance harness.
  - **Verify**: `cargo test -p mcp-gateway`
  - _Reqs: FR-1, AC-4.1_

- [x] 1.3 Add remote MCP registry and proxying in `briefcased`
  - **Do**: add DB tables for remote MCP servers; implement MCP client connections; implement “tool catalog” aggregation and routing.
  - **Files**: `apps/briefcased/src/db.rs`, `apps/briefcased/src/mcp_client.rs` (new), `apps/briefcased/src/app.rs`
  - **Done when**: remote MCP tools can be listed and called through the gateway; receipts reflect remote provenance.
  - **Verify**: `cargo test -p briefcased`
  - _Reqs: FR-2, AC-4.3_

- [x] 1.4 Add remote MCP stub servers for integration tests
  - **Do**: implement local test servers for each transport and auth mode.
  - **Files**: `tests/mcp_stub/*` or `apps/mcp-stub/*`
  - **Done when**: CI runs an e2e test: agent->gateway->briefcased->remote MCP and validates policy/receipts.
  - **Verify**: `cargo test -p briefcased e2e_remote_mcp_*`

- [x] 1.5 Quality checkpoint
  - **Verify**: `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test --all`

## Phase 2: OAuth PRM Discovery + Full MCP Auth Integration

- [x] 2.1 Implement OAuth discovery per RFC 9728 and MCP authorization guidance
  - **Do**: add `crates/briefcase-oauth-discovery` that fetches Protected Resource Metadata and resolves authorization server metadata; cache with TTL; validate HTTPS and issuer rules.
  - **Files**: `crates/briefcase-oauth-discovery/*`, `apps/briefcased/src/app.rs`, `apps/briefcased/src/remote_mcp.rs`, `apps/briefcased/src/db.rs`, `openapi/briefcased.yaml`
  - **Done when**: given a remote MCP URL, briefcased can determine auth endpoints/scopes and produce an authorization URL.
  - **Verify**: `cargo test -p briefcase-oauth-discovery`
  - _Reqs: FR-3, AC-4.2_

- [x] 2.2 Implement DPoP (RFC 8707) support (optional but default-on for new providers)
  - **Do**: generate DPoP proofs using `briefcase-keys` signer; bind access tokens when supported.
  - **Files**: `crates/briefcase-keys/*` (Phase 4), `apps/briefcased/src/oauth.rs`
  - **Done when**: integration tests pass for DPoP-bound token flow against stub provider.
  - **Verify**: `cargo test -p briefcased oauth_dpop_*`

- [x] 2.3 Add extension-driven OAuth UX (no secrets in extension)
  - **Do**: daemon exposes onboarding state; extension opens auth URL and returns code; daemon exchanges for tokens; refresh tokens stored only in daemon secrets store.
  - **Files**: `apps/briefcase-extension/*`, `apps/native-messaging-host/*`, `apps/briefcased/src/app.rs`
  - **Done when**: OAuth onboarding can be completed without CLI copy/paste; refresh token never leaves daemon.
  - **Verify**: extension e2e test + daemon integration test.
  - _Reqs: FR-4, AC-3.1_

## Phase 3: Strong Tool Isolation (Sandbox + Egress Allowlists)

- [x] 3.1 Create WASM-first sandbox runtime
  - **Do**: add `crates/briefcase-sandbox` using `wasmtime` with memory/time limits; design host-call surface.
  - **Files**: `crates/briefcase-sandbox/*`
  - **Done when**: a sample tool runs in sandbox and can call `host.http_request` with enforced allowlist.
  - **Verify**: `cargo test -p briefcase-sandbox`
  - _Reqs: FR-7, AC-5.1_

- [x] 3.2 Add per-tool manifest (allowed domains/paths, quotas)
  - **Do**: add manifest schema, store in DB, and enforce at runtime; deny-by-default.
  - **Files**: `crates/briefcase-core/src/tool_manifest.rs` (new), `apps/briefcased/src/db.rs`, `apps/briefcased/src/tools.rs`
  - **Done when**: tool calls that attempt disallowed egress/filesystem access fail closed and are receipted.
  - **Verify**: `cargo test -p briefcased sandbox_*`
  - _Reqs: AC-5.2_

- [x] 3.3 Migrate “connector execution” into sandboxed path
  - **Do**: move remote HTTP/MCP connector logic behind host calls so sandboxed tools never see raw tokens.
  - **Files**: `apps/briefcased/src/provider.rs`, `crates/briefcase-sandbox/*`
  - **Done when**: sandboxed tools can trigger provider calls without access to secrets; receipts include sandbox provenance.
  - **Verify**: e2e test.

- [x] 3.4 Quality checkpoint
  - **Verify**: `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test --all`

## Phase 4: Hardware-Backed Key Custody + Mobile/Enterprise Signers

- [x] 4.1 Introduce `crates/briefcase-keys` signer abstraction
  - **Do**: implement `Signer` trait + key handles; software Ed25519/P-256 backend; serialization; integrate with `briefcase-secrets`.
  - **Files**: `crates/briefcase-keys/*`, `apps/briefcased/src/app.rs`
  - **Done when**: briefcased can create and use a non-exportable key handle (software backend first) for PoP/identity.
  - **Verify**: `cargo test -p briefcase-keys`
  - _Reqs: FR-6_

- [x] 4.2 Implement PKCS#11 backend (+ SoftHSM CI)
  - **Do**: add PKCS#11 signer; dockerized SoftHSM integration tests.
  - **Files**: `crates/briefcase-keys/src/pkcs11.rs`, `docker/softhsm/*`, `.github/workflows/*`
  - **Done when**: CI can run sign/verify with SoftHSM.
  - **Verify**: `just test-pkcs11`

- [x] 4.3 Implement TPM backend (+ swtpm CI)
  - **Do**: add TPM2 signer; run swtpm in CI to validate key creation/signing.
  - **Files**: `crates/briefcase-keys/src/tpm2.rs`, `docker/swtpm/*`
  - **Done when**: CI can run sign/verify via swtpm.
  - **Verify**: `just test-tpm2`

- [x] 4.4 Implement Apple Keychain/Secure Enclave backend (macOS/iOS)
  - **Do**: use Apple Security framework to create P-256 secure enclave keys; fallback to Keychain when SE unavailable.
  - **Files**: `crates/briefcase-keys/src/apple.rs`
  - **Done when**: macOS integration test passes on environments that support it; fallback works elsewhere.
  - **Verify**: `cargo test -p briefcase-keys --features apple apple_*`

- [x] 4.5 Implement Windows CNG/NCrypt backend (TPM where possible)
  - **Do**: implement CNG signer; detect TPM provider; fallback to software key.
  - **Files**: `crates/briefcase-keys/src/windows.rs`
  - **Done when**: Windows CI runs software fallback tests; optional hardware tests documented.
  - **Verify**: `cargo test -p briefcase-keys --features windows windows_`

- [x] 4.6 Integrate keys into OAuth (DPoP) and capability PoP
  - **Do**: standardize PoP on DPoP where possible; update provider gateway to verify; update daemon client to attach proofs.
  - **Files**: `apps/agent-access-gateway/src/main.rs`, `apps/briefcased/src/provider.rs`
  - **Done when**: replay protection and PoP binding pass integration tests.
  - **Verify**: `cargo test -p agent-access-gateway pop_*`

## Phase 5: Browser Extension + Native Messaging Host

- [x] 5.1 Implement native messaging host
  - **Do**: build `apps/native-messaging-host` in Rust; define JSON message protocol; harden against origin confusion.
  - **Files**: `apps/native-messaging-host/*`, `packaging/native-messaging/*`
  - **Done when**: extension can call daemon APIs via host; host cannot be used by other OS users.
  - **Verify**: integration test + manual extension smoke.

- [x] 5.2 Build extension UI (approvals/receipts/providers/budgets)
  - **Do**: implement MV3 extension with UI pages; subscribe to approval stream; approve actions; view receipts.
  - **Files**: `apps/briefcase-extension/*`
  - **Done when**: approvals can be approved from the extension; receipts are viewable and exportable.
  - **Verify**: Playwright e2e extension tests.

- [x] 5.3 Extension security hardening
  - **Do**: content security policy, permissions minimization, anti-DNS rebinding checks, signed messages to host.
  - **Files**: `apps/briefcase-extension/manifest.json`, `apps/native-messaging-host/*`
  - **Done when**: security review checklist passes and automated tests cover critical invariants.
  - **Verify**: `pnpm -r test`

## Phase 6: Mobile Signer

- [x] 6.1 Define pairing + request protocol (Noise or mTLS)
  - **Do**: specify protocol; implement in Rust daemon + a simulator; ensure replay protection and device binding.
  - **Files**: `docs/PAIRING.md`, `apps/briefcased/src/pairing.rs` (new), `tests/signer_sim/*`
  - **Done when**: daemon can enroll a simulated signer and require it for approvals.
  - **Verify**: `cargo test -p briefcased signer_*`

- [x] 6.2 Implement iOS signer app (Secure Enclave)
  - **Do**: implement iOS app with secure enclave key + signing; approval UI; QR pairing.
  - **Files**: `apps/briefcase-mobile-signer/ios/*`
  - **Done when**: iOS can pair and approve/sign requests end-to-end.
  - **Verify**: manual smoke + iOS unit tests in CI (build at minimum).

- [x] 6.3 Implement Android signer app (Keystore-backed keys)
  - **Do**: implement Android app with Keystore-backed keys; approval UI; QR pairing.
  - **Files**: `apps/briefcase-mobile-signer/android/*`
  - **Done when**: Android can pair and approve/sign requests end-to-end.
  - **Verify**: manual smoke + Android unit tests in CI (build at minimum).

- [x] 6.4 Mobile signer policy integration
  - **Do**: add policy knobs: which tools/cost thresholds require mobile confirmation; integrate with Cedar policy decisions.
  - **Files**: `crates/briefcase-policy/*`, `apps/briefcased/src/app.rs`
  - **Done when**: high-risk actions are blocked without mobile confirmation.
  - **Verify**: e2e tests with simulated signer.

## Phase 7: Real x402 Stablecoin Payments

- [x] 7.1 Implement x402 payment backend
  - **Do**: implement x402 spec-compliant challenge parsing and payment execution; support a real wallet backend (helper process encouraged).
  - **Files**: `crates/briefcase-payments/src/x402.rs` (new), `apps/briefcase-payment-helper/*` (new)
  - **Done when**: can complete x402 payment against a real provider sandbox/testnet.
  - **Verify**: integration tests + staged manual test.
  - _Reqs: FR-8_

- [x] 7.2 Build x402 test harness
  - **Do**: docker-compose or local harness providing a fake x402 provider and wallet backend; run in CI.
  - **Files**: `docker/x402-harness/*`, `.github/workflows/*`
  - **Done when**: CI runs x402 integration test deterministically.
  - **Verify**: `just test-x402`

## Phase 8: Real L402 Lightning Payments

- [x] 8.1 Implement L402 backend with LND
  - **Do**: implement invoice payment via LND gRPC; parse BOLT11 invoices; handle macaroon+preimage return.
  - **Files**: `crates/briefcase-payments/src/l402_lnd.rs` (new)
  - **Done when**: can pay invoices on regtest and complete L402 flow end-to-end.
  - **Verify**: `just test-l402-lnd`
  - _Reqs: FR-9_

- [x] 8.2 Implement L402 backend with Core Lightning (optional but recommended)
  - **Do**: implement payment via CLN JSON-RPC; share common code with LND backend.
  - **Files**: `crates/briefcase-payments/src/l402_cln.rs` (new)
  - **Done when**: CLN backend passes regtest integration tests.
  - **Verify**: `just test-l402-cln`

- [x] 8.3 Lightning regtest harness in CI
  - **Do**: add docker-compose harness for LND/CLN regtest; ensure tests are stable/time-bounded.
  - **Files**: `docker/lightning-regtest/*`, `.github/workflows/*`
  - **Done when**: CI runs L402 tests reliably.
  - **Verify**: `just test-lightning`

## Phase 9: Revocation + Status Lists

- [x] 9.1 OAuth revoke/forget flows
  - **Do**: add revoke endpoints; implement provider-optional RFC7009 call; always delete local secret.
  - **Files**: `apps/briefcased/src/oauth.rs`, `apps/briefcase-extension/*`, `apps/briefcase-cli/*`
  - **Done when**: revocation works end-to-end and removes secrets.
  - **Verify**: integration tests.
  - _Reqs: FR-10_

- [x] 9.2 VC status list verification
  - **Do**: implement status-list fetch and checks; safe caching; fail-closed vs require-approval policy knob.
  - **Files**: `crates/briefcase-revocation/*`, `apps/briefcased/src/provider.rs`
  - **Done when**: revoked VCs are rejected and logged/receipted.
  - **Verify**: unit + integration tests.

- [x] 9.3 Capability revocation profile
  - **Do**: update provider gateway to support `jti` denylist; add revoke endpoint; daemon handles revocation signals.
  - **Files**: `apps/agent-access-gateway/src/main.rs`, `apps/briefcased/src/provider.rs`
  - **Done when**: revoked capabilities cannot be used; daemon refreshes appropriately.
  - **Verify**: integration tests.

## Phase 10: AI Policy Compiler + Consent Copilot + Anomaly Detection

- [x] 10.1 Define AI interface and “non-authoritative” invariants
  - **Do**: add `crates/briefcase-ai` with strict rules; add test corpus ensuring AI can’t bypass policy.
  - **Files**: `crates/briefcase-ai/*`, `docs/AI_SAFETY.md`
  - **Done when**: AI is optional and cannot influence allow decisions except by requiring approval.
  - **Verify**: `cargo test -p briefcase-ai`
  - _Reqs: FR-11, AC-8.2_

- [x] 10.2 Implement policy compiler (proposal + diff + apply)
  - **Do**: implement compile endpoint returning Cedar diffs; require user confirmation (and optional mobile signer) to apply.
  - **Files**: `apps/briefcased/src/policy_compiler.rs` (new), `apps/briefcase-extension/*`
  - **Done when**: user can type natural language policy and apply a verified diff.
  - **Verify**: e2e tests with deterministic stub LLM.

- [x] 10.3 Implement consent copilot + anomaly dashboard
  - **Do**: generate summaries for approvals; detect spend spikes/new domains/output poisoning patterns from receipts stream.
  - **Files**: `crates/briefcase-ai/*`, `apps/briefcase-extension/*`, `apps/briefcase-ui/*`
  - **Done when**: anomalies appear as alerts; approvals have plain-language summaries.
  - **Verify**: unit tests + UI snapshot tests.

## Phase 11: Enterprise Control Plane (Reference)

- [x] 11.1 Implement control plane API (RBAC, policy bundles, receipt ingestion)
  - **Do**: build `apps/briefcase-control-plane` server with Postgres; define API contracts; issue signed policy bundles.
  - **Files**: `apps/briefcase-control-plane/*`, `deploy/docker-compose.enterprise.yml`
  - **Done when**: a client can enroll, fetch policy, and upload receipts; auditors can query.
  - **Verify**: docker-compose e2e tests.
  - _Reqs: FR-12_

- [x] 11.2 Integrate device enrollment and policy sync into daemon
  - **Do**: add enroll command; periodic sync; signature verification; safe rollback on failure.
  - **Files**: `apps/briefcased/src/control_plane.rs` (new), `apps/briefcase-cli/*`, `apps/briefcase-extension/*`
  - **Done when**: policy is centrally managed and enforced locally.
  - **Verify**: e2e tests.

- [x] 11.3 Optional remote custody mode (HSM/Vault)
  - **Do**: implement remote signer backend in `briefcase-keys`; add control plane service for signing.
  - **Files**: `crates/briefcase-keys/src/remote.rs` (new), `apps/briefcase-control-plane/*`
  - **Done when**: remote signer can be used for DPoP/capabilities while preserving “no raw secrets to agent”.
  - **Verify**: integration tests with SoftHSM/Vault dev mode.

## Phase 12: Production Hardening + Release

- [x] 12.1 Add fuzzing + security regression suite
  - **Do**: add `cargo-fuzz` targets for MCP parsing, x402/L402 parsing, receipt ingestion; add “no secrets in logs” tests.
  - **Files**: `fuzz/*`, `.github/workflows/security.yml`
  - **Done when**: fuzz targets run in CI on schedule; regressions blocked.
  - **Verify**: `cargo fuzz run ...` (CI job)

- [ ] 12.2 Observability (OpenTelemetry end-to-end)
  - **Do**: add OTel traces for tool execution chain across gateway/daemon/sandbox; metrics for spend/approvals.
  - **Files**: `apps/briefcased/*`, `apps/mcp-gateway/*`, `docs/OBSERVABILITY.md`
  - **Done when**: trace shows end-to-end request with policy decision and upstream call.
  - **Verify**: integration test + local demo.

- [ ] 12.3 Release automation for multi-artifact repo
  - **Do**: add GH Actions workflows for extension build/package, mobile builds (CI build only), control plane container builds, SBOMs.
  - **Files**: `.github/workflows/*`, `docs/RELEASING.md`
  - **Done when**: tagged release produces signed artifacts for daemon/gateway/cli/ui and versioned artifacts for extension/control plane.
  - **Verify**: create a test tag and validate release assets.
