# Tasks: Move Credential Briefcase from reference implementation to production-grade universal agentic auth platform

## Overview

Total tasks: 36

POC-first workflow:
1. Make it work (POC)
2. Refactor
3. Tests
4. Quality gates
5. Release qualification

## Task format

For each task, include:

- **Do**: exact steps
- **Files**: paths to create/modify
- **Done when**: explicit success criteria
- **Verify**: command(s) or manual checks

## Phase 0: Program Baseline And GA Definition

- [x] 0.1 Freeze GA definition and profile scope
  - **Do**: define v1.0 GA exit criteria, support matrix, and compatibility profile boundaries.
  - **Files**: `docs/COMPATIBILITY_PROFILE.md`, `docs/RELEASING.md`, `specs/universal-agentic-auth-ga/requirements.md`
  - **Done when**: GA criteria are explicit, versioned, and approved.
  - **Verify**: manual review checklist sign-off.
  - _Reqs: FR-1, FR-8, AC-5.3_

- [x] 0.2 Build docs-vs-code drift check for auth profile
  - **Do**: add tests that compare capability claim schema/headers in docs vs implementation.
  - **Files**: `crates/briefcase-core/tests/docs_profile_consistency.rs`, `docs/CAPABILITY_TOKENS.md`
  - **Done when**: CI fails if profile docs diverge from wire behavior.
  - **Verify**: `cargo test -p briefcase-core --test docs_profile_consistency`
  - _Reqs: FR-1, AC-2.3_

- [x] 0.3 Add spec-level progress tracking
  - **Do**: initialize `.progress.md` with phase ownership and milestone checkpoints.
  - **Files**: `specs/universal-agentic-auth-ga/.progress.md`
  - **Done when**: milestones and owners are visible and current.
  - **Verify**: manual check.

- [x] 0.4 Quality checkpoint
  - **Do**: run core repo quality gates before implementation begins.
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`
  - **Done when**: all checks pass on current baseline.

## Phase 1: Compatibility Profile (AACP) POC

- [x] 1.1 Author AACP v1.0 normative specification
  - **Do**: define mandatory claims, headers, error codes, replay semantics, approval retry semantics, provenance envelope.
  - **Files**: `docs/COMPATIBILITY_PROFILE.md` (new), `docs/CAPABILITY_TOKENS.md`, `docs/ARCHITECTURE.md`
  - **Done when**: profile has normative MUST/SHOULD language and versioning policy.
  - **Verify**: manual RFC-style review.
  - _Reqs: FR-1, FR-8, AC-2.1_

- [x] 1.2 Add profile mode to daemon and gateway
  - **Do**: introduce `BRIEFCASE_PROFILE_MODE={reference,staging,ga}` and branch strictness behavior.
  - **Files**: `apps/briefcased/src/main.rs`, `apps/briefcased/src/app.rs`, `apps/mcp-gateway/src/main.rs`, `crates/briefcase-core/src/types.rs`
  - **Done when**: profile mode is visible in identity/diagnostics and affects enforcement knobs.
  - **Verify**: `cargo test -p briefcased profile_and_compat_diagnostics_surface_mode` and `cargo test -p mcp-gateway`
  - _Reqs: FR-1, FR-3_

- [x] 1.3 Standardize approval lifecycle for MCP clients
  - **Do**: implement profile-compliant approval-token retry semantics and metadata fields for client interoperability.
  - **Files**: `apps/mcp-gateway/src/main.rs`, `crates/briefcase-mcp/src/types.rs`, `crates/briefcase-api/src/types.rs`
  - **Done when**: at least two MCP client implementations pass approval retry conformance tests.
  - **Verify**: `cargo test -p mcp-gateway approval_interop_*`
  - _Reqs: FR-3, AC-2.1_

- [x] 1.4 Provider gateway alignment to AACP v1.0
  - **Do**: align capability claims/errors/replay responses to profile schema and version markers.
  - **Files**: `apps/agent-access-gateway/src/main.rs`, `docs/CAPABILITY_TOKENS.md`
  - **Done when**: provider conformance suite passes with AACP v1.0.
  - **Verify**: `cargo test -p agent-access-gateway aacp_*`
  - _Reqs: FR-4, AC-2.1_

- [x] 1.5 POC checkpoint (end-to-end)
  - **Do**: demonstrate agent->gateway->daemon->provider call under profile mode with approval and PoP.
  - **Files**: `apps/mcp-gateway/src/main.rs` (tests)
  - **Done when**: e2e smoke passes in CI.
  - **Verify**: `cargo test -p mcp-gateway e2e_profile_smoke_`
  - _Reqs: AC-2.1, AC-4.1_

- [x] 1.6 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 2: Security Hardening (Boundary, Leakage, Replay)

- [x] 2.1 Expand secret canary regression suite across all execution paths
  - **Do**: add canary tokens for refresh/access/capability/payment proof and assert absence in logs, receipts, responses, OTEL spans.
  - **Files**: `apps/briefcased/src/app.rs` (expanded `no_secrets_in_logs_regression`), `crates/briefcase-otel/src/lib.rs`
  - **Done when**: leakage tests cover local tool, remote MCP, provider flow, control-plane sync.
  - **Verify**: `cargo test -p briefcased no_secrets_in_logs_regression`
  - _Reqs: FR-2, AC-1.1, AC-1.2_

- [x] 2.2 Harden outbound network policy defaults in GA mode
  - **Do**: enforce HTTPS-only (except loopback) and strict deny-by-default for any new outbound path.
  - **Files**: `apps/briefcased/src/app.rs`, `apps/briefcased/src/provider.rs`, `apps/briefcased/src/remote_mcp.rs`
  - **Done when**: policy bypass attempts fail closed and are receipted.
  - **Verify**: `cargo test -p briefcased egress_policy_*`
  - _Reqs: FR-2, FR-5_

- [x] 2.3 Replay defense hardening and bounded cache policy
  - **Do**: standardize replay cache limits/TTL behavior for DPoP and payment nonces.
  - **Files**: `apps/agent-access-gateway/src/main.rs`, `apps/briefcased/src/provider.rs`, `docs/COMPATIBILITY_PROFILE.md`
  - **Done when**: replay attacks fail deterministically without unbounded memory growth.
  - **Verify**: `cargo test -p agent-access-gateway replay_*`
  - _Reqs: FR-4, AC-1.3_

- [x] 2.4 Threat model GA revision
  - **Do**: replace v0.1 assumptions with GA threat model, include shared-host and enterprise threat classes.
  - **Files**: `docs/THREAT_MODEL.md`
  - **Done when**: threat model includes explicit mitigations and residual risks per deployment mode.
  - **Verify**: manual security architecture review.
  - _Reqs: FR-2, FR-6_

- [x] 2.5 External security assessment harness preparation
  - **Do**: package reproducible adversarial test runner and evidence collection for third-party testing.
  - **Files**: `tests/adversarial/*`, `docs/OPERATIONS.md`, `.github/workflows/security.yml`
  - **Done when**: one-command execution produces assessment-ready report bundle.
  - **Verify**: `bash scripts/run_security_assessment.sh` (new)
  - _Reqs: AC-1.3, AC-5.1_

- [x] 2.6 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 3: Interoperability And Provider Contract Kit

- [x] 3.1 Build provider conformance harness framework
  - **Do**: create contract tests for OAuth, token exchange, DPoP, revocation, error mapping, and capability caveats.
  - **Files**: `tests/compat/provider_contract/*` (new), `crates/briefcase-api/src/types.rs`
  - **Done when**: harness can run against reference gateway and external providers.
  - **Verify**: `cargo test provider_contract_`
  - _Reqs: FR-4, AC-2.2_

- [x] 3.2 Support matrix declaration and enforcement
  - **Do**: codify supported MCP client/provider/version matrix and enforce via CI matrix jobs.
  - **Files**: `docs/SUPPORT_MATRIX.md` (new), `.github/workflows/ci.yml`
  - **Done when**: unsupported integrations fail with explicit profile mismatch diagnostics.
  - **Verify**: `bash scripts/validate_support_matrix.sh`
  - _Reqs: FR-8, AC-2.2_

- [x] 3.3 Remote MCP compatibility profile enforcement
  - **Do**: require remote server metadata/profile compatibility before enabling tool routing in GA mode.
  - **Files**: `apps/briefcased/src/remote_mcp.rs`, `apps/briefcased/src/app.rs`, `crates/briefcase-core/src/types.rs`
  - **Done when**: incompatible remote MCP endpoints are blocked with actionable diagnostics.
  - **Verify**: `cargo test -p briefcased remote_mcp_profile_*`
  - _Reqs: FR-1, FR-4_

- [x] 3.4 Documentation alignment (reference vs GA)
  - **Do**: separate reference behaviors from GA guarantees across architecture/policy/capability docs.
  - **Files**: `docs/ARCHITECTURE.md`, `docs/POLICY.md`, `docs/CAPABILITY_TOKENS.md`, `README.md`
  - **Done when**: docs explicitly state guaranteed behavior and optional/reference behavior.
  - **Verify**: manual docs audit + docs consistency test.
  - _Reqs: AC-2.3, FR-8_

- [x] 3.5 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 4: Platform Hardening And Deployment Universality

- [x] 4.1 Implement Windows named-pipe IPC transport
  - **Do**: add named-pipe server/client path and preserve daemon auth semantics.
  - **Files**: `apps/briefcased/src/app.rs`, `crates/briefcase-api/src/client.rs`, `apps/mcp-gateway/src/main.rs`
  - **Done when**: Windows default transport is named pipe with integration tests.
  - **Verify**: `cargo test -p briefcased windows_ipc_*` (Windows runner)
  - _Reqs: FR-5, AC-3.1_

- [x] 4.2 Multi-user host hardening options
  - **Do**: add optional strict mode to prevent cross-user state access and document host isolation patterns.
  - **Files**: `apps/briefcased/src/main.rs`, `apps/briefcased/src/middleware.rs`, `docs/OPERATIONS.md`
  - **Done when**: shared-host risk mitigations are enforceable and tested.
  - **Verify**: `cargo test -p briefcased host_isolation_*`
  - _Reqs: FR-5, AC-3.3_

- [x] 4.3 Control-plane enrollment and token hardening
  - **Do**: add stronger enrollment token lifecycle constraints and anti-replay checks for control-plane sync.
  - **Files**: `apps/briefcased/src/control_plane.rs`, `apps/briefcase-control-plane/src/main.rs`, `crates/briefcase-control-plane-api/src/types.rs`
  - **Done when**: enrollment/sync replay and stale-token attempts are rejected.
  - **Verify**: `cargo test control_plane_enroll_*`
  - _Reqs: FR-6, AC-3.2_

- [x] 4.4 Policy bundle compatibility guards
  - **Do**: require profile-version compatibility in signed policy bundles; reject incompatible bundles safely.
  - **Files**: `apps/briefcase-control-plane/src/main.rs`, `apps/briefcased/src/control_plane.rs`, `docs/POLICY.md`
  - **Done when**: daemon safely ignores incompatible policy updates and records evidence.
  - **Verify**: `cargo test policy_bundle_compat_*`
  - _Reqs: FR-6, AC-3.2_

- [x] 4.5 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 5: Reliability, Diagnostics, and Incident Readiness

- [x] 5.1 Define SLOs and operational diagnostics endpoints
  - **Do**: add latency/availability/error-budget metrics and `/v1/diagnostics/*` endpoints.
  - **Files**: `apps/briefcased/src/app.rs`, `crates/briefcase-otel/src/lib.rs`, `docs/OPERATIONS.md`
  - **Done when**: SLO dashboards can be built from emitted metrics/traces.
  - **Verify**: `cargo test -p briefcased observability_*`
  - _Reqs: FR-9, AC-4.1_

- [x] 5.2 Migration compatibility tests (N-1)
  - **Do**: add upgrade/downgrade integration tests for DB schema, receipt chain, policy bundles, and provider config.
  - **Files**: `tests/migration/*` (new), `apps/briefcased/src/db.rs`
  - **Done when**: N-1 upgrade and rollback path passes in CI.
  - **Verify**: `cargo test migration_*`
  - _Reqs: FR-7, AC-4.2_

- [x] 5.3 Incident playbooks and drills
  - **Do**: create runbooks for token compromise, provider outage, control-plane outage, and receipt verification failure.
  - **Files**: `docs/OPERATIONS.md`, `docs/THREAT_MODEL.md`
  - **Done when**: runbooks include trigger, diagnosis, mitigation, rollback, and evidence steps.
  - **Verify**: quarterly game-day checklist.
  - _Reqs: FR-9, AC-4.3_

- [x] 5.4 Add automatic health triage tool
  - **Do**: implement CLI diagnostics command that validates daemon/gateway/profile/provider/control-plane state.
  - **Files**: `apps/briefcase-cli/src/main.rs`, `crates/briefcase-api/src/client.rs`
  - **Done when**: command reports red/yellow/green statuses with remediation hints.
  - **Verify**: `cargo run -p briefcase-cli -- diagnostics check`
  - _Reqs: FR-9_

- [x] 5.5 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 6: Release Trust, Evidence, and Support Policy

- [x] 6.1 Strengthen release qualification pipeline
  - **Do**: add mandatory GA qualification gate producing signed compatibility/security reports.
  - **Files**: `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `.github/workflows/security.yml`
  - **Done when**: release job fails without qualification artifacts.
  - **Verify**: dry-run release workflow on staging tag.
  - _Reqs: FR-10, AC-5.1_

- [x] 6.2 Security policy upgrade to GA support model
  - **Do**: define supported versions, patch SLAs, disclosure timelines, and incident communication expectations.
  - **Files**: `SECURITY.md`, `docs/RELEASING.md`
  - **Done when**: security support policy is explicit and enforceable.
  - **Verify**: manual policy review.
  - _Reqs: AC-5.2_

- [x] 6.3 Release evidence manifest
  - **Do**: generate machine-readable manifest linking artifact hashes, SBOM, provenance attestations, compatibility results.
  - **Files**: `docs/RELEASING.md`, `scripts/release_manifest.sh` (new)
  - **Done when**: each release contains complete evidence manifest.
  - **Verify**: `bash scripts/release_manifest.sh && bash scripts/release_manifest.sh --verify dist/release-manifest.json`
  - _Reqs: FR-10, AC-5.1_

- [x] 6.4 Publish support and deprecation policy
  - **Do**: define profile version support windows and deprecation process.
  - **Files**: `docs/SUPPORT_MATRIX.md`, `docs/COMPATIBILITY_PROFILE.md`
  - **Done when**: profile lifecycle is documented and referenced in release process.
  - **Verify**: manual docs review.
  - _Reqs: FR-8, AC-5.3_

- [x] 6.5 Quality checkpoint
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`

## Phase 7: GA Certification And Launch Readiness

- [x] 7.1 Full GA conformance run
  - **Do**: run complete compatibility/provider/security/adversarial suite on release candidate.
  - **Files**: `tests/compat/*`, `tests/adversarial/*`, `.github/workflows/ci.yml`
  - **Done when**: all GA-required suites pass on target platforms.
  - **Verify**: CI evidence bundle attached to release candidate.
  - _Reqs: AC-1.3, AC-2.2, AC-5.3_

- [ ] 7.2 Staging soak and SLO validation
  - **Do**: run 30-day staging soak with production-like workloads and track error budgets.
  - **Files**: `docs/OPERATIONS.md`, observability dashboards/configs
  - **Done when**: SLO compliance achieved for 30 consecutive days.
  - **Verify**:
    - Use `cargo run -p briefcase-cli -- diagnostics soak --duration-secs 3600 --interval-ms 1000 --tool quote --out dist/soak-report.json` (or equivalent) to generate periodic JSON evidence.
    - Attach the 30-day SLO report (dates + dashboards + soak reports) to the GA release ticket.
  - _Reqs: AC-4.1_

- [ ] 7.3 External security review sign-off
  - **Do**: execute third-party security assessment and resolve findings to policy thresholds.
  - **Files**: `SECURITY.md`, release evidence artifacts
  - **Done when**: zero unresolved critical/high findings at GA cutoff.
  - **Verify**:
    - Run `bash scripts/ga_qualification.sh --mode release --label vX.Y.Z` to generate evidence bundles.
    - Package a reviewer-friendly tarball: `bash scripts/security_review_packet.sh --label vX.Y.Z`.
    - Attach the signed assessment report to the GA release ticket and reference it from `docs/GA_SIGNOFF_v1.0.0.md`.
  - _Reqs: AC-1.3, AC-5.1_

- [ ] 7.4 GA launch decision gate
  - **Do**: run final checklist across security, interoperability, operations, and release evidence.
  - **Files**: `docs/RELEASING.md`, `docs/SUPPORT_MATRIX.md`, `specs/universal-agentic-auth-ga/.progress.md`
  - **Done when**: release committee approves `v1.0.0` cut.
  - **Verify**:
    - Fill `docs/GA_SIGNOFF_v1.0.0.md` (no `REPLACE_ME_*` placeholders).
    - Run: `bash scripts/check_ga_signoff.sh docs/GA_SIGNOFF_v1.0.0.md`
  - _Reqs: AC-5.3_

- [x] 7.5 Final quality gate
  - **Verify**: `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test`
  - **Done when**: all mandatory quality gates pass immediately before tag.

## Parallelization guidance

- Stream A (protocol/profile): 1.x + 3.x
- Stream B (security hardening): 2.x + 4.x
- Stream C (ops/release): 5.x + 6.x
- Convergence milestones: 1.5, 3.5, 5.5, 6.5, 7.1

## Exit criteria summary

- All High-priority FRs complete.
- All ACs pass with reproducible evidence.
- GA quality gates and external review sign-offs complete.
- Support/deprecation and incident response policies published.
