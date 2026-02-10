---
spec: universal-agentic-auth-ga
phase: research
created: 2026-02-09T21:23:35+00:00
---

# Research: universal-agentic-auth-ga

## Goal

Move Credential Briefcase from reference implementation to production-grade universal agentic auth platform.

## Executive summary

- Feasibility: High for a production-grade platform, Medium for truly universal interoperability in one release train.
- Current baseline: the repo already has strong enforcement primitives (policy, approvals, budgets, sandbox, receipts, PoP/capability flows, multi-platform CI).
- Main gap: several components and docs are explicitly v0.1/reference/demo; production hardening, interoperability contracts, and operational maturity are not yet complete.

## What “universally done” means (working definition)

For this program, "universally done" is achieved only when all of the following are true:

1. Security boundary completeness: raw secrets never leave trusted boundary under tested adversarial scenarios, with independent verification.
2. Protocol interoperability: standards-profiled auth/tooling flows that work across heterogeneous provider ecosystems, not only reference endpoints.
3. Deployment universality: local, enterprise, and cloud-managed modes with equivalent policy/security semantics.
4. Operational maturity: defined SLOs, upgrade/migration paths, incident response, and continuous security evidence.
5. Product maturity: documented compatibility profile, clear support policy, deterministic releases, and long-term maintenance process.

## Codebase scan

### Existing strengths confirmed in code

- Trust boundary is explicit and enforced:
  - Agent talks to gateway; gateway forwards to daemon.
  - `README.md`, `docs/ARCHITECTURE.md`, `apps/mcp-gateway/src/main.rs`, `apps/briefcased/src/app.rs`.
- Daemon-side enforcement stack is real, not just documentation:
  - JSON schema input validation, Cedar policy decisions, approval token binding, risk tightening, budget gating, sandbox violations, output firewalling, receipts.
  - `apps/briefcased/src/app.rs`, `apps/briefcased/src/tools.rs`, `apps/briefcased/src/firewall.rs`.
- Provider auth strategy and PoP are implemented:
  - VC/OAuth/payment token minting order, DPoP usage, redirect disabled.
  - `apps/briefcased/src/provider.rs`, `apps/agent-access-gateway/src/main.rs`.
- Receipt chain and observability scaffolding exist:
  - hash-chained receipts and OTEL spans/metrics.
  - `crates/briefcase-receipts`, `docs/OBSERVABILITY.md`.

### Material gaps to close for GA

1. Reference/demo posture still explicit across key surfaces:
- Docs and code repeatedly mark v0.1/reference/demo behavior.
- `docs/THREAT_MODEL.md`, `docs/CAPABILITY_TOKENS.md`, `docs/ARCHITECTURE.md`, `docs/RELEASING.md`, `apps/agent-access-gateway/src/main.rs`, `crates/briefcase-payments/src/lib.rs`.

2. Documentation/protocol drift:
- Capability token doc describes older `pop_pk_b64` style; implementation uses DPoP + `cnf.jkt` claims.
- `docs/CAPABILITY_TOKENS.md` vs `apps/agent-access-gateway/src/main.rs`.

3. Platform hardening gaps explicitly called out:
- Windows daemon IPC currently loopback TCP; named pipes planned.
- `docs/THREAT_MODEL.md`.

4. Multi-user/tenant hardening is not complete:
- Threat model assumes per-user install and local-first trust boundary.
- Enterprise model exists but is “reference” with additional hardening implied.

5. Production provider compatibility is incomplete:
- Current provider gateway is a strong reference harness but still quote-centric and demo-biased.
- Need provider compatibility profiles and conformance test kits for third-party integrations.

6. Security assurance process is partial:
- Good CI/security workflows exist (audit/fuzz/release signing), but no formal security SLOs, external pen-test gating, or compatibility certification program yet.

7. Gateway approval UX/protocol completeness needs finalization:
- Approval retry semantics are modeled in daemon APIs, but MCP/gateway-level end-to-end flows must be standardized and validated against multiple clients.

## Constraints

- Hard invariants in `AGENTS.md` must never regress:
  - no raw secrets in logs/responses/storage outside trusted boundary.
  - `briefcased` remains authority for policy/payments/keys/audit.
- Existing architecture must remain composable across local and enterprise modes.
- Rust workspace quality gates are mandatory for each phase:
  - `cargo fmt --all`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test`

## Risks

- Scope risk: "universal" can become unbounded if compatibility targets are not explicitly versioned.
- Security regression risk: broad refactors in auth/payment/network paths can accidentally widen trust boundary.
- Interop risk: provider ecosystems vary in OAuth/DPoP behavior and transport assumptions.
- Operational risk: adding enterprise-grade controls may degrade local-first developer UX if not isolated by deployment profile.

## Open questions for requirements

1. What exact external standards profile must be certified at GA (mandatory vs optional RFC features)?
2. What support matrix is required at launch (OS versions, MCP client classes, provider classes)?
3. Is "universal" targeting self-hosted only, or managed cloud control-plane as a first-class mode?
4. What compliance bar is required (SOC 2, ISO 27001 readiness, FIPS-validated modules, etc.)?
5. What SLO/SLA commitments are expected for enterprise customers?

## Sources

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/CAPABILITY_TOKENS.md`
- `docs/POLICY.md`
- `docs/AI_SAFETY.md`
- `docs/OBSERVABILITY.md`
- `docs/RELEASING.md`
- `apps/briefcased/src/app.rs`
- `apps/briefcased/src/provider.rs`
- `apps/mcp-gateway/src/main.rs`
- `apps/agent-access-gateway/src/main.rs`
- `.github/workflows/ci.yml`
- `.github/workflows/security.yml`
