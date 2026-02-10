# Requirements: Move Credential Briefcase from reference implementation to production-grade universal agentic auth platform

## Goal

Define and execute a GA program that turns the existing strong reference architecture into a production-grade, interoperable, and operationally mature agentic auth platform.

The resulting system must preserve existing security invariants while adding explicit compatibility, hardening, and reliability guarantees that can be validated by tests and external audits.

## Users / personas

- Platform security engineer deploying/operating briefcase in production.
- Provider integration engineer exposing protected tools/APIs to agent ecosystems.
- Enterprise admin/compliance team requiring policy, audit, and incident controls.
- Application developer integrating MCP clients with minimal trust assumptions.

## User stories

### US-1: Security boundary assurance

**As a** platform security engineer
**I want** machine-verifiable guarantees that secrets never cross the untrusted agent boundary
**So that** I can deploy this system in adversarial environments.

**Acceptance criteria**
- AC-1.1: Every tool execution path (local tool, remote MCP, provider HTTP, payment helper) is covered by tests asserting no raw secret leakage in responses/logs/receipts.
- AC-1.2: Any new auth/payment path is blocked from merge unless secret-redaction and output-firewall checks pass in CI.
- AC-1.3: Independent adversarial test suite (prompt injection/output poisoning/replay attempts) passes for release candidates.

### US-2: Interoperable auth flows

**As a** provider integration engineer
**I want** standards-profiled OAuth/capability/PoP behavior with a compatibility suite
**So that** third-party providers can integrate without relying on repo-specific assumptions.

**Acceptance criteria**
- AC-2.1: Capability token profile v1.0 is versioned and documented, with conformance tests for both daemon and provider reference gateway.
- AC-2.2: DPoP, token refresh, revocation, and replay-defense semantics are validated against at least 3 non-reference provider implementations.
- AC-2.3: Documentation and implementation remain in lockstep via doc-vs-code conformance tests.

### US-3: Deployment universality

**As an** enterprise admin
**I want** equivalent security controls across local, enterprise, and Windows/macOS/Linux deployment profiles
**So that** policy behavior is predictable regardless of environment.

**Acceptance criteria**
- AC-3.1: Windows named-pipe local IPC is implemented and validated with the same auth semantics as Unix sockets.
- AC-3.2: Enterprise mode includes hardened device enrollment, signed policy bundle rollout, and auditable receipt ingestion with replay protection.
- AC-3.3: Multi-user host deployment guidance and enforcement options are tested and documented.

### US-4: Reliability and operability

**As an** SRE/operator
**I want** measurable SLOs and safe rollout/recovery mechanics
**So that** the platform can run continuously with predictable risk.

**Acceptance criteria**
- AC-4.1: Availability, latency, and approval-path SLOs are defined and continuously measured.
- AC-4.2: Migrations are reversible; upgrade/downgrade compatibility is tested for N-1 releases.
- AC-4.3: Incident response playbooks (credential compromise, provider outage, receipt chain failure) are documented and exercised.

### US-5: Governance and release trust

**As a** compliance/audit stakeholder
**I want** signed, reproducible releases and evidence artifacts
**So that** security and compliance reviews can be completed without bespoke engineering effort.

**Acceptance criteria**
- AC-5.1: Every release includes provenance attestations, SBOM, vulnerability report, and compatibility report.
- AC-5.2: Security policy defines supported versions, patch SLAs, and embargoed vulnerability handling.
- AC-5.3: Release qualification requires passing all GA security/interoperability checklists.

## Functional requirements (FR)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| FR-1 | Implement a versioned "Agentic Auth Compatibility Profile" (AACP) for gateway, daemon, provider, and control plane semantics. | High | Profile spec + automated conformance suite in CI |
| FR-2 | Add comprehensive redaction/leak-prevention assertions across logs, APIs, receipts, and traces. | High | Secret canary tests + fuzz + regression suite |
| FR-3 | Finalize approval lifecycle interoperability for MCP clients, including retries/tokens/provenance metadata. | High | MCP client integration matrix tests |
| FR-4 | Implement production-grade provider compatibility kit (OAuth, DPoP, capability, revocation, payment rails) with contract tests. | High | Provider contract test harness |
| FR-5 | Harden local IPC and host isolation per OS (Unix socket permissions, Windows named pipes, loopback policy fallback). | High | Platform-specific integration tests |
| FR-6 | Strengthen enterprise control-plane guarantees (signed bundles, anti-replay, RBAC scope boundaries, receipt integrity checks). | High | End-to-end enterprise security tests |
| FR-7 | Add rollout safety controls: feature flags, canary, policy dry-run, and rollback tooling. | Medium | Release rehearsal tests |
| FR-8 | Publish support matrix and compatibility guarantees for MCP clients, providers, and deployment modes. | Medium | Versioned docs + compatibility CI gates |
| FR-9 | Provide operational runbooks and automatic health diagnostics for auth, policy, approvals, and payment pathways. | Medium | Runbook drills + smoke checks |
| FR-10 | Establish release evidence pipeline (SBOM/provenance/signatures/security report) as mandatory gate. | High | Release workflow checks |

## Non-functional requirements (NFR)

| ID | Category | Target | Notes |
|----|----------|--------|-------|
| NFR-1 | Security | Zero known critical secret-leak paths in supported configurations | Enforced by canary tests + external assessment |
| NFR-2 | Reliability | 99.9% daemon availability in production profile | Measured via OTEL + health checks |
| NFR-3 | Performance | p95 tool call latency overhead from policy/risk/receipts <= 150ms (excluding upstream) | Benchmarked per release |
| NFR-4 | Interoperability | 100% pass of AACP conformance suite for GA-labeled components | Required for release |
| NFR-5 | Operability | MTTR playbook execution under 30 minutes for top 5 incident classes | Quarterly game-days |
| NFR-6 | Maintainability | All user-facing auth/payment protocols are versioned and backward compatible for one minor release | Enforced by compatibility tests |

## Out of scope / non-goals

- Replacing Cedar with a new policy engine.
- Turning AI/risk scoring into authoritative allow logic.
- Guaranteeing compatibility with every proprietary provider variant without profile mapping.
- Shipping managed SaaS control-plane unless explicitly scoped in a follow-up spec.

## Assumptions

- Existing trust boundary (daemon authoritative, gateway agent-facing) remains unchanged.
- Capability token and DPoP concepts remain core primitives.
- Hardware-backed key custody continues to be best-effort by platform capabilities.
- Existing CI and release workflows can be expanded without replacing repository tooling.

## Dependencies

- Rust workspace quality gates and existing CI workflows.
- Provider ecosystem partners for interoperability testing.
- Security assessment capacity (internal or third-party).
- Control-plane and enterprise deployment environments for staged validation.

## Success metrics

1. GA checklist completion rate: 100% of FR/AC items signed off.
2. Interop score: >= 3 independent provider implementations pass AACP tests.
3. Security score: 0 critical/0 high unresolved findings at GA cutoff.
4. Reliability score: SLOs met for 30 consecutive days in staging.
5. Release trust score: every release artifact includes signatures, SBOM, and provenance attestation.

## GA exit criteria and sign-off

The program is considered "universally done" only when:

- Automatable gates are green (quality gates + conformance suites + release evidence generation), and
- Non-automatable gates are signed off (soak, external review, launch approvals).

The source of truth for the release-grade GA checklist is:

- `docs/RELEASING.md` ("GA exit criteria (v1.0.0)")
- `docs/COMPATIBILITY_PROFILE.md` (scope + normative requirements)
- `docs/SUPPORT_MATRIX.md` (supported platforms + profile lifecycle)
