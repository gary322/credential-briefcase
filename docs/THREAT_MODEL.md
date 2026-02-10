# Threat Model (AACP v1)

## Assumptions

- The LLM runtime is untrusted and may be prompt-injected.
- Tool outputs are untrusted and may attempt output poisoning.
- Remote MCP and provider services may be malicious or compromised.
- Local host hardening differs by OS and deployment profile.

## Security goals

- Never expose raw long-lived secrets to agent-facing surfaces.
- Keep authorization decisions authoritative in policy/budget/approval engines.
- Minimize blast radius using short-lived caveated capabilities + PoP + replay defenses.
- Produce auditable, tamper-evident execution records.

## Trust boundaries

- Trusted boundary: `briefcased` daemon + secret/key stores + policy engine + receipt store.
- Agent boundary: `mcp-gateway` is the only agent-facing MCP server.
- Admin boundary: CLI/UI/extension/mobile signer are approval/admin surfaces, not secret exfiltration channels.

## Key controls

- Bearer-authenticated daemon APIs with constant-time token comparison.
- Secret storage abstraction (`keyring`/encrypted file; memory backend only for tests/dev).
- Non-exportable signing key backends where supported.
- JSON-schema validation before tool execution.
- Cedar policy allow/deny + approval derivation semantics.
- Risk scoring is non-authoritative and can only tighten to approval.
- Category budgets and approval overrides.
- Per-tool sandbox deny-by-default egress/filesystem policies.
- Output firewall filtering before agent-visible return values.
- Chained-hash receipts for all tool-call outcomes.
- Capability tokens with TTL/max_calls and optional DPoP `cnf.jkt` binding.
- Replay protection for DPoP JTIs and payment nonces.

## Residual risks

- Shared/multi-user hosts require additional OS isolation hardening.
- Windows local IPC currently uses loopback TCP; named-pipe hardening remains planned.
- Profile `reference` mode allows less strict defaults for developer ergonomics.
- Third-party provider correctness still depends on external contract adherence.

## Deployment profiles

- `reference`: dev/demo profile, permissive local assumptions.
- `staging`: pre-production verification profile.
- `ga`: production profile, strict compatibility/security expectations.

## Validation strategy

- CI quality gates: fmt/clippy/tests.
- Adversarial regressions: secret canary + replay + approval-binding paths.
- Receipt integrity checks in daemon and control-plane pathways.
- Release evidence: signed artifacts, SBOM, and compatibility docs.
