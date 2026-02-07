# Threat Model (v0.1)

## Assumptions

- The LLM is untrusted and may be prompt-injected.
- Tool outputs are untrusted (output poisoning).
- The local machine is the trust boundary; other local processes should not gain access to secrets by default.

## Goals

- Never provide raw long-lived secrets (refresh tokens, private keys) to the agent runtime.
- Minimize blast radius with approvals, budgets, and short-lived capability tokens.
- Provide auditability via tamper-evident receipts.

## Key Controls Implemented

- **Local auth token**: `briefcased` requires `Authorization: Bearer <token>` for its API. Token is stored on disk with restrictive permissions on Unix.
- **Secret storage**: refresh tokens and private key material are stored via `briefcase-secrets` (keyring by default; encrypted-file backend supported).
- **Hardware-backed keys (where available)**: signing keys can be non-exportable (PKCS#11/TPM2/Secure Enclave/CNG; optional remote signer for enterprise mode).
- **Policy gating**: Cedar allow/deny + derived "require approval" via a stricter action.
- **Risk scoring**: non-authoritative heuristics (and optional HTTP classifier) can require approval for suspicious calls.
- **Budgets**: category-based daily limits; overruns require approval.
- **Schema validation**: tool args validated against JSON Schema before execution.
- **Tool isolation**: per-tool deny-by-default network/filesystem using a WASM sandbox + explicit allowlists.
- **Output firewall**: allowlisted paths/fields for tool output where configured.
- **Receipts**: every tool call produces a chained-hash receipt record.
- **Capability tokens**: provider issues short-lived JWTs with caveats (`max_calls`, TTL) and optional PoP binding + replay defense.
- **Trusted approval surfaces**: extension/CLI/UI for local approvals; optional mobile signer for high-risk approvals (signature-based auth).
- **Local UI proxy**: `briefcase-ui` proxies to the daemon and enforces a per-process CSRF token for write actions.
- **Remote MCP routing**: remote MCP servers are accessed by `briefcased` (as a client) so policy/receipts still apply.

## Known Gaps / Planned Hardening

- Multi-user machines: the local-first model assumes per-user install; additional OS-level isolation may be needed for shared hosts.
- Packaging hardening: default install/service recipes are provided, but production deployments should review platform-specific service isolation.
- Windows local IPC: the daemon defaults to loopback TCP; named pipe support is a planned improvement.
