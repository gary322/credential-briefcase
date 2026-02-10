# Operations Guide

## SLOs

Recommended starting SLOs for `ga` mode:

- Daemon availability: 99.9% monthly
- Gateway availability: 99.9% monthly
- Policy + approval decision latency overhead (excluding upstream): p95 <= 150ms
- Receipt append success: 99.99%

## Staging soak (GA gate)

For `v1.0.0` GA, the program requires a **30-day staging soak** meeting the SLOs above.

Practical approach:

1. Deploy staging with `BRIEFCASE_PROFILE_MODE=ga` (and `BRIEFCASE_STRICT_HOST=1` where applicable).
2. Ensure observability is enabled (OTel exporter + log collection).
3. Run a continuous or periodic soak loop to generate availability/latency evidence:
   - `briefcase diagnostics soak --duration-secs 3600 --interval-ms 1000 --tool quote --out dist/soak-report.json`
4. Keep the JSON reports plus dashboard screenshots/exports as the 30-day evidence bundle.

## Core diagnostics

Use daemon diagnostics APIs:

- `GET /v1/profile`
- `GET /v1/diagnostics/compat`
- `GET /v1/diagnostics/security`

Or use the CLI triage helper (does not print raw secrets):

- `briefcase diagnostics check`

## Strict host isolation mode

On shared/multi-user hosts, enable strict host isolation to reduce cross-user state exposure risk.

- Enable: `BRIEFCASE_STRICT_HOST=1` (daemon)
- Enforced:
  - Loopback-only TCP binds (rejects `0.0.0.0`, non-loopback IPs)
  - Unix: `data_dir` is forced to `0700`, `auth_token` forced to `0600`, and the Unix socket path must live inside `data_dir`
  - Windows: named pipe path must be the derived default (prevents predictable pipe-name token phishing)

## Incident classes

### 1) Credential Exposure Suspicion

- Trigger: suspected leak of OAuth refresh/access tokens, capability tokens, device tokens, or key material.
- Diagnose:
  - Run `briefcase diagnostics check` and `POST /v1/receipts/verify`.
  - Review recent receipts for unusual tool calls or approvals.
  - If you run centralized logging/OTel: search for known canary substrings (do not paste real secrets into logs).
- Contain:
  - Revoke provider OAuth credentials (per provider): `briefcase providers oauth-revoke --id <provider>`.
  - Revoke remote MCP OAuth credentials (per server): `briefcase mcp servers oauth-revoke <server-id>`.
  - If enrolled: rotate the control-plane device token by re-enrolling the device (server-side admin action).
- Recover:
  - Re-run provider OAuth login flows and re-issue capability tokens.
  - Verify the daemon is still enforcing `ga` mode strictness (`GET /v1/profile`).
- Evidence:
  - Preserve the daemon data dir and receipts store.
  - Export the release/security evidence bundle used for the deployment (SBOM, manifest, conformance report).

### 2) Capability Replay / PoP Failures

- Trigger: spikes in provider `replay_detected` / PoP mismatch errors, or inability to mint capabilities.
- Diagnose:
  - Confirm system clocks are sane (client and provider).
  - Inspect provider gateway logs for replay errors and request method/URL mismatches.
  - Run the provider contract harness against the provider: `cargo run -p briefcase-conformance --bin provider-contract -- ...`
- Mitigate:
  - If the provider is unstable: temporarily require interactive approvals for affected tools/categories.
  - Reduce blast radius by disabling the affected provider integration until conformance passes again.
- Recover:
  - Restart provider gateway and validate replay cache behavior remains bounded.
  - Validate the AACP profile marker is present on provider responses.
- Evidence:
  - Capture the provider contract JSON report and attach it to the incident ticket.

### 3) Control-Plane Policy Sync Failure

- Trigger: daemon reports control-plane sync errors, policies stop updating, receipts stop uploading.
- Diagnose:
  - Check reachability and TLS validation to the control plane.
  - Validate policy bundle signatures and compatibility profile (daemon keeps last-known-good policy on failure).
  - Inspect `GET /v1/control-plane` for `last_error` and last successful sync timestamp.
- Mitigate:
  - Keep last known good policy active (default behavior); do not apply unsigned bundles.
  - If needed, temporarily pause sync by increasing `BRIEFCASE_CONTROL_PLANE_SYNC_INTERVAL_SECS`.
- Recover:
  - Run a manual sync: `briefcase control-plane sync`.
  - Fix control plane outage, then verify bundle ids advance and receipt upload watermark moves forward.
- Evidence:
  - Export receipts + control-plane audit logs covering the outage window.

### 4) Receipt Chain Verification Failure

- Trigger: `POST /v1/receipts/verify` reports a chain break or hash mismatch.
- Diagnose:
  - Identify the first bad receipt id and the expected `prev_hash_hex`.
  - Check for concurrent writers or disk corruption on the receipts store.
- Contain:
  - Stop downstream audit exports that depend on the receipt chain.
  - Preserve a copy of the current receipts store and daemon DB before attempting repairs.
- Recover:
  - Restore from a validated backup and re-run `POST /v1/receipts/verify`.
  - Re-ingest any missing receipts from upstream sources if available.
- Evidence:
  - Attach the verification output (first failing id/hash) and the backup provenance to the incident.

### 5) Upstream Provider Outage

- Trigger: provider token endpoint/quote endpoint failures, elevated latency, or auth server unavailability.
- Diagnose:
  - Confirm provider health and DNS/TLS status.
  - Check if failures are limited to a single provider or impact multiple.
- Mitigate:
  - Fail closed for `write`/`admin` and require approvals for any exception path.
  - Prefer cached read-only behavior where safe, but do not bypass auth.
- Recover:
  - Once provider recovers: clear stale capability state, re-attempt token minting, and re-run the provider contract harness.
- Evidence:
  - Preserve logs/receipts for the outage window and note any manual overrides/approvals.

## Release readiness runbook

Before cutting a release:

1. Run quality gates:
- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`

2. Run security assessment bundle:
- `bash scripts/run_security_assessment.sh`

3. Validate support/compat docs:
- `bash scripts/validate_support_matrix.sh`

4. Generate release manifest:
- `bash scripts/release_manifest.sh`

Optional (recommended for release candidates): run the full GA qualification bundle:
- `bash scripts/ga_qualification.sh --mode release --label vX.Y.Z`

## Backup and recovery

- Backup daemon data directory (`briefcase.sqlite`, receipts store, policy state).
- Protect backups as sensitive because they may contain metadata and encrypted secret blobs.
- Validate restore by running health + diagnostics + receipt verify APIs.
