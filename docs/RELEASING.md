# Releasing

This repository is a monorepo. The release tag (`vX.Y.Z`) is intended to be the **single version** for all shipped artifacts:

- Rust binaries (`briefcased`, `mcp-gateway`, `briefcase-cli`, `briefcase-ui`, `agent-access-gateway`)
- browser extension package
- mobile signer apps (CI build artifacts)
- enterprise control plane container images (GHCR)

## Current releases (v0.1.x)

Release artifacts are built and published by GitHub Actions when a tag `v*` is pushed.

## Versioning policy

- Public APIs/configs follow SemVer.
- `main` is always releasable (CI must stay green).
- Releases are cut from an annotated tag on `main`.
- Compatibility behavior follows `docs/COMPATIBILITY_PROFILE.md` (`aacp_v1` currently).

## GA exit criteria (v1.0.0)

This section is the "universally done" definition for agentic auth GA.

Automatable gates (must be green immediately before tagging):

1. Repository quality gates:
   - `cargo fmt --all`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test`
2. Security assessment bundle (evidence artifact):
   - `bash scripts/run_security_assessment.sh`
3. Support and docs consistency:
   - `bash scripts/validate_support_matrix.sh`
   - `cargo test -p briefcase-core --test docs_profile_consistency`
4. Compatibility / interop:
   - MCP approval-token conformance tests pass (`cargo test -p mcp-gateway`)
   - Provider reference gateway conformance tests pass (`cargo test -p agent-access-gateway`)
   - Remote MCP `ga` profile enforcement tests pass (`cargo test -p briefcased remote_mcp_profile_*`)
5. Release evidence:
   - `bash scripts/release_manifest.sh && bash scripts/release_manifest.sh --verify dist/release-manifest.json`
   - Release workflow attaches SBOM + SHA256SUMS + signatures + manifest.
6. GA qualification evidence bundle (release-grade):
   - `bash scripts/ga_qualification.sh --mode release --label vX.Y.Z`
   - Produces `provider-contract-<tag>.json`, `security-assessment-<tag>.tar.gz`, and `ga-qualification-<tag>.{json,tar.gz}`.
   - For the final GA tag (`v1.0.0`), the workflow also requires `docs/GA_SIGNOFF_v1.0.0.md` to be filled (no `REPLACE_ME_*` placeholders).

Non-automatable gates (require time/human sign-off):

1. Staging soak:
   - 30 consecutive days meeting SLOs (see `docs/OPERATIONS.md`).
2. External security review:
   - Signed assessment report with 0 unresolved critical/high findings at GA cutoff.
   - Optional helper: `bash scripts/security_review_packet.sh --label vX.Y.Z` to package the evidence bundle and key docs for reviewers.
3. Launch decision:
   - Named approvers sign off the final launch checklist.

## GA launch checklist (sign-off)

This checklist is required for `v1.0.0` GA and should be attached to the release ticket.

- Release candidate tag: `v1.0.0-rc.N` (or `v1.0.0`)
- Qualification artifacts present in the release:
  - `release-manifest-<tag>.json` (and signatures)
  - `sbom-<tag>.spdx.json`
  - `provider-contract-<tag>.json`
  - `security-assessment-<tag>.tar.gz`
  - `ga-qualification-<tag>.tar.gz`
- Non-automatable gate evidence attached:
  - 30-day soak SLO report (dates + dashboards)
  - External security review report (signed)
- Final approvals (name + date):
  - Security: ____________________
  - Interop: _____________________
  - Operations/SRE: ______________
  - Release owner: _______________

## Cut a release

1. Ensure `main` is green in CI.
2. Bump versions (and regenerate `Cargo.lock`):
   - `Cargo.toml` (`[workspace.package].version`)
   - `package.json` (monorepo version)
   - `apps/briefcase-extension/package.json`
   - `cargo update -w` is not required; keep dependency churn separate.
3. Commit the version bump.
4. Tag and push:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `release` workflow will:

- Build Rust binaries on Linux/macOS/Windows and package them into OS archives.
- Build and package the browser extension (`briefcase-extension-<tag>.zip`).
- Build and package mobile signer apps (CI-only, unsigned simulator/debug outputs).
- Generate an SPDX JSON SBOM (`sbom-<tag>.spdx.json`).
- Generate a release evidence manifest (`release-manifest-<tag>.json`) via `scripts/release_manifest.sh`.
- Build, push, and keylessly sign the control plane container image to GHCR:
  - `ghcr.io/<owner>/agentic-auth-control-plane:<tag>`
  - `ghcr.io/<owner>/agentic-auth-control-plane:latest`
- Generate `SHA256SUMS.txt`.
- Sign release artifacts using keyless Sigstore `cosign sign-blob`.
- Publish a GitHub Release with all artifacts + signatures.
