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
- Build, push, and keylessly sign the control plane container image to GHCR:
  - `ghcr.io/<owner>/credential-briefcase-control-plane:<tag>`
  - `ghcr.io/<owner>/credential-briefcase-control-plane:latest`
- Generate `SHA256SUMS.txt`.
- Sign release artifacts using keyless Sigstore `cosign sign-blob`.
- Publish a GitHub Release with all artifacts + signatures.
