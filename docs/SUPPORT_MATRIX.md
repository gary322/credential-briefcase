# Support Matrix

## Compatibility profile

- Current stable profile: `aacp_v1`
- Runtime modes: `reference`, `staging`, `ga`

## Platforms

| Component | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| `briefcased` daemon | Supported | Supported | Supported | Default transport: Unix socket (Unix) / named pipe (Windows). TCP loopback is supported via `BRIEFCASE_TCP_ADDR`. |
| `mcp-gateway` | Supported | Supported | Supported | stdio + MCP Streamable HTTP |
| `briefcase-cli` | Supported | Supported | Supported | Admin surface only |
| `briefcase-ui` | Supported | Supported | Supported | Local operator UI |
| Browser extension | Chromium-family | Chromium-family | Chromium-family | Via native messaging host |
| Mobile signer iOS | N/A | Supported build path | N/A | Hardware-backed key custody where available |
| Mobile signer Android | Supported build path | Supported build path | Supported build path | Hardware-backed key custody where available |

## Auth/payment compatibility

| Flow | Profile status | Notes |
|---|---|---|
| OAuth (authorization code + refresh) | Supported | Refresh tokens remain daemon-side only |
| Capability tokens (JWT) | Supported | Short-lived caveated tokens |
| DPoP-bound capability (`cnf.jkt`) | Supported | Replay-protected in reference provider gateway |
| Legacy PoP header (`x-briefcase-pop-pub`) | Compatible | Backward compatibility path only |
| VC entitlement -> capability | Supported | VC revocation/status checks apply |
| x402 flow | Supported (reference rails + helper backend) | Production deployments should use helper backend |
| L402 flow (lnd/cln) | Supported | Regtest harness coverage included |

## Deployment profiles

| Profile | Intended use | Strictness |
|---|---|---|
| `reference` | Local development, demos | Lowest |
| `staging` | Pre-production validation | Medium |
| `ga` | Production | Highest |

## Version support policy

- Supported release lines:
  - `N` (latest minor) is fully supported.
  - `N-1` (previous minor) receives security + compatibility fixes.
- End of support:
  - `N-1` support ends when `N+1` is released (or earlier if explicitly noted in release notes).
- Compatibility profile lifecycle:
  - A profile id (for example `aacp_v1`) is supported for the lifetime of the release lines above.
  - Deprecations MUST be announced at least one minor release before removal, and MUST include a migration path (typically a newer profile id).
