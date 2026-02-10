# Capability Tokens (AACP v1)

## Purpose

Providers should return short-lived, caveated capability tokens to limit blast radius:

- short TTL (minutes)
- endpoint/tool scope
- call limits and usage caveats
- proof-of-possession (PoP) binding when supported

## Profile contract (AACP v1)

The following are treated as **stable** interoperability points under `aacp_v1`:

- Providers SHOULD include a compatibility marker on responses:
  - Response header: `x-briefcase-compatibility-profile: aacp_v1`
  - Token response field: `compatibility_profile: "aacp_v1"`
- Capability JWTs SHOULD include:
  - `exp` / `iat`
  - `jti` (used for metering/revocation and replay-adjacent audit)
  - `scope` (resource/tool scope)
  - `max_calls` (usage caveat when supported)
- If PoP binding is used, capabilities MUST be bound using `cnf.jkt` and verified with DPoP proofs on protected calls.

Additional claims/fields may exist, but should be treated as **non-contractual** unless explicitly documented as profile-governed.

## Reference implementation

`apps/agent-access-gateway` issues JWT capability tokens with:

- `exp` / `iat`
- `jti` (usage metering key)
- `scope` (for example `quote`)
- `max_calls`
- `cost_microusd` (reference metering field; not required for interop)
- `cnf.jkt` (optional): JWK thumbprint for DPoP-bound capabilities

`briefcased` caches capability tokens and uses them for provider calls.

### Profile markers

Provider gateways should include a stable compatibility marker so clients can detect mismatches:

- Response header: `x-briefcase-compatibility-profile: aacp_v1`
- Token response field: `compatibility_profile: "aacp_v1"`

## PoP binding

The preferred PoP mechanism is DPoP:

1. Client includes `DPoP` proof when requesting `/token`.
2. Provider derives the proof key thumbprint and mints capability with `cnf.jkt`.
3. For each protected API call, client sends:
   - `Authorization: DPoP <capability_jwt>`
   - `DPoP: <proof_jwt>`
4. Provider verifies:
   - proof method + URL binding
   - `ath` binding to the presented access token
   - `jti` replay defense window
   - key thumbprint equals `cnf.jkt`

Legacy compatibility path:

- `x-briefcase-pop-pub` is accepted by the reference provider for backward compatibility and mapped to a `cnf.jkt` value.

## Replay defense

Providers must enforce replay protection for DPoP proofs and payment nonces.
The reference gateway keeps bounded replay caches and rejects reused identifiers.

## Notes

- Capability tokens are bearer-like unless PoP-bound.
- Capability revocation and max-call exhaustion are treated as authorization failures.
- Breaking claim/behavior changes require a new compatibility profile version.
