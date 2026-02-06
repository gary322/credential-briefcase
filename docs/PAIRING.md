# Mobile Signer Pairing (v0.1)

This repo supports a "mobile signer" that can be required to approve high-risk tool calls without ever giving the agent raw secrets.

## Goals

- Pair a signer device to a specific `briefcased` instance.
- Keep the pairing code off the wire (no copy/paste into logs).
- Require replay-resistant approvals (each approval is signed with the signer's key).

## Protocol Summary (Implemented)

### Pairing bootstrap (Noise PSK)

1. An admin user starts pairing:
   - `POST /v1/signer/pair/start` (daemon-authenticated)
2. `briefcased` returns:
   - `pairing_id` (UUID)
   - `pairing_code` (base64url; treat as a secret; short-lived)
   - `expires_at_rfc3339`
3. The signer completes pairing using Noise with PSK:
   - `POST /v1/signer/pair/{pairing_id}/complete`

Noise parameters:

- `Noise_NNpsk0_25519_ChaChaPoly_SHA256`
- PSK index `0`
- The PSK is the `pairing_code` decoded from base64url.

The signer sends:

- Noise message 1 (`msg1_b64`)
- a signing public key (`signer_pubkey_b64`) and `algorithm` (`ed25519` or `p256`)

`briefcased` responds with Noise message 2 (`msg2_b64`) whose decrypted payload includes the assigned `signer_id`.

### Approval requests (signed + replay protected)

Signer requests are authenticated by a signature plus a timestamp + nonce.

For a signed request, the signer sends:

- `signer_id`
- `ts_rfc3339`
- `nonce` (UUID string)
- `sig_b64` (base64url signature; format depends on `algorithm`)

The signature input is a simple newline-delimited string:

- `list_approvals\n{signer_id}\n-\n{ts}\n{nonce}\n`
- `approve\n{signer_id}\n{approval_id}\n{ts}\n{nonce}\n`

Signature formats:

- `ed25519`: 64 raw bytes.
- `p256`: DER-encoded ECDSA signature (X9.62).

`briefcased` enforces:

- max clock skew (currently 120s)
- nonce replay cache (in-memory TTL)

## Notes

- The daemon continues to default to a Unix socket on Unix platforms. For cross-device pairing you must run `briefcased` on TCP (`BRIEFCASE_TCP_ADDR`), and consider additional network controls.
- v0.1 implements a local-first reference protocol; enterprise deployments should integrate with a proper device enrollment and transport security profile.
