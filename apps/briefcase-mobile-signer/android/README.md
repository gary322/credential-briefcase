# Briefcase Mobile Signer (Android)

Reference Android signer app that pairs with `briefcased` and can approve high-risk tool calls using a Keystore-backed P-256 signing key when available.

## Build (CI)

This project uses the Gradle wrapper. CI builds `assembleDebug` to ensure the project stays buildable.

## Pairing

Pairing is compatible with `docs/PAIRING.md` and uses:

- Noise: `Noise_NNpsk0_25519_ChaChaPoly_SHA256`
- Signatures: `p256` (DER ECDSA / `SHA256withECDSA`)

The app accepts QR payloads as either:

- `briefcase-signer://pair?base_url=...&pairing_id=...&pairing_code=...`
- `{"base_url":"...","pairing_id":"...","pairing_code":"..."}`

