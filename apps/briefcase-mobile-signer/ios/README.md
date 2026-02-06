# Briefcase Mobile Signer (iOS)

This is a reference iOS signer app that pairs with `briefcased` and can approve high-risk tool calls without ever exposing daemon auth tokens or provider secrets.

## Build

Prereqs:

- Xcode (for iOS Simulator/device builds)
- `xcodegen` (project generator)

Generate the Xcode project:

```bash
cd apps/briefcase-mobile-signer/ios
xcodegen generate
```

Then open `BriefcaseMobileSigner.xcodeproj` in Xcode and run on a Simulator or device.

## Pairing

Pairing uses Noise PSK (`Noise_NNpsk0_25519_ChaChaPoly_SHA256`) and never transmits the pairing code in plaintext.

1. On your desktop, start pairing (daemon-authenticated):
   - `POST /v1/signer/pair/start`
2. Create a QR payload for the iOS app. The app accepts either:
   - a URL: `briefcase-signer://pair?base_url=...&pairing_id=...&pairing_code=...`
   - JSON: `{"base_url":"...","pairing_id":"...","pairing_code":"..."}`
3. In the iOS app, scan the QR code (or paste the values) and tap **Pair**.

Notes:

- For cross-device pairing, run `briefcased` on TCP (see `docs/PAIRING.md`).
- The iOS app signs approvals with a hardware-backed P-256 key when available (Secure Enclave); it falls back to a software key on simulators.

