# Native Messaging Host

This repo uses a **native messaging host** so the browser extension can talk to the local `briefcased` daemon **without** opening a public TCP port and **without** putting daemon auth tokens in the extension.

## Host Binary

Build:

```bash
cargo build -p native-messaging-host --release
```

Binary output:
- macOS/Linux: `target/release/native-messaging-host`

The host connects to `briefcased` via:
- Unix socket (default if `<data_dir>/briefcased.sock` exists)
- or TCP via `BRIEFCASE_TCP_BASE_URL` (fallback)

## Chrome/Chromium Setup

1. Build the extension:

```bash
pnpm -C apps/briefcase-extension install
pnpm -C apps/briefcase-extension build
```

Load the unpacked extension from `apps/briefcase-extension/extension`.

2. Install the native host manifest

Chrome expects a per-user manifest file at:

- macOS:
  - `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
- Linux:
  - `~/.config/google-chrome/NativeMessagingHosts/`
  - `~/.config/chromium/NativeMessagingHosts/`

Copy the template manifest:

`packaging/native-messaging/chrome/com.briefcase.credential_briefcase.json`

and edit:
- `path`: absolute path to `native-messaging-host`
- `allowed_origins`: the extension origin, `chrome-extension://<extension_id>/`

## Security Notes

- The native messaging host reads the daemon auth token from the daemon data dir and does **not** expose it to the extension.
- Only allow the expected extension origin(s) in the browser manifest.

