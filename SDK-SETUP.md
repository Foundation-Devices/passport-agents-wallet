<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Foundation SDK setup

Agents Wallet is a standalone Foundation SDK 1.0 application for KeyOS 1.4. It
does not require a KeyOS source checkout.

## Build an install archive

Install the Foundation SDK, then run:

```bash
foundation doctor
foundation pack --release
```

The CLI creates the gitignored `.foundation-sdk/current` and `ui/ui` mappings,
builds for `armv7a-unknown-xous-elf`, signs with the identity in
`app-config.toml`, and writes the `.app` archive under `target/keyos/`.

Use `./scripts/setup-sdk.sh` only when running Cargo directly without first
running a Foundation command. It creates the same project-local SDK and UI
mappings without linking SDK fonts, icons, or images into the app.

## Test on the host

Enter the SDK development shell and target the host explicitly:

```bash
foundation develop
cargo test --target aarch64-apple-darwin
```

The device build uses the SDK's KeyOS `getrandom` implementation. The host test
target exercises the policy, descriptor, PSBT, persistence, and signing suites.

## Install

Copy `target/keyos/gui-app-nunchuk-signer.app` to USB or Airlock and install it
from Settings > Apps > Install App. A developer-signed build prompts for trust
on first install and does not require a Foundation production signature.

## Current transport limitation

The public SDK does not expose the QuantumLink crates and permissions needed for
the desktop host route. The app installs and its on-device wallet, policy, file,
QR, and signing flows work, but live `xpub`, `register`, and `sign` requests do
not yet arrive over USB. See `MIGRATION-QLV2.md`.
