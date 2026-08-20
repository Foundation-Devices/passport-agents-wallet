<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Migration: USB-CDC -> QuantumLink v2 (`os/ql`)

## Status

The custom **USB CDC-ACM transport was removed** (`src/usb_cdc.rs`, retired to git
history) and replaced with a **stub** at [`src/transport.rs`](src/transport.rs).
CDC is not used going forward. The app still builds and runs on the simulator
(file bridge); on device the host transport currently no-ops until the qlv2
endpoint below is wired.

This doc captures what changed, what is left, and the two external items that gate
a fully self-contained `foundation` SDK build.

## Why

Foundation is standardising on **QuantumLink v2 ("qlv2")** for host<->device comms.
Reference POC: KeyOS-dev branch **`ql-usb`** (`Foundation-Devices/KeyOS-dev`,
head `09a4864`). There, USB is owned by an **OS service** (`os/ql`, package
`ql-server`, with `usb_transport.rs`) that registers vendor interface 6
(class `0xFF` / subclass `0x51` / protocol `0x01`, two 512-byte bulk endpoints,
one record per transfer, ZLP-delimited, 32 KiB max). **Apps no longer register USB
themselves** — they register RPC routes with the `ql` app API and the service does
the wire work. That is why `src/usb_cdc.rs` (and its `usb` / `server` / `xous`
deps) could be deleted outright rather than ported.

> **Related:** the app has since been converted to a **standalone Foundation SDK
> 1.0.0 app** (no KeyOS checkout needed) — see [`SDK-SETUP.md`](SDK-SETUP.md). The
> SDK ships `security` (`app_seed()`), `fs`, `server`, `slint-keyos-platform` and
> `foundation-themes`, but **not** `usb` or the qlv2 `ql` crates, which is why the
> transport below stays stubbed.

## Done in this repo (the stub)

- Deleted `src/usb_cdc.rs`; added `src/transport.rs` keeping the transport-agnostic
  `dispatch()` seam (`Response::parse_request` -> `process_request`) plus a stub
  `serve()`.
- `src/main.rs`: `mod usb_cdc` -> `mod transport`; the device thread calls
  `transport::serve` and no-ops for now.
- `Cargo.toml`: removed `usb`, `server`, and the `cfg(xous)` `xous` dep (all were
  used only by the CDC file). `ngwallet`, `security`, `fs`, `log-server`,
  `slint-keyos-platform` stay.
- `manifest.toml`: removed the `os/usbdev` block; left inline notes for the qlv2
  permissions.

## To un-stub (wire the qlv2 endpoint)

Build against the `ql-usb` KeyOS-dev workspace (the qlv2 crates are **not** in the
published SDK yet — see Gating). Reference app: `test-apps/gui-app-qlv2` and the
already-ported `apps/gui-app-bitcoin`.

1. **Cargo deps** (add): `ql = { workspace = true, features = ["worker"] }`,
   `ql-api`, `ql-rpc`. (`ql-api`/`ql-rpc` come from `foundation-api` branch
   `ql-v2-shared-api`.)
2. **Seed:** in `src/master_key.rs`, swap `Security::default().app_seed()` /
   `GetAppSeed` for `.seed()` / `GetSeed` (returns a BIP-39 `Seed`; feed
   `entropy.bytes()` into the existing master-key derivation).
3. **Manifest:** `template = ["gui-app", "fs-generic", "ql-rpc"]`;
   `"os/ql" = ["SubscribeIncomingStreams", "SubscribeStatus", "GetStatus",
   "EnableCompanionPairing", "DisableCompanionPairing", "ClearPeer", "ClearCompanion"]`;
   `"os/security" = ["GetSeed", ...]`.
4. **`build.rs`:** the newer one-liner `slint_keyos_platform_build::compile_app("ui/app.slint")`.
5. **`src/transport.rs`:** replace the stub `serve` with a qlv2 RPC endpoint:
   `ql::use_api!()`, `QlApi::default().peer(PeerTarget::Companion).rpc(worker())`,
   define `xpub` / `register` / `sign` as `ql-api` routes (one opaque-bytes route
   can carry today's JSON envelope verbatim), serve via
   `Router::builder_local(..).request::<..>().build(..)` +
   `ql.rpc_handlers(worker(), router)`, handing each request payload to
   `dispatch(&state, payload)` and returning `Response::to_line()` bytes.
6. **Host tool:** retire the Python `host/prime-usb` (CDC). Build a Rust host tool
   on `utils/ql-usb-host`'s `transport.rs` + `platform.rs` (copy verbatim; they are
   protocol-agnostic — `rusb`, VID/PID `0x1307`/`0x0165`, scans for the
   `0xFF`/`0x51`/`0x01` interface), carrying the same wallet routes, plus the
   companion-pairing step (`RequestPeerPermissions`).

The rest of `src/nunchuk/` is unchanged: it already uses
`ngwallet::bdk_wallet::{bitcoin, miniscript}`, exactly what `gui-app-bitcoin` uses
on this branch, so the Bitcoin/PSBT core needs no change and links on device.

## Gating (external, not in this repo's control)

1. **qlv2 is dev-branch-only.** `api/ql`, `os/ql`, and the `ql-*` crates exist only
   in the `ql-usb` KeyOS-dev branch. The published `foundation` SDK (0.4.0 / 1.0.0)
   still ships legacy `quantum-link` and pins `foundation-api` to tag `5.4.6`. So
   "clone it and `foundation build/sign/sideload`" waits on Foundation cutting an
   SDK release that vendors qlv2 and bumps `foundation-api` past the
   `ql-v2-shared-api` merge. Until then this ports as a workspace app in the
   `ql-usb` tree (like `gui-app-bitcoin`).
2. **Device firmware must include `os/ql`.** Sideloading a qlv2 app needs the Prime
   running a KeyOS build with the `os/ql` service. Confirm the **1.4 beta** includes
   it (ask Georges, the `ql-usb` branch author) — otherwise the app has no transport
   to bind to.

Also confirm the exact `ql-api` route-definition macro syntax against the
`ql-v2-shared-api` branch before writing the route types.
