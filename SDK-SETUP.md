<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Foundation SDK setup

This app is a **standalone Foundation SDK application**. It builds against the
published SDK (**1.0.0**, which targets **KeyOS 1.4**) and needs **no KeyOS source
checkout**.

## 1. Install the SDK

Install the Foundation SDK so you have a directory like:

```
~/.foundation/sdk/foundation-sdk-1.0.0-aarch64-apple-darwin/
```

Verify with `foundation doctor`.

> **Version note.** On some machines `~/.foundation/sdk/current` and the
> `~/.foundation/sdk/bin/foundation` shim still point at an older **0.4.0** SDK.
> This app requires **1.0.0** (0.4.0's `foundation-themes` has no `include_theme!`
> / `apply_theme!` macros and its `api/` has no `security` crate). Either repoint
> `current`, or invoke 1.0.0 directly:
>
> ```bash
> export FOUNDATION_SDK_ROOT="$HOME/.foundation/sdk/foundation-sdk-1.0.0-aarch64-apple-darwin"
> "$FOUNDATION_SDK_ROOT/bin/foundation" <command>
> ```

## 2. Map the SDK into the project (once per clone)

Cargo cannot expand environment variables in `path = ...` dependencies, so
`Cargo.toml` refers to the stable relative path `.foundation-sdk/current/...` and
you point that at your SDK install:

```bash
./scripts/setup-sdk.sh
# or explicitly:
./scripts/setup-sdk.sh ~/.foundation/sdk/foundation-sdk-1.0.0-aarch64-apple-darwin
```

This creates gitignored symlinks: `.foundation-sdk/current/{lib/keyos,lib/slint,ui/ui,resources}`,
plus `ui/ui` and `resources/{fonts,icons,images}` which the Slint build and
`app-config.toml` reference.

> The Foundation CLI does **not** create this mapping itself, despite what some
> older app READMEs claim. It is a project convention, hence the script.

## 2b. Toolchain — build inside the SDK dev shell

**Build with the SDK's Nix dev shell, not your ambient cargo:**

```bash
foundation develop     # enters the SDK dev shell with the correct rustc
foundation sim
```

`rust-toolchain.toml` pins `nightly-2025-09-11` to match the SDK's `flake.nix`,
which is the right answer for a rustup-based build. Be aware of one caveat found
while porting: with the SDK 1.0.0 install as shipped, **no rustup nightly on hand
(including that pinned one) could compile the SDK's own `server-macro`**:

```
error[E0635]: unknown feature `proc_macro_tracked_path`
error[E0433]: could not find `tracked` in `proc_macro`
error: could not compile `server-macro`
```

`server-macro` uses `#![feature(proc_macro_tracked_path)]` with the
`proc_macro::tracked::path` API, which no public nightly tested (2025-02-16,
2025-06-24, 2025-09-11, 2026-03-10, 2026-04-11) provides — the newer ones renamed
it to `track_path`/`tracked_path` and later removed it. The SDK's Nix shell supplies
the exact rustc this expects, so use `foundation develop`. If you hit this outside
Nix, it is the toolchain, not this app's source.

## 2c. Slint pinning

`[patch.crates-io]` pins every Slint crate to the fork bundled with the SDK at
`lib/slint` (**1.17.0** on disk, even though the SDK's own `manifest.toml`
advertises `v1.12.1-foundation11`). Without the patch, cargo resolves Slint from
crates.io and a second Slint ABI enters the build. Keep it.

Note the internal inconsistency this exposes: the bundled Slint 1.17 declares
`rust-version = 1.92`, while the SDK's flake pins a 1.91 nightly. `cargo check
--ignore-rust-version` gets past the gate for a rustup build.

## 3. Build and run

```bash
foundation sim                 # build + run in the KeyOS simulator
foundation build               # debug app bundle
foundation build --release     # signed release bundle
```

Plain `cargo check` also works once the SDK is mapped.

## 4. Sign and sideload to a Passport Prime

Sideloading needs a signing identity once:

```bash
foundation cert gen            # secp256k1 keypair + X.509 publisher cert + cosign2.toml
foundation cert print          # inspect it
```

Then, with a Prime on **KeyOS 1.4** connected over USB:

```bash
foundation sideload            # build + SIGN + copy to the device + launch
foundation sideload --no-run   # copy without launching
foundation logs                # device log viewer
```

`sideload` signs automatically using the identity from `cert gen`. The device
must also trust your publisher key (first install prompts). A later build with
the same `app-id` replaces the installed app.

## Project shape

| File | Role |
|---|---|
| `app-config.toml` | **Authored** app manifest: id, version, icon, theme, permissions |
| `permission_templates.toml` | Permission bundles (`gui-app`, `fs-generic`, `navigable`) |
| `manifest.toml` | **Generated** from `app-config.toml` by the CLI. Gitignored, do not author |
| `resources/theme.json` | App theme (`id` must match `include_theme!(app_theme)` in `src/theme.rs`) |
| `src/theme.rs`, `build.rs` | Taken from the 1.0.0 template; do not hand-write |
| `ui/compat/*.slint` | Shims mapping this app's older widget vocabulary onto the SDK's `@ui` components |
| `ui/gen/` | Router/i18n codegen from `build.rs`. Gitignored |
| `.cargo/config.toml` | Pins the ARM cross-toolchain for device builds |

## Known gaps

- **Host transport is stubbed.** The USB CDC transport was removed; the
  QuantumLink v2 replacement is not in the published SDK yet. On device the app
  runs but exposes no host transport. See [`MIGRATION-QLV2.md`](MIGRATION-QLV2.md).
- The `bitcoin`/`miniscript` stack comes from the public `ngwallet` git dependency
  (not the SDK, which bundles no Bitcoin crates).
