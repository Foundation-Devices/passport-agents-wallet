<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Nunchuk Agent Signer — SDK setup & integration

## Is this an "SDK app"? Yes.

The official Foundation developer docs (<https://docs.foundation.xyz/developers>)
describe an `app-config.toml` + `foundation sideload` flow. The **shipped
`foundation` CLI is ahead-of / behind those docs**: running
`foundation new <name> --template multi-page-app` produces a project that is
**structurally identical to this one** — a `manifest.toml` (not `app-config.toml`),
the same `slint-keyos-platform` path-deps, the same `src/main.rs` + `ui/pages/*`
+ `build.rs` + `resources/icon.svg` + `i18n/en.json` layout, the `app!()` macro,
and the `@ui` widget library. So **`manifest.toml` is the real SDK manifest**, and
this app already conforms to the SDK project shape.

**CLI maturity (important):** at the time of writing only `foundation new` and
`foundation develop` are implemented; `sim`, `sideload`, and `cert` are not. So the
CLI can scaffold a project and open the Nix dev shell, but it cannot yet build or
install to hardware. Use KeyOS's own `cargo xtask` flow for that (it is the same
toolchain the CLI will eventually wrap).

## Layout vs. the SDK template

| SDK template (`foundation new`) | This repo |
|---|---|
| `manifest.toml` | ✅ `manifest.toml` (`appId` = ASCII `nunchuk-sign-app`, `appName` = "Agents") |
| `Cargo.toml`, `build.rs` | ✅ |
| `src/main.rs` + `ui/app.slint` + `ui/pages/*` | ✅ |
| `resources/icon.svg` | ✅ |
| `i18n/en.json` | ✅ (scaffold — see note) |
| — | `src/nunchuk/` (policy/PSBT/signing core), `host/` (CLI tooling + skill), `demo/` (storefront), `docs/` (this app's extras) |

> **No separate `logic/` crate.** Unlike the Nostr/Passwords apps, the descriptor /
> policy / PSBT / signing core lives **inline** under `src/nunchuk/`, built on
> `ngwallet`'s `bitcoin` + `miniscript` so it compiles for **both** the host
> simulator and the `armv7a-unknown-xous-elf` device target.

> **i18n note.** `i18n/en.json` is present for SDK-template parity and as the
> localization source-of-truth, but strings are currently inline in the Slint pages
> (`build.rs` sets `include_translations: false`). Wiring `@tr`/keyed lookups is a
> follow-up; the JSON already mirrors every user-facing string.

## Build & run (today, via `cargo xtask`)

From a KeyOS checkout with this app integrated (see below):

```bash
# Type/borrow-check the app for BOTH device (ARM/xous) and the simulator:
cargo xtask check gui-app-nunchuk-signer

# Run the hosted simulator (opens the Passport window):
just sim            # or: cargo xtask run --hosted
```

The app appears in the dev **Secret Menu** / hidden-apps launcher list as **"Agents"**.
For the end-to-end agent-spending walkthrough, see the runbook in
[`host/skills/prime-hsm/SKILL.md`](host/skills/prime-hsm/SKILL.md) and the video
runbook in [`demo/DEMO.md`](demo/DEMO.md).

**Device image build** (full flashable firmware) is done on **Ubuntu** (the
supported build host) or inside the KeyOS Nix flake; macOS is not supported for the
full image (an unrelated `rfal-sys` NFC `build.rs` step needs Linux/Nix headers).
Once in that environment:

```bash
cargo xtask build && cargo xtask flash    # signed image + flash over USB (SAM-BA)
```

## Integrating into a KeyOS checkout

This repo is the app plus its host-side tooling (`host/`) and demo storefront
(`demo/`). To build the on-device app you drop the app crate into a KeyOS
workspace. From a clean KeyOS checkout:

1. **Copy the app in** (the crate — the `host/` and `demo/` trees are host-side and
   are not part of the device build):

   ```bash
   mkdir -p <keyos>/apps/gui-app-nunchuk-signer
   # copy: Cargo.toml manifest.toml build.rs src/ ui/ resources/ i18n/
   ```

2. **Register it in the workspace** (`<keyos>/Cargo.toml`):
   - add `"apps/gui-app-nunchuk-signer"` to `[workspace].members`.

3. **Hook the launcher + build lists** (mirrors the reference integration):
   - `os/gui-app-launcher/src/main.rs` — add the hidden-app entry:
     ```rust
     HiddenApp { label: "Agents".into(), app_id: "0x6e756e6368756b2d7369676e2d617070".into() },
     ```
   - `xtask/src/main.rs` — add `"gui-app-nunchuk-signer"` to `DEV_APPS` and to
     `DEFAULT_SERVICES_HOSTED` (so it builds for device and the simulator).

4. **`appId` is exactly 16 bytes.** `manifest.toml`'s `appId` and the launcher's
   `app_id` are both `0x` + 32 hex (ASCII `nunchuk-sign-app`). An off-by-one byte
   panics the system on boot — keep them identical.

5. **Runtime USB interface needs `ResetController`.** The app registers its USB-CDC
   interface **at runtime** (not at boot), so it must call `reset_controller()` to
   force the host to re-enumerate — otherwise the host never re-reads the config and
   the `/dev/cu.usbmodem…` port never appears. The permission is already granted in
   `manifest.toml` (`os/usbdev` → `ResetController`); don't remove it.

After that, `cargo xtask check gui-app-nunchuk-signer` should pass for both targets.

## Host-side tooling (`host/`)

The device app is only half the system; the agent side runs on a normal computer:

- **`host/prime-usb`** — thin USB-CDC talker (pyserial only). Reads Prime's key,
  registers a wallet descriptor (on-device approval), and routes PSBTs to Prime for
  an in-policy auto-sign or an over-policy approval. **It does no Bitcoin work.**
- **`host/prime-signer`** — the simulator-era file-bridge equivalent (hosted sim).
- **`host/skills/prime-hsm/SKILL.md`** — the full, hardware-verified runbook
  (2-of-3 cloud-assisted and 2-of-2 self-custodied, with recovery).
- **`host/hwi/`**, **`host/spend_2of3.py`**, **`host/two_of_two_agent.py`** —
  reference flows.

All Bitcoin/coordination is done by **`nunchuk-cli`** (key generation, PSBTs,
signing, broadcast). See the README and the skill for the end-to-end loop.

## Adopting the official `foundation` CLI later

Once `foundation sim`/`sideload`/`cert` ship, the migration is mechanical:
`foundation new nunchuk-signer --template multi-page-app`, then move `src/`, `ui/`,
`resources/`, `i18n/`, and `manifest.toml` into the scaffold — the layout already
matches. `foundation sideload` would then push the signed app bundle over USB
without a full firmware rebuild.

## Open items

- Full signed device image + sideload via the `foundation` CLI (pending CLI
  `build`/`sideload`).
- Wire `i18n/en.json` through the Slint pages (currently inline strings).
- Recovery-leg *signing* (2-of-2, account `1'`, for an actual sweep) is the
  remaining on-device item; building / registering / everyday-signing are verified.
