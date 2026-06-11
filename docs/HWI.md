<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->
# HWI integration for Prime (investigation + design)

How the host talks to Prime. HWI is the path to making Prime a **first-class hardware
wallet** that `nunchuk-cli`/libnunchuk (and Sparrow, Bitcoin Core, Specter) reach natively
over USB.

> **Status update (post-hardware):** the **USB-CDC transport is built and working on real
> hardware** — the host drives Prime over USB-CDC with **`host/prime-usb`** (the hardware
> shim; `prime-signer` remains the sim file-bridge equivalent). **Arbitrary-path xpub
> export is implemented** (`get_pubkey_at_path`), now allowlisted to standard BIP44/48/49/84/86
> account paths. So the parts marked "need" / "USB later" below are **done**; what remains
> is the native `prime.py` HWI *driver* (this doc's Model B), to reach stock Sparrow/Specter/Core.

## Two integration models (both valid)

**A. Shim model - BUILT.** The agent-skill calls `prime-signer` directly; nunchuk-cli
handles the wallet/PSBT, `prime-signer` handles Prime signing. HWI is bypassed. This is
the clean path for the *agent* use case and it works today (file transport now, USB
later - same two verbs). Verified live on the sim.

**B. Native HWI model - this doc.** Prime ships an HWI driver, so libnunchuk reaches it
via the HWI binary (`AppSettings.set_hwi_path()`) like any hardware wallet. Bigger lift,
but unlocks every nunchuk hardware flow + other wallets, with no bespoke shim.

The shim's two verbs map 1:1 onto HWI, so B is "swap the shim's transport for HWI":

| `prime-signer` | HWI method |
|---|---|
| `xpub` | `get_master_fingerprint()` + `get_pubkey_at_path(path)` |
| `sign --psbt` | `sign_tx(psbt) -> psbt` |
| (address verify) | `display_multisig_address(addr_type, descriptor)` |

## HWI methods Prime must implement

From `hwilib/hwwclient.py` (`HardwareWalletClient`):

| Method | Prime status |
|---|---|
| `get_master_fingerprint() -> bytes` | **have** (device key fp) |
| `get_pubkey_at_path(path) -> ExtendedKey` | **need**: derive at an *arbitrary* path. Today the app only exports the fixed BIP48 `m/48'/1'/0'/2'`. Small extension - derive `Xpub` at any requested path from the app seed. |
| `sign_tx(psbt) -> psbt` | **have** (the gate + `signing::sign`). HSM nuance below. |
| `display_multisig_address(addr_type, multisig)` | **partial**: we already verify an address against a registered descriptor (`verify_address_in_policy`); HWI wants on-screen display + return. |
| `display_singlesig_address(path, addr_type)` | optional (Prime is multisig-focused) |
| `sign_message(message, path)` | optional |
| `get_master_xpub(addrtype, account)` | derive helper |
| `can_sign_taproot() -> bool` | return false for v1 (P2WSH only) |
| `setup/wipe/restore/backup_device`, `prompt_pin/send_pin`, `toggle_passphrase` | **not applicable** via HWI - Prime owns its own PIN/seed lifecycle on-device; return unsupported. |

**HSM nuance.** HWI's `sign_tx` is normally *interactive* (the user confirms on the
device screen). Prime in **HSM mode** auto-signs in-policy with no prompt and holds
over-policy spends for approval. So a Prime HWI driver's `sign_tx` returns immediately
for in-policy PSBTs, and for over-policy it either blocks on the on-screen tap or
returns a "needs approval" status (HWI has no native "deferred" state - likely return
the unsigned/partial PSBT with a message, and the caller retries after approval). This
is the same semantics the `prime-signer sign` shim already encodes (non-zero exit +
"over policy").

## The transport question - SPIKE ANSWERED (reuse, don't reinvent)

HWI reaches devices over **USB HID** (hidapi) or **USB-CDC serial**. The earlier open
question - "can a KeyOS app own a USB-CDC endpoint?" - is **already answered by the
nostr-signer and password-manager POCs**:

- `KeyOS-nostr-signer/.../src/transport/usb_cdc.rs` registers a **second CDC-ACM serial
  interface at runtime** (control + data interfaces, bulk endpoints, line framing) and
  the host talks to it over Web Serial. The password manager does the same. So the
  **CDC transport plumbing exists and is reusable.**
- **But those POCs speak a CUSTOM protocol** (newline-delimited JSON) to their **own
  browser extension** - NOT HWI. So they prove the transport, not the standard.
- Caveat from their own notes: HID kernel-panicked on the first OUT packet; CDC works,
  but a *second* CDC interface at runtime "has never been done before" and may still
  trip a KeyOS USB-server kernel bug. Flag for engineering at hardware bring-up.

**Note on Specter-DIY:** HWI's `hwilib/devices/` (master) has NO generic Specter serial
driver - every device has its OWN driver (bitbox02, coldcard `ckcc`, digitalbitbox,
**jade**, keepkey, ledger, trezor). The serial/USB-CDC one is **Jade** (Blockstream),
which speaks its own structured protocol over a virtual COM port. So there is no
"emulate Specter-DIY" shortcut; **Prime needs its own HWI driver** (`prime.py`), like
Coldcard and Jade each have theirs.

The good news: this reuses the nostr POC twice over. The split for native HWI:

1. **Transport: reuse `usb_cdc.rs`** verbatim (CDC-ACM registration + bulk read/write +
   line framing). No new USB plumbing.
2. **Protocol: reuse the nostr newline-JSON request/response shape** (`{cmd, ...}\n` ->
   `{result}\n`) with HWI-shaped ops: `fingerprint`, `xpub {path}`, `sign {psbt_b64}`,
   `showaddr {descriptor}`. Same pattern the nostr signer already runs over CDC.
3. **Driver: write `prime.py`** in `hwilib/devices/` (Jade is the closest reference -
   serial-based) that maps `HardwareWalletClient` methods onto those JSON ops + an
   `enumerate()` VID/PID match, and register it in HWI's device list. Point libnunchuk
   at it via `set_hwi_path`. `host/hwi/prime_hwi.py` is this driver (file transport now,
   CDC later - the transport is swappable behind the same protocol).

Alternative (the **shim**, built today): keep the JSON protocol over `usb_cdc.rs` and
drive Prime from the host with `prime-signer`, bypassing HWI - works with the agent-skill
only, not stock nunchuk-cli hardware flow / Sparrow / Specter / Bitcoin Core.

Custom HID + a bespoke driver (Coldcard `ckcc` style) is a third option, but HID is the
path that kernel-panicked, so CDC + a `prime.py` driver is the lower-risk native-HWI route.

Foundation USB identifiers (from the device tooling): normal mode `VID:1307 PID:0165`
(SAM-BA flash mode `VID:03eb PID:6124`). An HWI driver's `enumerate()` would match the
normal-mode VID/PID.

## Failure states & resilience (Prime not connected)

"Prime not plugged in" is a **host-side** condition: the device doesn't know the
computer is gone, the host's transport does. Both ends are handled.

**Host driver (`prime_hwi.py`)** maps every failure onto HWI's standard taxonomy so
libnunchuk / Sparrow / Bitcoin Core surface clean errors, not raw traces:

| Condition | Where | Result |
|---|---|---|
| Nothing connected | `enumerate()` | returns `[]` (HWI's "no device") - probes USB by VID/PID `1307:0165`, falls back to the file-bridge dir for the sim |
| Port absent / busy on open | `PrimeSerialTransport._open()` | retries with capped exponential backoff, then `DeviceConnectionError` |
| Cable yanked mid-call | `PrimeSerialTransport._rpc()` | one reconnect+resend per drop (bounded), within the call deadline; then `DeviceConnectionError("Prime connection lost")` |
| No reply in time | `_rpc()` / file bridge | `DeviceConnectionError("timed out …")` |
| Over-policy spend | `sign_psbt_b64()` | `UnavailableActionError` - held on Prime for an on-device approval, caller retries |
| App not running (sim) | `prime-signer status` | `"Prime bridge not found … (is the app running?)"` |

**Retry/backoff knobs** (env, for headless/CI; defaults give `0.5 → 1.0 → 2.0 → 4.0s`):

| Env var | Default | Meaning |
|---|---|---|
| `PRIME_CONNECT_RETRIES` | `5` | open/reconnect attempts before giving up |
| `PRIME_BACKOFF_BASE` | `0.5` | first backoff (seconds), doubles each retry |
| `PRIME_BACKOFF_CAP` | `4.0` | max backoff (seconds) |

**Device end (`usb_cdc.rs`)** is the complementary half: the reader/writer loops catch
`UsbError::HostDisconnected` and park on `wait_for_connection()`, so a yank-and-replug
self-heals from both sides rather than wedging the app.

**Not yet enforced in code:** the 2-of-3 availability story - when Prime is off, the
agent keeps spending in-policy via *agent + Platform Key* (Nunchuk enforces server-side).
That's a Nunchuk-side behavior the `prime-hsm` skill documents; nothing here asserts the
agent loop switches combos. The **file-bridge** transport has no retry/backoff (its
"unreachable" case is just "app not running → no response file," already a timeout).

## Recommendation

- **Now:** the shim model (B-bypass) is done and is the right primitive for the agent.
  Its file transport is a stand-in for USB; the verbs don't change.
- **Next (device phase):** the USB-CDC endpoint question is answered (`usb_cdc.rs` builds
  for the device target). Wire `prime.py`'s serial transport to Prime's newline-JSON
  protocol over that CDC interface → native HWI support → Prime works in nunchuk-cli,
  Sparrow, Specter, Bitcoin Core. Validate the second-CDC-interface kernel risk at the
  first flash. The shim remains the supported transport if CDC bring-up slips.
- Either way, add `get_pubkey_at_path(arbitrary)` to the app - needed for both HWI and
  richer nunchuk flows.

See `prime_hwi.py` (skeleton) for the driver shape mapping these methods onto the
shim/USB transport.
