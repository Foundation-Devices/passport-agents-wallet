# Passport Agents Wallet

**A Passport Prime as a self-custodied, hardware-enforced spending-policy co-signer
for an AI agent's Bitcoin wallet.** The agent runs a Nunchuk wallet via `nunchuk-cli`;
Prime holds one key and enforces a spending policy on the device. Small spends sign
**unattended** (HSM mode); anything over your limits is held for a physical tap on Prime.

It is the self-custodied analog of Nunchuk's server-side Platform Key: the agent can
keep spending within a budget, but the keys and the veto live in your hardware.

> **See it first:** [video demo](https://drive.google.com/file/d/16PrrIsYB586VmCbxKu6rHHGMrMIIAuHd/view?usp=sharing)
> (an AI agent buys its own coffee on testnet; an over-limit purchase is held for a tap).
>
> **Status:** hardware-verified proof of concept. Not production-ready. See [Status](#status).

---

## Run it with your AI agent (the intended path)

This repo ships a complete, hardware-verified **agent runbook** at
[`host/skills/prime-hsm/SKILL.md`](host/skills/prime-hsm/SKILL.md). It is written for an
AI coding agent (Claude Code, Cursor, and similar) to execute end to end: read Prime's
key, build the wallet in Nunchuk, register it on the device, and run the spend loop.

After the [prerequisites](#what-you-need) are in place, point your agent at the skill
and ask in plain language, for example:

> "Using the prime-hsm skill, set up a 2-of-3 testnet wallet with a hot key you hold,
> my Passport Prime, and Nunchuk's Platform Key. Put a 10,000 sat/day limit on the
> Platform Key with auto-broadcast, register it on my Prime, and give me a receive
> address to fund."

The agent does the rest: it drives `nunchuk-cli` for all Bitcoin work and `host/prime-usb`
for the device, pausing only when Prime needs a tap. The [`demo/`](demo/DEMO.md) storefront
reproduces the agent-buys-coffee flow so you can watch both lanes (auto-clear vs. tap).

## What you need

- **A Passport Prime** running the **Agents** app (this app), with a wallet seed set up.
- **[`nunchuk-cli`](https://github.com/nunchukio)** on your `PATH`, then:
  `nunchuk auth login` (free Nunchuk Developer Portal key) and `nunchuk network set testnet`.
- **Node.js** if you want the demo storefront (`cd demo/storefront && npm install`).
- **testnet4 coins** to spend. Nunchuk's testnet backend indexes **testnet4**, so fund
  from a testnet4 faucet (testnet3 coins will not appear).

You do **not** bring the agent's key (the runbook generates it) and you do **not** need
coins to *create* a wallet, only to spend.

> ⚠️ **Host transport is currently stubbed.** The USB CDC transport was removed in
> favour of QuantumLink v2, which is not in the published SDK yet, so on device the
> app runs but the `xpub` / `register` / `sign` requests cannot reach it over USB.
> The simulator file bridge still works. See [`MIGRATION-QLV2.md`](MIGRATION-QLV2.md).

## Build it yourself

This is a **standalone Foundation SDK app** (SDK **1.0.0**, targeting **KeyOS 1.4**).
No KeyOS source checkout required:

```bash
git clone https://github.com/Foundation-Devices/passport-agents-wallet
cd passport-agents-wallet
./scripts/setup-sdk.sh          # map your installed SDK into the project (once)
foundation develop              # SDK dev shell (supplies the required rustc)
foundation sim                  # build + run in the simulator
```

To put it on hardware (Passport Prime on KeyOS 1.4):

```bash
foundation cert gen             # one-time signing identity
foundation sideload             # build + sign + copy to the device + launch
```

Full details, including the SDK version gotcha, in [`SDK-SETUP.md`](SDK-SETUP.md).

## What's in the box

| Path | What it is |
|------|-----------|
| `src/nunchuk/` | On-device core: descriptor matching, policy gate, PSBT, signing (Rust) |
| `src/`, `ui/`, `app-config.toml`, `build.rs` | The KeyOS app (Slint UI, SDK scaffolding) |
| `host/prime-usb` | Legacy USB-CDC device talker (retired; see MIGRATION-QLV2.md) |
| `host/prime-signer` | The simulator file-bridge equivalent (hosted sim) |
| `host/skills/prime-hsm/SKILL.md` | **The agent runbook** (start here) |
| `host/hwi/`, `host/*.py` | HWI driver skeleton + reference flows |
| `demo/` | Storefront for the agent-buys-coffee demo + `DEMO.md` |
| `docs/` | `ARCHITECTURE.md`, `HWI.md` |
| `SDK-SETUP.md` | Standalone SDK build: setup, signing, sideload |

## Two treasury models (chosen on-device at onboarding)

- **Self-custodied (2-of-2):** `wsh(or_d(multi(2, agent, prime), and_v(v:pk(prime), older(N))))`.
  Agent + Prime co-sign; Prime enforces the policy. A recovery branch lets Prime spend
  **alone after N blocks** if the agent key is lost. Fully sovereign.
- **Cloud-assisted (2-of-3):** adds Nunchuk's always-online **Platform Key** as a third
  signer, so the agent keeps spending while Prime is off. Prime stays sovereign:
  `agent + Prime` is a valid 2-of-3 that never needs Nunchuk. (A plain 2-of-3 self-recovers
  via any 2 of 3 keys, so it has no separate timelock branch; the `older(N)` recovery leg
  is a 2-of-2 feature.) See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## The policy gate (`src/nunchuk/gate.rs` + `history.rs`)

Prime decides, per PSBT, whether to release its signature:

- A per-tx `max_amount`, rolling **velocity** caps (daily/weekly), and clock-free
  **session/lifetime** backstops that survive reboot.
- Under every cap: **auto-sign, no human.** Over any cap: **on-device approval.**
- An append-only ledger (debited **before** signing) powers the velocity caps and the
  on-device Activity screen. Recovery-path spends always require approval.

## Build & run

See [Build it yourself](#build-it-yourself) above and [`SDK-SETUP.md`](SDK-SETUP.md).
In the simulator, open **Agents** from the launcher, pick a treasury model plus
recovery timelock, then use **Sign PSBT** / **Policy** / **Activity** /
**Export key for Nunchuk**.

## Tests

```bash
cargo test  -p gui-app-nunchuk-signer     # host unit tests (policy, PSBT, descriptor)
cargo check -p gui-app-nunchuk-signer     # both host + armv7a-unknown-xous-elf
```

## Architecture notes

- Bitcoin/PSBT/policy logic in `src/nunchuk/` on `ngwallet::bdk_wallet::{bitcoin, miniscript}`,
  so the same code compiles for the host simulator and `armv7a-unknown-xous-elf`.
- UI in Slint under `ui/pages/*`; the router in `ui/gen/*` is generated by `build.rs`.
- Device key: `security.app_seed()` gives a master `Xpriv`, then BIP48 `m/48'/1'/0'/2'`.
- Host transport is **stubbed** (`src/transport.rs`). USB-CDC was removed; the
  QuantumLink v2 replacement is not in the published SDK yet.
- Builds standalone against the Foundation SDK 1.0.0 via the `.foundation-sdk`
  mapping; no KeyOS source checkout.

## Status

**Hardware-verified (pre-SDK-migration).** Both models round-tripped on testnet4 over the
then-current USB-CDC transport:
2-of-2 (agent + Prime) and 2-of-3 (with the live Nunchuk Platform Key). The on-device
policy gate, per-wallet limits, destination allowlist, freeze, and fail-closed ledger are
all verified on hardware. Since then the app was converted to a standalone SDK 1.0.0 app
and the CDC transport was retired, so the host lane needs the qlv2 work in
[`MIGRATION-QLV2.md`](MIGRATION-QLV2.md) before it round-trips again.

Known limitations / outstanding:

- **testnet4 only** for now (what Nunchuk's backend supports).
- **i18n:** strings are inline in the Slint pages; `i18n/en.json` is not yet wired through.
- **Rolling daily/weekly caps** need an on-device RTC and are paused on hardware today;
  the session/lifetime backstops work.
- **Recovery-leg signing** (2-of-2, account `1'`, for an actual sweep) is not yet verified
  on hardware; building, registering, and everyday-signing are.
- **Native HWI driver** for stock Sparrow/Specter/Core is a skeleton (see [`docs/HWI.md`](docs/HWI.md)).

## License

GPL-3.0-or-later. Copyright Foundation Devices, Inc.
