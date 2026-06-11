<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->
# Agent-signer video demo — runbook

**Scenario:** the user tells an AI agent (Claude, in plain language) to buy things from a
shop. A **Passport Prime** co-signs the payments: small orders clear unattended, larger
ones wait for a physical tap on the device. We demo **both** wallet models, on testnet4.

Everything here uses only the documented tools (`nunchuk-cli` + `host/prime-usb`) — nothing
another agent without this session's context couldn't do.

## Pre-flight (have all of this before recording)

- **Shop server running + open in the user's browser** at `http://127.0.0.1:3015`:
  ```bash
  cd apps/gui-app-nunchuk-signer/demo/storefront
  rm -f .server-state.json      # clean slate
  node server.mjs               # leave running
  ```
  (First time only: `node gen-merchant.mjs` to create `merchant.json`.)
- **Prime:** the **Agents** app OPEN (its USB port only exists while open). Device key
  fingerprint is **`c38e7d25`** (post-reset). Confirm: `prime-usb fingerprint`.
- **`prime-usb`** reachable. pyserial lives in `~/.passport-nunchuk-signer-keyos/venv`
  (prime-usb auto-uses it). If the port enumerates oddly: `PRIME_USB_PORT=/dev/cu.usbmodem… prime-usb …`.
- **`nunchuk-cli`** logged in, `nunchuk network set testnet`. **Fund with testnet4** coins.
- Pick a **per-tx limit** so the catalog straddles it. Default plan: **10,000 sats**.
  Beans (2,500) = under → auto. Hoodie (25,000) = over → Prime tap.

The agent buys by calling **`GET http://127.0.0.1:3015/api/agent/invoice/<product>`** — this
returns the invoice AND flips the shop to "Agent is paying…". Products: `beans`, `coldbrew`,
`pourover`, `hoodie`, `case`. Status: Awaiting → Agent is paying… → Payment received.

---

## Segment A — 2-of-3 (cloud-assisted)

**User says:** "Set up a 2-of-3 testnet Bitcoin wallet with three signers: a hot key you
hold, my Passport Prime, and Nunchuk's Platform Key. Set the Platform Key to a 10,000 sat/day
limit with auto-broadcast, so small purchases clear on their own and anything bigger comes to
my Prime for a tap. Register it on my Prime, then give me a receive address to fund."

**Agent runs** (full detail in `host/skills/prime-hsm/SKILL.md` A–C):
```bash
PRIME_KEY=$(prime-usb xpub)
AGENT_FP=$(nunchuk key generate --name agent --words 24 | awk '/Fingerprint:/{print $2}')
AGENT_KEY=$(nunchuk key info --fingerprint "$AGENT_FP" --path "m/48'/1'/0'/2'" | awk '/^Descriptor:/{print $2}')
SB=$(nunchuk sandbox create --name agent-wallet --m 2 --n 3 --address-type NATIVE_SEGWIT | grep -oiE '[0-9a-f-]{36}' | head -1)
nunchuk sandbox add-key "$SB" --slot 0 --descriptor "$AGENT_KEY"
nunchuk sandbox add-key "$SB" --slot 1 --descriptor "$PRIME_KEY"
nunchuk sandbox platform-key enable "$SB"
nunchuk sandbox platform-key set-policy "$SB" --auto-broadcast --limit-amount 10000 --limit-currency sat --limit-interval DAILY
WALLET=$(nunchuk sandbox finalize "$SB" | awk '/walletId:/{print $2}')
DESC=$(nunchuk wallet export "$WALLET" | grep -m1 -oE 'wsh\(.+\)#[a-z0-9]+')   # default = BIP-389 multipath <0;1>, NOT --format all
prime-usb register --descriptor "$DESC"          # USER TAPS to confirm on Prime
nunchuk wallet address get "$WALLET"             # give this tb1q… to the user to fund (testnet4)
```
**User funds** the address from a testnet4 faucet.

**Buys** (same two lines work for both wallets):
- "Go buy the Beans and pay it." → 2,500 < 10k → **agent + Platform Key auto-co-sign**, Prime idle.
- "Go buy the Hoodie and pay it." → 25,000 > 10k → Platform Key refuses → **routes to Prime → tap**.

Agent per buy: `GET /api/agent/invoice/<p>` → `nunchuk tx create … --to <addr> --amount <sats> --currency sat`
→ `nunchuk tx sign … --fingerprint $AGENT_FP` → `prime-usb sign --psbt <psbt>` (exit 10 = held for tap)
→ `nunchuk tx sign … --psbt <signed>` → `nunchuk tx broadcast …`.

---

## Segment B — 2-of-2 (self-custodied, spec-driven, with recovery)

**On the device first:** open the Agents app → "Add wallet" → **Self-custodied (2-of-2)** →
set the **recovery timelock** and the **spending limit** (e.g. 10,000 sats) → land on the wait screen.

**User says:** "Read the setup from my Passport and build the wallet it's waiting for, then
give me a receive address to fund."

**Agent runs** (the device picker is the source of truth — see `SKILL.md` F):
```bash
prime-usb spec                                    # {"model":"2-of-2","recovery_blocks":N}
REC=$(prime-usb spec --field recovery_blocks)
PRIME0=$(prime-usb xpub --path "m/48'/1'/0'/2'")  # everyday leg
PRIME1=$(prime-usb xpub --path "m/48'/1'/1'/2'")  # recovery leg (2nd account)
AGENT_FP=$(nunchuk key generate --name agent2 --words 24 | awk '/Fingerprint:/{print $2}')
AGENT_KEY=$(nunchuk key info --fingerprint "$AGENT_FP" --path "m/48'/1'/0'/2'" | awk '/^Descriptor:/{print $2}')
SB=$(nunchuk sandbox create --name agent-2of2 --miniscript-template "or_d(multi(2,key_0_0,key_1_0),and_v(v:pk(key_2_0),older($REC)))" | grep -oiE '[0-9a-f-]{36}' | head -1)
nunchuk sandbox add-key "$SB" --slot 0 --descriptor "$AGENT_KEY"   # agent
nunchuk sandbox add-key "$SB" --slot 1 --descriptor "$PRIME0"      # Prime everyday
nunchuk sandbox add-key "$SB" --slot 2 --descriptor "$PRIME1"      # Prime recovery
WALLET=$(nunchuk sandbox finalize "$SB" | awk '/walletId:/{print $2}')
DESC=$(nunchuk wallet export "$WALLET" | grep -m1 -oE 'wsh\(.+\)#[a-z0-9]+')   # default = BIP-389 multipath <0;1>, NOT --format all
prime-usb register --descriptor "$DESC"          # USER TAPS to confirm
nunchuk wallet address get "$WALLET"             # fund this (testnet4)
```
The 2-of-2 limit is **on-device** (set during onboarding) — no CLI limit command. Prime is the gate.

**Buys** (open the shop in a **fresh browser tab** so products draw new addresses):
- "Go buy the Beans and pay it." → under the on-device limit → **Prime auto-signs**, no tap.
- "Go buy the Hoodie and pay it." → over → **Prime tap**.

---

## Gotchas
- **Register the multipath descriptor.** Use the **default** `nunchuk wallet export "$WALLET"`
  (BIP-389 `<0;1>`), never `--format all` (`/0/*`, receive-only). Prime matches a PSBT by
  deriving receive **and** change scripts from the descriptor; a receive-only registration
  can't match any spend that consumes change and refuses with **"does not match a registered
  wallet"** — typically the *second* buy (the one funded by the first buy's change), so it
  passes a quick smoke test and bites mid-demo. The two forms have different `#checksum`s, so
  fixing it means re-registering (extra tap) and the bad entry can't be removed over USB.
- **testnet4** for funding (Nunchuk's testnet backend indexes testnet4). Faucet small amounts.
- **Round two = fresh browser tab** (or `rm .server-state.json` + restart server), else the
  product reuses a paid address and shows "Paid" instantly.
- A **factory reset changes Prime's key** — rebuild wallets from scratch (old ones orphaned).
- Recovery-leg *signing* (acct 1', for an actual sweep) is not yet verified on hardware; not
  needed for this demo (we only exercise the everyday leg).
