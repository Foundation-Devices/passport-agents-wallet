<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->
# prime-hsm

Set up and run an **agent-operated Nunchuk wallet** co-signed by a **Passport Prime**.
Nunchuk creates the wallet; Prime is the **policy co-signer** — it enforces a spending
policy **on the device** and signs in-policy transactions **with no person present**;
over-policy spends are held for a physical approval on Prime.

> **Model:** Nunchuk is the coordinator. Prime is the self-custodied, hardware answer
> to Nunchuk's server-side Platform Key. Nunchuk builds the wallet and the recovery
> branch; Prime exports its key, holds the on-device spending policy, and confirms +
> signs. Prime does NOT create wallets. See `../../docs/ARCHITECTURE.md`.

Two wallet models (chosen on the device at onboarding):

- **2-of-2 (self-custodied):** `agent + Prime`. Prime is the policy gate. Always
  sovereign; Prime must be powered + reachable to spend. Supports a Prime-only
  recovery branch (see [Recovery](#f-recovery)).
- **2-of-3 (cloud-assisted):** `agent + Prime + Nunchuk Platform Key`. The Platform
  Key is an always-online co-signer, so the agent keeps spending while Prime is off.
  Prime stays sovereign: `agent + Prime` is a valid 2-of-3 that never needs Nunchuk.

This runbook builds a **2-of-3**. For 2-of-2, see the note in [section B](#b-build-the-wallet-in-nunchuk).

---

## Prerequisites (the whole list)

You need a computer (macOS or Linux) with internet, a USB-C cable, and:

1. **A physical Passport Prime** running the **Nunchuk Signer app**, with a wallet seed
   set up (after a factory reset, finish device setup first so the signing key exists).
   Keep the app **open** while using USB — it registers the USB port at runtime.

2. **`nunchuk-cli`** — the only Bitcoin/coordinator toolchain (it generates keys, builds
   PSBTs, signs, and broadcasts). Node-based. Install it, then:
   ```bash
   nunchuk auth login            # needs a Nunchuk Developer Portal API key (free signup)
   nunchuk network set testnet   # this runbook is testnet
   ```
   > **Backend network note:** Nunchuk's testnet backend indexes **testnet4**. Wallet
   > creation works regardless, but to *fund and spend* you must use **testnet4** coins
   > (a testnet4 faucet); testnet3 coins won't show up. `tb`/`tpub` are shared, so the
   > keys are interchangeable.

3. **`prime-usb`** — a thin helper in this repo (`host/prime-usb`) that talks to the
   device over USB-CDC. Put it on your `PATH`. Its only dependency is pyserial:
   ```bash
   pip install pyserial
   ```
   On a modern macOS the system/Homebrew Python is "externally managed" and that pip
   install is blocked (PEP 668). Use a venv instead — `prime-usb` auto-detects it:
   ```bash
   python3 -m venv ~/.passport-nunchuk-signer-keyos/venv
   ~/.passport-nunchuk-signer-keyos/venv/bin/pip install pyserial
   ```
   (Override the interpreter with `PRIME_USB_PYTHON`, or pin the device port with
   `PRIME_USB_PORT=/dev/cu.usbmodemXXX` if it enumerates under a generic name.)
   `prime-usb` does no Bitcoin work; it only carries Prime's key, the descriptor, and
   PSBTs to/from the device. (The old `prime-signer` was a simulator-only file bridge —
   use `prime-usb` for hardware.)

That's it. The **agent's key is generated below** (you don't bring it), and **no coins
are needed to create the wallet** — only to spend afterwards.

---

## A. Get the two non-Nunchuk keys

```bash
# 1. Prime's key (read over USB). Or tap "Export key" on the device and copy it.
PRIME_KEY=$(prime-usb xpub)                 # [fp/48'/1'/0'/2']tpub...

# 2. The agent's hot key. nunchuk-cli generates + stores it (back up the mnemonic!).
AGENT_FP=$(nunchuk key generate --name agent --words 24 | awk '/Fingerprint:/{print $2}')
AGENT_KEY=$(nunchuk key info --fingerprint "$AGENT_FP" --path "m/48'/1'/0'/2'" \
              | awk '/^Descriptor:/{print $2}')
```

> In production the agent supplies its own key; `key generate` is just the convenient
> default. Because the key is stored in nunchuk-cli, the agent can sign with it by
> `--fingerprint` (no private-key handling on your part).

## B. Build the wallet in Nunchuk

```bash
# 1. Create a 2-of-3 sandbox. (Capture the sandbox UUID from the text output.)
SB=$(nunchuk sandbox create --name agent-wallet --m 2 --n 3 --address-type NATIVE_SEGWIT \
       | grep -oiE '[0-9a-f-]{36}' | head -1)

# 2. Add the agent (slot 0) and Prime (slot 1). The Platform Key takes the last slot.
nunchuk sandbox add-key "$SB" --slot 0 --descriptor "$AGENT_KEY"
nunchuk sandbox add-key "$SB" --slot 1 --descriptor "$PRIME_KEY"

# 3. Enable Nunchuk's Platform Key (it fills the last slot) and set its server-side
#    spending limit. Under this limit, agent + Platform Key auto-sign while Prime is off.
nunchuk sandbox platform-key enable "$SB"
nunchuk sandbox platform-key set-policy "$SB" \
    --auto-broadcast --limit-amount 100000 --limit-currency sat --limit-interval DAILY

# 4. Finalize -> a wallet. Grab the wallet id and the descriptor from the output.
WALLET=$(nunchuk sandbox finalize "$SB" | awk '/walletId:/{print $2}')
DESC=$(nunchuk wallet export "$WALLET" | grep -m1 -oE 'wsh\(.+\)#[a-z0-9]+')   # default = BIP-389 multipath <0;1>
```

> **2-of-2 instead?** Use `--m 2 --n 2`, add only the agent (slot 0) and Prime (slot 1),
> and **skip step 3** (no Platform Key). See [Recovery](#f-recovery) for the timelock branch.

## C. Enrol the wallet on Prime

```bash
prime-usb register --descriptor "$DESC"
```

Prime shows a review of the wallet (keys + spend paths). **Tap to confirm on the device.**
`prime-usb register` polls until Prime reports it enrolled. Now Prime recognises this
wallet and will co-sign for it.

> **Register the multipath descriptor, never the receive-only one.** Use the **default**
> `nunchuk wallet export "$WALLET"` (BIP-389, `<0;1>`) — *not* `--format all`, which emits
> only the receive branch (`/0/*`). Prime derives its match scripts from the descriptor's
> single-descriptors (receive = `<0>`, change = `<1>`); with no change branch it cannot match
> any spend that consumes a change UTXO and refuses it with **"does not match a registered
> wallet"** (the first real spend usually works, the second — funded by the first's change —
> fails). The `#checksum` differs between the two forms, so a wrong registration cannot be
> patched in place: you must re-register the multipath descriptor (another on-device tap), and
> the stale receive-only entry lingers because there is no USB unregister.

## D. Set Prime's on-device spending policy

Prime's policy is per-wallet and lives on the device. On the wallet's **Policy** screen:

- **Auto-sign limit** (per-tx) and the **velocity caps** (session + lifetime; daily/weekly
  need an RTC and are paused on hardware today).
- **Destination allowlist** — spends to anything not on it need a tap.
- **Freeze** — a kill-switch that forces every spend to a tap.

Prime auto-signs only when a spend is within **every** active cap **and** its destination
is allowed (or the allowlist is empty). Anything else is held for an on-device approval.

> In a **2-of-3**, Prime never auto-signs — the everyday limit is the Platform Key's
> (server-side, set in step B.3), and any spend routed to Prime always needs a tap.
> Prime's on-device caps apply to the **2-of-2** model, where Prime is the gate.

## E. Agent spending loop

```bash
# 1. Agent proposes a spend.
TXID=$(nunchuk tx create --wallet "$WALLET" --to "$DEST" --amount 50000 --currency sat \
         | awk '/Transaction ID:/{print $3}')

# 2. Agent signs its own key (server-side, by fingerprint) -> 1 of 2.
nunchuk tx sign --wallet "$WALLET" --tx-id "$TXID" --fingerprint "$AGENT_FP"

# 3. Route the partially-signed PSBT to Prime.
PSBT=$(nunchuk tx get --wallet "$WALLET" --tx-id "$TXID" | awk '/^PSBT:/{print $2}')
if SIGNED=$(prime-usb sign --psbt "$PSBT"); then
    # In policy: Prime auto-signed -> merge its signature and broadcast (agent + Prime).
    nunchuk tx sign --wallet "$WALLET" --tx-id "$TXID" --psbt "$SIGNED"
    nunchuk tx broadcast --wallet "$WALLET" --tx-id "$TXID"
else
    # Exit 10: over policy / frozen / not-allowlisted / recovery -> Prime is holding it.
    echo "Prime is holding this for an on-device approval. Approve on the device, then re-run."
fi
```

> **Prime off / unreachable?** Skip Prime entirely: after the agent signs (step 2), the
> **Platform Key** auto-co-signs server-side if the spend is within its limit (step B.3),
> and `--auto-broadcast` sends it. That's the `agent + Platform Key` lane — the agent
> keeps running with no device present.

## F. Recovery (2-of-2, with `nunchuk-cli`)

The **Prime-only recovery branch** — the dead-man's switch where Prime can sweep the coins
**alone** after `older(N)` of inactivity (≈30 days at `4320`) if the agent key is lost —
**is** constructible through `nunchuk-cli`. The trick: give the recovery leaf a **distinct
second Prime account** (account `1'`), so no key is named twice.

```bash
# 1. Read the timelock the user picked on the device, plus both Prime accounts.
REC_BLOCKS=$(prime-usb spec --field recovery_blocks)            # e.g. 4320 (~30 days)
PRIME0=$(prime-usb xpub --path "m/48'/1'/0'/2'")               # everyday leg
PRIME1=$(prime-usb xpub --path "m/48'/1'/1'/2'")               # recovery leg (2nd account)
# (AGENT_KEY as in section A.)

# 2. Build the recovery template — 3 distinct key slots.
SB=$(nunchuk sandbox create --name agent-wallet-recovery \
       --miniscript-template "or_d(multi(2,key_0_0,key_1_0),and_v(v:pk(key_2_0),older($REC_BLOCKS)))" \
       | grep -oiE '[0-9a-f-]{36}' | head -1)
nunchuk sandbox add-key "$SB" --slot 0 --descriptor "$AGENT_KEY"   # agent
nunchuk sandbox add-key "$SB" --slot 1 --descriptor "$PRIME0"      # Prime everyday
nunchuk sandbox add-key "$SB" --slot 2 --descriptor "$PRIME1"      # Prime recovery
WALLET=$(nunchuk sandbox finalize "$SB" | awk '/walletId:/{print $2}')
DESC=$(nunchuk wallet export "$WALLET" | grep -m1 -oE 'wsh\(.+\)#[a-z0-9]+')   # default = BIP-389 multipath <0;1>

# 3. Register on Prime (on-device approval), same as section C.
prime-usb register --descriptor "$DESC"
```

This yields `wsh(or_d(multi(2, agent, prime_acct0), and_v(v:pk(prime_acct1), older(N))))`.
Both Prime keys share a fingerprint but are different xpubs, which `nunchuk-cli` accepts
(it dedups on the xpub, not the fingerprint). It stays **Prime-alone recoverable** because
both keys come from Prime's one seed. No Platform Key, no hand-built embit descriptor.

> **What's verified vs not.** *Building, registering, and everyday-signing* this wallet are
> verified (Prime owns both accounts by fingerprint; the everyday leg auto-signs in policy).
> *Signing the recovery leg itself* (account `1'`, only used for an actual sweep) is the
> remaining on-device item. A recovery PSBT always needs an on-device approval; Prime never
> auto-signs it.

**2-of-3:** a plain 2-of-3 already **self-recovers** — lose any one key and the other two
spend — so it needs no extra branch. For the "Prime alone, no Nunchuk ever" guarantee, use
the 2-of-2 with the recovery leg above.

## Rules

- Enrolment is not completion — confirm `prime-usb register` reported the wallet enrolled.
- In-policy = unattended; over-policy / recovery = a human approves on Prime, every time.
- The Platform Key is a convenience co-signer, never a custodian: `agent + Prime` (and a
  2-of-2's Prime-only recovery) always bypass it, so Nunchuk can never freeze the funds.

## Notes

- A **factory reset changes Prime's key** (new fingerprint); any wallet built with the old
  key is orphaned. Re-run from [section A](#a-get-the-two-non-nunchuk-keys).
- **Simulator vs hardware:** on the hosted simulator the transport is a file bridge driven
  by `host/prime-signer`; on real hardware it is USB-CDC driven by `host/prime-usb`. The
  Nunchuk and policy steps are identical.
- Only standard account paths are served over USB (`prime-usb xpub` defaults to
  `m/48'/1'/0'/2'`); the device refuses arbitrary paths.
