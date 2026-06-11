# Nunchuk Agent Signer - Signet test (simulator)

> **Outdated — read this first.** Two things changed since this was written:
> (1) **Nunchuk's CLI/backend supports mainnet/testnet only — NOT signet** (and its
> testnet backend indexes **testnet4**), so use testnet4 where this says signet.
> (2) The **hardware USB path now exists** (`host/prime-usb` over USB-CDC). For the real,
> verified, hardware-first runbook with current command syntax, use
> **`host/skills/prime-hsm/SKILL.md`**. This file is retained only as the local
> file-bridge (simulator) demo.

End-to-end test of the Prime-gated 2-of-2 on Signet, using the hosted simulator as
"Prime" and `nunchuk-cli` as the agent/coordinator on the same Mac. File-based
transport via `~/.passport-nunchuk-signer-keyos/` (the sim has no USB; real hardware
uses `prime-usb` over USB-CDC).

## What this proves
1. The app exports a BIP48 xpub Nunchuk accepts as a signer.
2. A 2-of-2 `wsh(sortedmulti(2, agent, prime))` treasury where Prime owns one key.
3. The on-device **policy gate**: under the per-tx limit + within velocity caps →
   Prime auto-signs with no interaction; over either → Prime requires a physical tap.
4. Prime signs as a 2-of-2 member (no finalize); `nunchuk tx sign --psbt` merges it.

## 0. Self-contained sim demo (no nunchuk-cli needed)
On first boot the app seeds a **demo 2-of-2 treasury** (the device is one signer)
and, when no `unsigned.psbt` bridge is present, builds a 50k-sat demo PSBT. So:
open the app -> **Sign PSBT** -> it matches the demo treasury, the gate returns
*auto-sign* (51k outflow < 100k per-tx default), the device signs, and the activity
ledger records an `Auto` entry. Whole gate->sign path, zero setup. Raise the amount
or drop a >100k PSBT to see the **approval** path.

## 1. Bridge directory
~/.passport-nunchuk-signer-keyos/
  passport-key.txt      OUT: Prime's [fp/48'/1'/0'/2']xpub (Export Xpub)
  import.txt            IN:  treasury descriptor to register
  unsigned.psbt         IN:  agent/nunchuk-cli PSBT (binary or base64)
  signed.psbt           OUT: Prime's signed PSBT (binary)
  signed-psbt.b64.txt   OUT: same, base64 (paste into `nunchuk tx sign`)

## 2. Export Prime's key
App -> **Export Xpub** (Signet) -> writes `passport-key.txt`:
`[<fp>/48'/1'/0'/2']tpub...` - the format `nunchuk sandbox add-key --descriptor` expects.

## 3. Build the 2-of-2 treasury in nunchuk-cli
    nunchuk auth login                  # needs a Developer Portal API key
    nunchuk network set signet          # verify backend supports signet, else testnet
    nunchuk config electrum set ssl://<signet-electrum>:51002
    nunchuk sandbox create --name treasury --m 2 --n 2 --address-type native-segwit
    nunchuk sandbox add-key <sandbox> --descriptor "$(cat ~/.passport-nunchuk-signer-keyos/passport-key.txt)"
    nunchuk sandbox add-key <sandbox> --descriptor "[<agentfp>/48'/1'/0'/2']tpub..."
    nunchuk sandbox finalize <sandbox>
    nunchuk wallet export <wallet> --format descriptor > ~/.passport-nunchuk-signer-keyos/import.txt
App -> **Import Policy** registers the real treasury (replacing the demo). Its
checksum must match `nunchuk wallet get`.

## 4. Agent builds a spend; Prime gates it
    nunchuk tx create <wallet> --to <signet-addr> --amount 0.0005   # 50k -> under limit
    nunchuk tx get <wallet> <txid> --psbt > ~/.passport-nunchuk-signer-keyos/unsigned.psbt
App -> **Sign PSBT**:
- Under policy -> auto-signs silently; ledger shows `Auto`.
- Over policy (e.g. --amount 0.005 = 500k > 100k per-tx, or velocity tripped) ->
  review screen names the binding cap + reason and requires the **Approve** tap.
Either way Prime writes `signed-psbt.b64.txt`.

## 5. Merge + broadcast
    nunchuk tx sign <wallet> <txid> --psbt "$(cat ~/.passport-nunchuk-signer-keyos/signed-psbt.b64.txt)"
    nunchuk tx broadcast <wallet> <txid>     # Electrum-direct
Agent key + Prime's gated signature = a valid 2-of-2 Signet spend.

## Policy / clock
Default (sim): per-tx 100k, daily 500k, weekly 1M, session 2M sats; host-time clock.
Persisted to `policy.json`. Session + lifetime caps are clock-free (hold even if the
host clock is spoofed); daily/weekly need a trusted clock - host time on the sim,
an RTC on hardware (TODO, see plan). The Nunchuk backend is a coordinator only
(metadata + group state), never a custodian: it holds no key and cannot sign.
