<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->
# Prime as Nunchuk's hardware policy co-signer

## The one-line model
**Nunchuk creates the wallet; Prime is the policy co-signer.** Prime is the
self-custodied, hardware-enforced equivalent of Nunchuk's server-side *Platform
key* — the spending limits live on the device and over-limit spends need a
physical tap.

## Why this shape (verified against Nunchuk, 2026)
Nunchuk's published "Bitcoin agents with bounded authority" model has four
parties — **your key, agent key, policy co-signer, shared wallet** — and enforces
limits ("spending limits, signing delays, dummy-transaction approvals; above the
limit, you sign") **at the Platform-key level, server-side**. Their own docs note
there is *no* hardware-signer integration or on-device physical approval.

That gap **is** Prime: same bounded-authority model, but the policy co-signer is a
hardware device you hold, enforcing the gate locally and requiring a physical
approval for anything over the limit. Software/server policy is convenient;
Prime is the sovereign, hardware answer.

Nunchuk's CLI (`nunchuk-cli`, "lets AI agents use Bitcoin safely") builds the
wallet — miniscript, decaying-multisig, external signers, descriptor/BSMS export
— so **no custom tooling is needed** to make Prime work with it.

## The two wallet models
| | Everyday spends | Over-limit / sovereign | Recovery |
|---|---|---|---|
| **2-of-2** (self-custodied) | agent + **Prime** (Prime auto-signs in-policy) | agent + Prime, Prime taps | Prime alone after `older(N)` |
| **2-of-3** (cloud-assisted) | agent + **Nunchuk Platform key** (server policy) | agent + Prime, Prime taps | any 2 of the 3 (self-recovers); **no** separate Prime-only branch |

In the **2-of-2**, Prime *is* the policy holder. In the **2-of-3**, Nunchuk's
Platform key holds the everyday policy and Prime is the over-limit / when-cloud-is-
down backstop (it never auto-signs in a 2-of-3 — it always approves).

## Recovery = a dead-man's-switch (2-of-2), built by `nunchuk-cli`
The recovery branch lets **Prime sweep the coins alone** after `older(N)` of inactivity
(~30 days at `4320`) if the agent key is lost. It **is** constructible through
`nunchuk-cli` — the trick is to give the recovery leaf a **distinct second Prime
account**, so no key is named twice:
```
wsh(or_d(multi(2, agent, prime_acct0/<0;1>/*), and_v(v:pk(prime_acct1/<0;1>/*), older(N))))
```
where `prime_acct0 = [fp/48'/1'/0'/2']` (everyday) and `prime_acct1 = [fp/48'/1'/1'/2']`
(recovery). Both derive from Prime's one seed, so it's still **Prime-alone recoverable**;
they share a fingerprint but are different xpubs.

**Why this works now (corrects an earlier assumption).** The *single-key* form reused one
xpub on two multipath legs (`<0;1>` + `<2;3>`), and `nunchuk-cli` rejected that with
**"Duplicate miniscript key"**. But the CLI dedups on the full key (xpub), **not** the
fingerprint (verified live), so two distinct Prime accounts pass. Prime recognises both as
its own because ownership is by **fingerprint** (`signers()` in `policy.rs`), and signing
derives whatever path the PSBT references — so no device change is needed to *register* or
*everyday-sign* the recovery wallet. (Reference hand-built coordinator `host/two_of_two_agent.py`
via embit still exists, but is no longer required.)

> **One caveat:** *signing the recovery leg itself* (account `1'`, for an actual sweep) is
> exercised only when the agent key is gone. Registration + everyday signing are verified
> (host test `two_account_recovery_descriptor_registers_and_signs_everyday_leg`); the
> recovery-leg sweep on hardware is the remaining item.

**The 2-of-3 carries no recovery branch.** A plain 2-of-3 self-recovers (lose any one key,
the other two spend), so the leg is redundant. For the "Prime alone, no Nunchuk ever"
guarantee, use the 2-of-2 with the recovery leg above.

## The Nunchuk-coordinated flow
No custom tooling for the everyday wallet (recovery is the exception — see above). The
full verified runbook is `host/skills/prime-hsm/SKILL.md`; in brief, for a 2-of-3:
```
# 1. Prime exports its key (prime-usb xpub, or "Export key" on the device)
PRIME_KEY = [fp/48'/1'/0'/2']tpub...

# 2. Nunchuk CLI builds the wallet (Nunchuk is the coordinator)
nunchuk sandbox create --name agent-wallet --m 2 --n 3 --address-type NATIVE_SEGWIT
nunchuk sandbox add-key <id> --slot 0 --descriptor "$AGENT_KEY"
nunchuk sandbox add-key <id> --slot 1 --descriptor "$PRIME_KEY"
nunchuk sandbox platform-key enable <id>     # fills the last slot with the Platform Key
nunchuk sandbox finalize <id>
nunchuk wallet export <id>                    # the descriptor (default = BIP-389 multipath <0;1>; NOT --format all, which is receive-only /0/* and won't match change-spends on Prime)

# 3. Enrol on Prime (on-device approval), then sign per policy:
prime-usb register --descriptor "<descriptor>"
#    in-policy  -> auto-signs unattended  (2-of-2 only; a 2-of-3 always taps)
#    over-limit -> on-device approval (physical tap)
```
For a 2-of-2 **with** recovery, add a third slot for Prime's account `1'` key and the
`or_d(..., and_v(v:pk(prime_acct1), older(N)))` leg (see the recovery section above) —
still all `nunchuk-cli`.

## What is and isn't Prime's job
**Prime does:** export its xpub (account `0'` everyday, account `1'` for a recovery leg);
hold + enforce its on-device spending policy (per-tx + velocity caps, destination allowlist,
freeze, all per-wallet and editable live); expose the onboarding **spec** (model + recovery
timelock) the agent reads at the wait step; confirm the registered wallet; sign per policy.
**Prime does not:** create the wallet or choose the keys — `nunchuk-cli` does. Prime does
not *set* the recovery timelock into the descriptor; it **publishes** the picked value over
USB (`prime-usb spec`) and the agent bakes it into the descriptor, so the on-device picker
is the source of truth. There is no on-device wallet minting (the old `seed_demo_wallet`
"Create wallet" path was a POC stand-in and is removed).

## App implications
- Onboarding for **both** models is the same guided flow: choose model → set
  Prime's spending policy (+ recovery timelock for the 2-of-2) → export Prime's key →
  wait for the agent to build + push the wallet over USB → confirm. No on-device mint.
- The recovery-timelock picker is **read back by the agent** over `prime-usb spec`, so the
  value you choose is the value built into the 2-of-2 descriptor — not a dead recommendation.
  (A 2-of-3 self-recovers, so it has no picker.)
- "Add wallet" enters the same guided flow (not a file picker).

## Sources
- Nunchuk, *Open-source Bitcoin agents with bounded authority* (2026) — https://nunchuk.io/blog/bitcoin-agents
- Nunchuk, *Miniscript: Programmable Bitcoin* / *Miniscript 101* (2026) — https://nunchuk.io/blog/miniscript-programmable-bitcoin , https://nunchuk.io/blog/miniscript101
- `nunchuk-cli` — https://github.com/nunchuk-io/nunchuk-cli
