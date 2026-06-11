#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# spend_2of3.py - drive a live agent + Passport (2-of-3) spend on testnet.
# Lane B: the agent signs its key, routes the PSBT to Passport over USB; Passport
# always-approves in 2-of-3, so it surfaces an on-device tap, signs, and the two
# signatures finalise the sortedmulti without Nunchuk in the loop.
#
#   build      -> build the unsigned PSBT from the funded UTXO + agent-sign it
#   route      -> send the agent-signed PSBT to Passport (tap to approve), finalise
#   broadcast  -> push the finalised tx to mempool.space testnet

import sys, json, time
import urllib.request
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit import bip32
from embit.psbt import PSBT, DerivationPath
from embit.finalizer import finalize_psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput
import two_of_two_agent as a  # reuse rpc()/port()

NET = NETWORKS["test"]
AGENT_SEED = bytes([0x42]) * 32
DESC = open("/tmp/2of3-descriptor.txt").readline().strip().split("#")[0]

# Funded UTXO (mempool, idx-0 receive address of te53nmfp).
PREV_TXID = "b57134ede024ab0a70de1787f5af55e443769926715695b6783a4abe248430e2"
PREV_VOUT = 1
PREV_VALUE = 468071
DEST = "tb1q2n0relk2m29khp3juwm2vnnmngfp67pxrafgh0"  # throwaway testnet sink
SEND = 150000   # > the 100k/day Platform-Key limit, so this is a Passport-routed spend
FEE = 500

AGENT_B64 = "/tmp/2of3-agent-signed.b64"
FINAL_HEX = "/tmp/2of3-final.hex"


def recv_at(i):
    return Descriptor.from_string(DESC.replace("/<0;1>/", "/0/")).derive(i)


def change_at(i):
    return Descriptor.from_string(DESC.replace("/<0;1>/", "/1/")).derive(i)


def build():
    d_recv = Descriptor.from_string(DESC.replace("/<0;1>/", "/0/"))
    d0 = d_recv.derive(0)
    spk = d0.script_pubkey()
    change = PREV_VALUE - SEND - FEE
    if change <= 0:
        sys.exit("input too small")
    vin = [TransactionInput(bytes.fromhex(PREV_TXID), PREV_VOUT)]
    vout = [
        TransactionOutput(SEND, __import__("embit").script.address_to_scriptpubkey(DEST)),
        TransactionOutput(change, change_at(0).script_pubkey()),
    ]
    psbt = PSBT(Transaction(vin=vin, vout=vout))
    inp = psbt.inputs[0]
    inp.witness_utxo = TransactionOutput(PREV_VALUE, spk)
    inp.witness_script = d0.witness_script()
    # Attach bip32 derivations for all three cosigners (agent + Prime sign; Platform
    # key present for completeness so the device matches its own key cleanly).
    for key in d_recv.keys:
        k0 = key.derive(0)
        inp.bip32_derivations[k0.get_public_key()] = DerivationPath(
            key.origin.fingerprint, list(key.origin.derivation) + [0, 0]
        )
    # Agent signs.
    root = bip32.HDKey.from_seed(AGENT_SEED, version=NET["xprv"])
    n = psbt.sign_with(root)
    print("agent signed %d input(s)" % n)
    open(AGENT_B64, "w").write(psbt.to_string())
    print("send %d sats to %s, change %d, fee %d" % (SEND, DEST, change, FEE))
    print("agent-signed PSBT -> %s" % AGENT_B64)


def route():
    b64 = open(AGENT_B64).read().strip()
    print("routing to Passport - APPROVE on the device when it prompts...")
    r = a.rpc({"cmd": "sign", "psbt": b64}, timeout=60)
    res = r.get("result")
    if res == "pending":
        print("PENDING (Passport-routed): %s" % r.get("reason"))
        print("  approve on Prime, then re-run `route` to collect the signature.")
        return
    if res != "signed":
        sys.exit("unexpected: %s" % r)
    signed = PSBT.from_string(r["psbt"])
    sigs = len(signed.inputs[0].partial_sigs)
    print("SIGNED by Passport. partial sigs: %d" % sigs)
    tx = finalize_psbt(signed)
    if not tx:
        sys.exit("finalize failed (need 2 sigs, have %d)" % sigs)
    raw = tx.serialize().hex()
    open(FINAL_HEX, "w").write(raw)
    print("2-of-3 FINALISED (agent + Passport). raw tx -> %s" % FINAL_HEX)
    print("txid:", tx.txid().hex())


def broadcast():
    raw = open(FINAL_HEX).read().strip()
    req = urllib.request.Request(
        "https://mempool.space/testnet/api/tx", data=raw.encode(), method="POST"
    )
    try:
        txid = urllib.request.urlopen(req, timeout=20).read().decode()
        print("BROADCAST ok, txid:", txid)
    except urllib.error.HTTPError as e:
        print("broadcast rejected:", e.read().decode())


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    {"build": build, "route": route, "broadcast": broadcast}.get(cmd, lambda: sys.exit("usage: build|route|broadcast"))()
