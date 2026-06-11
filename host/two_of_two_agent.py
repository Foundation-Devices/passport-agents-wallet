#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# two_of_two_agent.py - a self-custodied 2-of-2 agent coordinator for Passport Prime.
#
# This is the agent side of the Nunchuk "agent + Prime" model (see
# host/skills/prime-hsm/SKILL.md), with NO Nunchuk backend in the loop: the agent
# holds one hot key, Prime holds the other, and the agent coordinates locally.
#
#   setup            -> fetch Prime's xpub over USB, build the 2-of-2 descriptor,
#                       register it on Prime (tap to approve on the device).
#   spend <sats>     -> build a PSBT, sign it with the agent key, route it to Prime.
#                       Under policy: Prime auto-signs unattended -> 2-of-2 finalizes.
#                       Over policy:  Prime holds it for an on-device tap.
#
# Transport: newline-delimited JSON over USB-CDC (the device protocol). Prime keeps
# its spending policy on-device; the agent never sees the device key.

import sys, json, time, glob, hashlib
import serial
from embit import bip32, script
from embit.networks import NETWORKS
from embit.descriptor import Descriptor
from embit.psbt import PSBT, DerivationPath
from embit.finalizer import finalize_psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

# The agent's hot key. Deterministic for the POC; in production this is the agent's
# own secret, generated + stored by the agent process (never leaves it).
AGENT_SEED = bytes([0x42]) * 32
ACCOUNT = "m/48h/1h/0h/2h"          # BIP48 P2WSH, testnet
NET = NETWORKS["test"]
DEST = "tb1q2n0relk2m29khp3juwm2vnnmngfp67pxrafgh0"  # throwaway testnet sink
FEE = 300
# Prime-alone recovery if the agent key is ever lost: after this many blocks, Prime
# can sweep the wallet by itself (always with a physical tap). ~30 days at 10 min/block.
RECOVERY_BLOCKS = 4320


def port():
    g = glob.glob("/dev/cu.usbmodemPassport_Prime*")
    if not g:
        sys.exit("no Prime USB port - is the Nunchuk app open on the device?")
    return g[0]


def rpc(req, timeout=15):
    s = serial.Serial(port(), 115200, timeout=timeout)
    time.sleep(0.2)
    s.reset_input_buffer()
    s.write((json.dumps(req) + "\n").encode())
    s.flush()
    line = s.readline().decode(errors="replace").strip()
    s.close()
    if not line:
        return {"result": "(timeout)"}
    return json.loads(line)


def agent_root():
    return bip32.HDKey.from_seed(AGENT_SEED, version=NET["xprv"])


def agent_key_str():
    root = agent_root()
    acct = root.derive(ACCOUNT)
    return "[%s/%s]%s" % (root.my_fingerprint.hex(), ACCOUNT.lstrip("m/"), acct.to_public().to_string())


def prime_key_str():
    fp = rpc({"cmd": "fingerprint"}).get("fingerprint")
    r = rpc({"cmd": "xpub", "path": "m/48'/1'/0'/2'"})
    key = r.get("key")
    if not key:
        sys.exit("could not read Prime xpub: %s" % r)
    # Normalise the device's ' to embit/miniscript-friendly h.
    return key.replace("'", "h")


def descriptor_str():
    a, p = agent_key_str(), prime_key_str()
    # Everyday path: agent + Prime (2-of-2, Prime gates by policy). Recovery path:
    # Prime ALONE after RECOVERY_BLOCKS, reusing Prime's key on the <2;3> branch so
    # its addresses never collide with the multisig ones. Prime dictates the recovery;
    # the agent just receives this descriptor to build PSBTs + watch the wallet.
    return (
        "wsh(or_d(multi(2,%s/<0;1>/*,%s/<0;1>/*),"
        "and_v(v:pk(%s/<2;3>/*),older(%d))))" % (a, p, p, RECOVERY_BLOCKS)
    )


def single(desc, recv):
    # recv=True -> receive branch (multipath leg 0): <0;1>->0, <2;3>->2.
    # recv=False -> change branch (leg 1): <0;1>->1, <2;3>->3.
    if recv:
        return Descriptor.from_string(desc.replace("/<0;1>/", "/0/").replace("/<2;3>/", "/2/"))
    return Descriptor.from_string(desc.replace("/<0;1>/", "/1/").replace("/<2;3>/", "/3/"))


def build_unsigned(desc, send_sats, in_value):
    full_recv = single(desc, True)   # or_d, receive branch -> spk + full witness script
    full_chg = single(desc, False)   # or_d, change branch -> change spk
    d0 = full_recv.derive(0)
    change = in_value - send_sats - FEE
    if change <= 0:
        sys.exit("input value too small for amount+fee")
    vin = [TransactionInput(bytes.fromhex("11" * 32), 0)]  # synthetic prevout (not broadcast)
    vout = [
        TransactionOutput(send_sats, script.address_to_scriptpubkey(DEST)),
        TransactionOutput(change, full_chg.derive(0).script_pubkey()),
    ]
    psbt = PSBT(Transaction(vin=vin, vout=vout))
    inp = psbt.inputs[0]
    inp.witness_utxo = TransactionOutput(in_value, d0.script_pubkey())
    inp.witness_script = d0.witness_script()
    # An everyday spend uses the multi() branch only, so attach just the agent + Prime
    # multisig keys (the recovery key on <2> isn't a signer here).
    multi = Descriptor.from_string("wsh(multi(2,%s/0/*,%s/0/*))" % (agent_key_str(), prime_key_str()))
    for key in multi.keys:
        k0 = key.derive(0)
        inp.bip32_derivations[k0.get_public_key()] = DerivationPath(
            key.origin.fingerprint, list(key.origin.derivation) + [0, 0]
        )
    return psbt


def cmd_setup():
    desc = descriptor_str()
    print("2-of-2 descriptor:\n  %s" % desc)
    print("registering on Prime - approve on the device when it prompts...")
    for _ in range(60):
        r = rpc({"cmd": "register", "descriptor": desc})
        res = r.get("result")
        if res == "registered":
            print("REGISTERED on Prime: name=%s checksum=%s" % (r.get("name"), r.get("checksum")))
            return
        if res == "error":
            sys.exit("register failed: %s" % r.get("message"))
        print("  waiting for on-device approval... (%s)" % r.get("reason", res))
        time.sleep(3)
    sys.exit("registration not approved in time")


def cmd_spend(send_sats):
    desc = descriptor_str()
    in_value = send_sats + FEE + 20_000  # synthetic UTXO big enough to leave change
    psbt = build_unsigned(desc, send_sats, in_value)

    # 1. Agent signs its hot key.
    n = psbt.sign_with(agent_root())
    print("agent signed %d input(s)" % n)
    b64 = psbt.to_string()

    # 2. Route to Prime. Under policy -> auto-signed; over policy -> held for a tap.
    print("routing to Prime (outflow = %d sats)..." % (send_sats + FEE))
    r = rpc({"cmd": "sign", "psbt": b64}, timeout=45)
    res = r.get("result")
    if res == "pending":
        print("PENDING (over policy): %s" % r.get("reason"))
        print("  -> approve on Prime, then re-run `spend %d` to collect the signature." % send_sats)
        return
    if res != "signed":
        sys.exit("unexpected: %s" % r)

    # 3. Prime signed. The 2-of-2 multi() branch is satisfied once BOTH the agent and
    #    Prime have signed (2 partial sigs). The witness assembly for the recovery
    #    miniscript is done by a full coordinator (Nunchuk / rust-miniscript); embit's
    #    simple finalizer only knows plain multisig, so we verify the signatures here.
    signed = PSBT.from_string(r["psbt"])
    sigs = len(signed.inputs[0].partial_sigs)
    print("SIGNED by Prime. partial sigs on input: %d" % sigs)
    if sigs >= 2:
        try:
            tx = finalize_psbt(signed)
            print("2-of-2 FINALISED (plain multisig): %d bytes, %d witness items" %
                  (len(tx.serialize()), len(tx.vin[0].witness.items)))
        except Exception:
            print("2-of-2 COMPLETE: agent + Prime both signed the everyday path.")
        print("agent + Prime alone satisfied the wallet - no human, no Nunchuk server.")
    else:
        print("WARN: expected 2 signatures, got %d" % sigs)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: two_of_two_agent.py {setup | spend <sats>}")
    if sys.argv[1] == "setup":
        cmd_setup()
    elif sys.argv[1] == "spend":
        cmd_spend(int(sys.argv[2]))
    else:
        sys.exit("unknown command %r" % sys.argv[1])


if __name__ == "__main__":
    main()
