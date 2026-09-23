// signing.rs — the security gate + the actual sign/finalize.
//
// Rules (from the plan):
//  - Never sign an unregistered/unmatched policy.
//  - Never silently fall back to a generic signing path.
//  - Refuse PSBTs with unknown/unsupported policy elements.
//  - Only sign when Passport owns a key on the *active* spend path.
//  - Recovery-path spends are allowed but flagged for explicit confirmation.
//  - Only ever produce SIGHASH_ALL signatures (SFT-8160).

use super::bitcoin::bip32::Xpriv;
use super::bitcoin::secp256k1::{All, Secp256k1};
use super::bitcoin::sighash::EcdsaSighashType;
use super::bitcoin::Psbt;
use super::miniscript::psbt::PsbtExt;
use super::psbt::MatchResult;
use super::{Error, RegisteredPolicy, Result, SpendPathKind};

#[derive(Debug, Clone, PartialEq)]
pub enum SignDecision {
    /// Safe to sign. Carries the active path; Recovery requires explicit
    /// user confirmation in the UI before `sign_and_finalize` is called.
    Allow {
        path: SpendPathKind,
        requires_confirmation: bool,
    },
    /// Do not sign. Carries a user-facing reason.
    Refuse(String),
}


/// The only sighash type this signer will ever accept or produce.
///
/// A signature made with anything else (`NONE`, `SINGLE`, or any
/// `ANYONECANPAY` variant) does not commit to the transaction's outputs, so a
/// malicious host can lift it out of the PSBT it proposed and replay it in a
/// different transaction spending the same UTXO. That bypasses the destination
/// allowlist and every spending cap, because the policy gate only ever sees the
/// benign transaction that was proposed. Forcing an on-device tap is *not* a
/// fix: the resulting signature still would not bind the outputs the user
/// approved. See SFT-8160.
const SIGHASH_ALL: u32 = EcdsaSighashType::All as u32; // 0x01

/// Reject a PSBT that requests any sighash type other than `SIGHASH_ALL`.
///
/// Called before every signing path, including manually approved spends. An
/// input with no explicit type is fine: rust-bitcoin defaults to `SIGHASH_ALL`.
pub fn check_sighash_all(psbt: &Psbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(ty) = input.sighash_type else {
            continue;
        };
        // Compare the raw u32 so non-standard values are caught too, rather
        // than going through a typed conversion that could itself error.
        if ty.to_u32() != SIGHASH_ALL {
            return Err(Error::Sign(format!(
                "input {i} requests sighash 0x{:02x}; only SIGHASH_ALL (0x01) is allowed",
                ty.to_u32()
            )));
        }
    }
    Ok(())
}

/// Assert every signature on the PSBT is `SIGHASH_ALL` before it leaves the
/// device, so a non-committing signature cannot escape even if a signing path
/// changes underneath us. Also covers signatures added by other co-signers.
fn assert_signatures_sighash_all(psbt: &Psbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        for (pk, sig) in &input.partial_sigs {
            if sig.sighash_type != EcdsaSighashType::All {
                return Err(Error::Sign(format!(
                    "refusing to release input {i}: signature for {pk} uses sighash 0x{:02x}, not SIGHASH_ALL",
                    sig.sighash_type as u32
                )));
            }
        }
        // Taproot is not a supported policy form here (see descriptor.rs), so
        // treat any taproot signature as an unvetted commitment rather than
        // letting it pass through unchecked.
        if input.tap_key_sig.is_some() || !input.tap_script_sigs.is_empty() {
            return Err(Error::Sign(format!(
                "refusing to release input {i}: taproot signatures are not supported"
            )));
        }
    }
    Ok(())
}

/// Decide whether signing is permitted, given a match result.
pub fn decide(psbt: &Psbt, m: &MatchResult, _policy: &RegisteredPolicy) -> SignDecision {
    // Refuse reusable (non-committing) sighashes up front so the UI shows a
    // reason instead of failing late. `sign()` enforces this again regardless.
    if let Err(e) = check_sighash_all(psbt) {
        return SignDecision::Refuse(format!("{e}"));
    }
    if !m.matched {
        return SignDecision::Refuse(
            "This PSBT does not match the registered policy. Refusing to sign.".into(),
        );
    }
    let Some(path) = m.active_path else {
        return SignDecision::Refuse("Could not determine the active spend path.".into());
    };
    if !m.passport_can_sign {
        return SignDecision::Refuse("Passport owns no key on the active spend path.".into());
    }
    SignDecision::Allow {
        path,
        requires_confirmation: matches!(path, SpendPathKind::Recovery),
    }
}

/// Sign every input we can with the device master key, WITHOUT finalizing.
/// This is the correct output for a coordinator workflow (Nunchuk combines and
/// finalizes). Errors if the device added no signatures.
pub fn sign(mut psbt: Psbt, master: &Xpriv, secp: &Secp256k1<All>) -> Result<Psbt> {
    check_sighash_all(&psbt)?;
    let signed = match psbt.sign(master, secp) {
        Ok(keys) => keys.len(),
        Err((keys, _errs)) => keys.len(),
    };
    if signed == 0 {
        return Err(Error::Sign("device key produced no signatures".into()));
    }
    assert_signatures_sighash_all(&psbt)?;
    Ok(psbt)
}

/// True if, after our signature, the PSBT can be finalized on its own (i.e.
/// Passport is the only signer the active path needs). Used as a UI hint;
/// never required for the coordinator workflow.
pub fn is_finalizable(psbt: &Psbt, secp: &Secp256k1<All>) -> bool {
    psbt.clone().finalize(secp).is_ok()
}

/// Sign every input we can with the device master key, then finalize.
/// Returns the finalized PSBT (ready for Nunchuk to broadcast).
pub fn sign_and_finalize(mut psbt: Psbt, master: &Xpriv, secp: &Secp256k1<All>) -> Result<Psbt> {
    check_sighash_all(&psbt)?;
    // Sign. Partial failures are tolerated (other signers' keys); we only
    // require at least one signature to have been added.
    let signed_keys = match psbt.sign(master, secp) {
        Ok(keys) => keys.len(),
        Err((keys, _errs)) => keys.len(),
    };
    if signed_keys == 0 {
        return Err(Error::Sign("device key produced no signatures".into()));
    }
    assert_signatures_sighash_all(&psbt)?;

    psbt.finalize_mut(secp)
        .map_err(|errs| Error::Sign(format!("finalize failed: {errs:?}")))?;
    Ok(psbt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nunchuk::bitcoin::absolute::LockTime;
    use crate::nunchuk::bitcoin::psbt::PsbtSighashType;
    use crate::nunchuk::bitcoin::transaction::Version;
    use crate::nunchuk::bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use std::str::FromStr;

    const ALL: u32 = 0x01;
    const NONE: u32 = 0x02;
    const SINGLE: u32 = 0x03;
    const ALL_ACP: u32 = 0x81;
    const NONE_ACP: u32 = 0x82; // the combination used by the SFT-8160 PoC
    const SINGLE_ACP: u32 = 0x83;

    fn psbt_with_sighash(ty: Option<u32>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_hex(
                    "0014000000000000000000000000000000000000dead",
                )
                .unwrap(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].sighash_type = ty.map(PsbtSighashType::from_u32);
        psbt
    }

    #[test]
    fn accepts_sighash_all_and_an_absent_type() {
        // Absent means rust-bitcoin signs with SIGHASH_ALL.
        check_sighash_all(&psbt_with_sighash(None)).expect("absent sighash is allowed");
        check_sighash_all(&psbt_with_sighash(Some(ALL))).expect("SIGHASH_ALL is allowed");
    }

    #[test]
    fn rejects_every_reusable_sighash() {
        for ty in [NONE, SINGLE, ALL_ACP, NONE_ACP, SINGLE_ACP] {
            let err = check_sighash_all(&psbt_with_sighash(Some(ty)))
                .expect_err(&format!("sighash 0x{ty:02x} must be refused"));
            match err {
                Error::Sign(msg) => assert!(
                    msg.contains(&format!("0x{ty:02x}")) && msg.contains("SIGHASH_ALL"),
                    "unexpected message for 0x{ty:02x}: {msg}"
                ),
                other => panic!("expected Error::Sign for 0x{ty:02x}, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_non_standard_sighash() {
        assert!(check_sighash_all(&psbt_with_sighash(Some(0x42))).is_err());
    }

    #[test]
    fn sign_refuses_reusable_sighash_before_producing_a_signature() {
        // The PoC path: a benign-looking transaction whose input asks for
        // NONE|ANYONECANPAY, so the signature would not commit to any output.
        let master = Xpriv::new_master(Network::Testnet, &[0x11; 32]).unwrap();
        let secp = Secp256k1::new();
        for ty in [NONE, SINGLE, ALL_ACP, NONE_ACP, SINGLE_ACP] {
            assert!(
                sign(psbt_with_sighash(Some(ty)), &master, &secp).is_err(),
                "sign() must refuse sighash 0x{ty:02x}"
            );
            assert!(
                sign_and_finalize(psbt_with_sighash(Some(ty)), &master, &secp).is_err(),
                "sign_and_finalize() must refuse sighash 0x{ty:02x}"
            );
        }
    }
}
