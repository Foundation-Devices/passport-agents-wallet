// signing.rs — the security gate + the actual sign/finalize.
//
// Rules (from the plan):
//  - Never sign an unregistered/unmatched policy.
//  - Never silently fall back to a generic signing path.
//  - Refuse PSBTs with unknown/unsupported policy elements.
//  - Only sign when Passport owns a key on the *active* spend path.
//  - Recovery-path spends are allowed but flagged for explicit confirmation.

use super::bitcoin::bip32::Xpriv;
use super::bitcoin::secp256k1::{All, Secp256k1};
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

/// Decide whether signing is permitted, given a match result.
pub fn decide(m: &MatchResult, _policy: &RegisteredPolicy) -> SignDecision {
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
    let signed = match psbt.sign(master, secp) {
        Ok(keys) => keys.len(),
        Err((keys, _errs)) => keys.len(),
    };
    if signed == 0 {
        return Err(Error::Sign("device key produced no signatures".into()));
    }
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
    // Sign. Partial failures are tolerated (other signers' keys); we only
    // require at least one signature to have been added.
    let signed_keys = match psbt.sign(master, secp) {
        Ok(keys) => keys.len(),
        Err((keys, _errs)) => keys.len(),
    };
    if signed_keys == 0 {
        return Err(Error::Sign("device key produced no signatures".into()));
    }

    psbt.finalize_mut(secp)
        .map_err(|errs| Error::Sign(format!("finalize failed: {errs:?}")))?;
    Ok(psbt)
}
