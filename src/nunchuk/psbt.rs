// psbt.rs — match a PSBT against a registered policy and determine the active
// spend branch. This is the security gate's input: we only sign what matches.

use std::collections::HashSet;

use super::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use super::bitcoin::secp256k1::Secp256k1;
use super::bitcoin::{Psbt, ScriptBuf};
use super::{descriptor, RegisteredPolicy, Result, SpendPathKind};

/// The trailing child index of a derivation path (the wildcard `/*` position in
/// a wallet descriptor). Both normal and hardened tails are read; wallet address
/// indices are normal, but we stay liberal.
fn tail_index(path: &DerivationPath) -> Option<u32> {
    path.into_iter().next_back().map(|c| match c {
        ChildNumber::Normal { index } | ChildNumber::Hardened { index } => *index,
    })
}

/// Every child index a PSBT actually references, gathered from the bip32 / taproot
/// key origins on its inputs AND outputs. A PSBT names the exact derivation for
/// each key it touches, so these are the ONLY indices that can match this wallet.
/// Deriving at just these turns an O(gap) brute-force scan (hundreds of EC
/// derivations on a device with no secp acceleration) into a handful. Falls back
/// to `0..gap` only when a PSBT carries no derivation hints at all (defensive —
/// a wallet we can actually sign for always names its paths).
fn referenced_indices(psbt: &Psbt, gap: u32) -> Vec<u32> {
    let mut set: HashSet<u32> = HashSet::new();
    for input in &psbt.inputs {
        for (_, path) in input.bip32_derivation.values() {
            if let Some(i) = tail_index(path) {
                set.insert(i);
            }
        }
        for (_, (_, path)) in input.tap_key_origins.values() {
            if let Some(i) = tail_index(path) {
                set.insert(i);
            }
        }
    }
    for output in &psbt.outputs {
        for (_, path) in output.bip32_derivation.values() {
            if let Some(i) = tail_index(path) {
                set.insert(i);
            }
        }
        for (_, (_, path)) in output.tap_key_origins.values() {
            if let Some(i) = tail_index(path) {
                set.insert(i);
            }
        }
    }
    if set.is_empty() {
        (0..gap).collect()
    } else {
        set.into_iter().collect()
    }
}

/// Derive a policy's scriptPubKeys at the given indices across both descriptor
/// paths (receive + change), reusing ONE secp context. miniscript's
/// `script_pubkey()` otherwise spins up a fresh `Secp256k1::verification_only()`
/// per key per index — the dominant cost on hardware. Parsing the descriptor and
/// building the context happen exactly once here.
fn spks_at(policy: &RegisteredPolicy, indices: &[u32]) -> Result<HashSet<ScriptBuf>> {
    let parsed = descriptor::import(&policy.descriptor)?;
    let singles = parsed
        .descriptor
        .into_single_descriptors()
        .map_err(|e| super::Error::Match(format!("multipath split: {e}")))?;
    let secp = Secp256k1::verification_only();
    let mut set = HashSet::new();
    for single in &singles {
        for &idx in indices {
            if let Ok(def) = single.at_derivation_index(idx) {
                if let Ok(concrete) = def.derived_descriptor(&secp) {
                    set.insert(concrete.script_pubkey());
                }
            }
        }
    }
    Ok(set)
}

/// Outcome of matching a PSBT against a registered policy.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    /// Every input's witnessScript matched a script derived from this policy.
    pub matched: bool,
    /// The spend branch the PSBT intends to use (inferred from input sequence).
    pub active_path: Option<SpendPathKind>,
    /// Relative timelock (blocks) of the active path, if it is a recovery path.
    pub active_timelock_blocks: Option<u32>,
    /// Passport owns a key on the active path AND that key is in the PSBT's
    /// bip32 derivations (i.e. we can actually contribute a signature).
    pub passport_can_sign: bool,
    pub matched_inputs: usize,
    pub total_inputs: usize,
    /// Human-readable notes for the signing-review screen / debugging.
    pub reasons: Vec<String>,
}

/// Match a PSBT against a single registered policy.
/// `gap` is how many derivation indices to check per descriptor path.
pub fn match_psbt(
    psbt: &Psbt,
    policy: &RegisteredPolicy,
    passport_fp: Fingerprint,
    gap: u32,
) -> Result<MatchResult> {
    // Candidate scriptPubKeys, derived only at the indices the PSBT references
    // (see `referenced_indices`). Matching on the spk (not the witnessScript)
    // lets one matcher cover both P2WSH and Taproot policies — Taproot inputs
    // carry no witnessScript, only an spk.
    let candidates = spks_at(policy, &referenced_indices(psbt, gap))?;

    let total_inputs = psbt.inputs.len();
    let mut matched_inputs = 0;
    let mut reasons = Vec::new();

    for (i, input) in psbt.inputs.iter().enumerate() {
        match input.witness_utxo.as_ref() {
            Some(utxo) if candidates.contains(&utxo.script_pubkey) => matched_inputs += 1,
            Some(_) => reasons.push(format!("input {i}: scriptPubKey not from this policy")),
            None => reasons.push(format!("input {i}: no witness_utxo (cannot verify)")),
        }
    }
    let matched = total_inputs > 0 && matched_inputs == total_inputs;

    if !matched {
        return Ok(MatchResult {
            matched: false,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            matched_inputs,
            total_inputs,
            reasons,
        });
    }

    // Infer the active branch from every input's nSequence. For a decaying
    // (multi-tier) policy, a relative-block nSequence unlocks every recovery
    // tier whose older(n) it satisfies; the deepest tier reached (largest n)
    // is the one being exercised. Mixed active branches are refused because a
    // single signing confirmation would be ambiguous.
    let input_paths: Vec<Option<u32>> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| {
            let seq_blocks = relative_blocks(txin.sequence);
            deepest_unlocked_recovery(policy, seq_blocks)
        })
        .collect();
    let first_path = input_paths.first().copied().flatten();
    if input_paths.iter().any(|p| *p != first_path) {
        reasons.push("inputs use mixed primary/recovery spend paths".into());
        return Ok(MatchResult {
            matched: true,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            matched_inputs,
            total_inputs,
            reasons,
        });
    }

    let (active_path, active_timelock_blocks) = match first_path {
        Some(n) => {
            reasons.push(format!("nSequence unlocks recovery older({n})"));
            (SpendPathKind::Recovery, Some(n))
        }
        None => (SpendPathKind::Primary, None),
    };

    // The PSBT must reference Passport's key (segwit-v0 bip32 origins OR Taproot
    // tap key origins), and Passport must own a key on a path that is spendable
    // *right now* — the primary path always, plus any recovery tier the
    // nSequence has unlocked. A key on a not-yet-matured tier cannot sign.
    let passport_in_psbt = psbt.inputs.iter().any(|inp| {
        inp.bip32_derivation
            .values()
            .any(|(fp, _)| *fp == passport_fp)
            || inp
                .tap_key_origins
                .values()
                .any(|(_, (fp, _))| *fp == passport_fp)
    });
    let fp_str = passport_fp.to_string();
    let owns_active_key = policy.paths.iter().any(|p| {
        let active = match (active_path, p.kind) {
            (SpendPathKind::Primary, SpendPathKind::Primary) => true,
            (SpendPathKind::Recovery, SpendPathKind::Recovery) => {
                p.relative_timelock_blocks == active_timelock_blocks
            }
            _ => false,
        };
        active && p.signer_fingerprints.contains(&fp_str)
    });
    let passport_can_sign = passport_in_psbt && owns_active_key;
    if !passport_can_sign {
        reasons.push(
            "Passport key is not on a currently-spendable path (or not referenced by the PSBT)"
                .into(),
        );
    }

    Ok(MatchResult {
        matched,
        active_path: Some(active_path),
        active_timelock_blocks,
        passport_can_sign,
        matched_inputs,
        total_inputs,
        reasons,
    })
}

/// Find the registered policy a PSBT belongs to, out of many.
pub fn match_against_all<'a>(
    psbt: &Psbt,
    policies: &'a [RegisteredPolicy],
    passport_fp: Fingerprint,
    gap: u32,
) -> Result<Option<(&'a RegisteredPolicy, MatchResult)>> {
    for p in policies {
        let r = match_psbt(psbt, p, passport_fp, gap)?;
        if r.matched {
            return Ok(Some((p, r)));
        }
    }
    Ok(None)
}

/// Relative block-height from an nSequence, if it encodes one.
fn relative_blocks(seq: super::bitcoin::Sequence) -> Option<u32> {
    seq.to_relative_lock_time().and_then(|lt| match lt {
        super::bitcoin::relative::LockTime::Blocks(h) => Some(h.value() as u32),
        super::bitcoin::relative::LockTime::Time(_) => None,
    })
}

fn deepest_unlocked_recovery(policy: &RegisteredPolicy, seq_blocks: Option<u32>) -> Option<u32> {
    policy
        .paths
        .iter()
        .filter(|p| matches!(p.kind, SpendPathKind::Recovery))
        .filter_map(|p| match (seq_blocks, p.relative_timelock_blocks) {
            (Some(s), Some(n)) if s >= n => Some(n),
            _ => None,
        })
        .max()
}

/// Candidate scriptPubKeys derived from a policy's descriptor (both receive +
/// change paths, up to `gap` indices). Used to detect which PSBT outputs are
/// change returning to the wallet.
pub fn candidate_spks(
    policy: &RegisteredPolicy,
    gap: u32,
) -> Result<HashSet<super::bitcoin::ScriptBuf>> {
    // No PSBT context here (this checks a scanned address), so a range scan is
    // required — but it shares one secp context instead of one per derivation.
    spks_at(policy, &(0..gap).collect::<Vec<_>>())
}

/// scriptPubKeys on the policy's CHANGE branch only (the internal `<...;1>` leg of
/// the multipath), at the given indices, with one shared secp context. Used to
/// detect genuine change. Receive-branch outputs are deliberately NOT counted as
/// change: a spend the agent routes to one of the wallet's own *receive* addresses
/// must still be metered as outflow (it's a chosen destination), so it can't be
/// used to understate outflow and slip a spend under the velocity caps.
fn change_spks(policy: &RegisteredPolicy, indices: &[u32]) -> Result<HashSet<ScriptBuf>> {
    let parsed = descriptor::import(&policy.descriptor)?;
    let singles = parsed
        .descriptor
        .into_single_descriptors()
        .map_err(|e| super::Error::Match(format!("multipath split: {e}")))?;
    // The change leg is the LAST single descriptor (receive=<0>, change=<1>). With no
    // distinct change branch, treat nothing as change (everything counts as leaving).
    let mut set = HashSet::new();
    if singles.len() >= 2 {
        if let Some(change) = singles.last() {
            let secp = Secp256k1::verification_only();
            for &idx in indices {
                if let Ok(def) = change.at_derivation_index(idx) {
                    if let Ok(concrete) = def.derived_descriptor(&secp) {
                        set.insert(concrete.script_pubkey());
                    }
                }
            }
        }
    }
    Ok(set)
}

/// Addresses of the outputs that LEAVE the wallet (non-change), for the destination
/// allowlist. Change outputs (returning to the wallet) are excluded - they always
/// count as "staying". An output whose scriptPubKey can't be rendered as an address
/// yields an empty string, which never matches an allowlist entry (fail-closed).
pub fn outgoing_addresses(
    psbt: &Psbt,
    policy: &RegisteredPolicy,
    gap: u32,
    network: super::bitcoin::Network,
) -> Result<Vec<String>> {
    let change = change_spks(policy, &referenced_indices(psbt, gap))?;
    let mut out = Vec::new();
    for o in &psbt.unsigned_tx.output {
        if change.contains(&o.script_pubkey) {
            continue;
        }
        let addr = super::bitcoin::Address::from_script(&o.script_pubkey, network)
            .map(|a| a.to_string())
            .unwrap_or_default();
        out.push(addr);
    }
    Ok(out)
}

/// Net outflow of a PSBT against a policy: total input value minus change that
/// returns to the wallet = payment + miner fee, in sats. This is the figure the
/// spending-policy gate meters (what actually leaves the wallet's control).
pub fn outflow_sats(psbt: &Psbt, policy: &RegisteredPolicy, gap: u32) -> Result<u64> {
    // Only the change branch counts as "returns to the wallet"; see `change_spks`.
    let candidates = change_spks(policy, &referenced_indices(psbt, gap))?;
    let total_in: u64 = psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat()))
        .sum();
    let change: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|o| candidates.contains(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .sum();
    Ok(total_in.saturating_sub(change))
}
