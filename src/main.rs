// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Nunchuk Signer — a policy-aware signer for Nunchuk-shaped Miniscript policies.
//!
//! Passport is NOT the wallet: Nunchuk desktop builds the PSBT. This app
//! registers the policy, matches a PSBT against it, shows the active spend
//! branch, and signs only when the PSBT matches and Passport owns a key on
//! that branch. All policy/PSBT/signing logic lives in `src/nunchuk`.

mod nunchuk;
mod master_key;
mod theme;
#[cfg(keyos)]
mod transport;

use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use gui_permissions::GuiPermissions;
// Bitcoin types used to build the demo wallet PSBT (+ test fixtures).
use nunchuk::bitcoin::{
    absolute::LockTime, psbt::Input, transaction::Version, Amount, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use nunchuk::{
    bitcoin::{
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
        psbt::Psbt,
        secp256k1::{All, Secp256k1},
        Address, Network,
    },
    descriptor, device_protocol, gate, history, policy, psbt as lpsbt, signing, store, RegisteredPolicy,
    SpendPathKind,
};
use slint_keyos_platform::{
    app,
    gui_server_api::navigation::{
        filepicker::{AllowedLocations, Location as PickLocation, SelectFileOptions},
        qrscanner::{ScanQrOptions, ScanQrResult},
    },
    navigation::{open_qr_scanner, select_file},
    slint::{ComponentHandle, ModelRc, SharedString, VecModel},
    spawn_local, spawn_worker,
};

app!("Nunchuk");

const DEFAULT_NETWORK: Network = Network::Testnet;
const MAINNET_ACCOUNT_PATH: &str = "m/48'/0'/0'/2'";
const TEST_ACCOUNT_PATH: &str = "m/48'/1'/0'/2'";
#[cfg(test)]
const RECOVERY_BLOCKS: u32 = 52_560; // ~12 months (test fixtures only)
const GAP: u32 = 100; // fallback address scan when a PSBT names no derivations (rare)

/// Process-wide secp256k1 context. Building the full sign+verify tables is the
/// expensive part of `Secp256k1::new()`; do it once for the whole app lifetime
/// instead of per sign. `Secp256k1<All>` is `Sync`, so a `'static` shared ref is
/// safe to hand to the off-thread signer.
fn shared_secp() -> &'static Secp256k1<All> {
    static SECP: std::sync::OnceLock<Secp256k1<All>> = std::sync::OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}
const DATA_SUBDIR: &str = ".passport-nunchuk-signer-keyos";
const MAX_PSBT_BYTES: u64 = 1_048_576;
const MAX_DESCRIPTOR_BYTES: u64 = 131_072;

// File-exchange paths inside DATA_SUBDIR (Nunchuk on the same host reads/writes
// these for the Signet test). No QR: Nunchuk is file-only (no UR/BBQr/scanner).
const IMPORT_DESCRIPTOR_FILE: &str = "import.txt"; // host-bridge descriptor (sim test)
const UNSIGNED_PSBT_FILE: &str = "unsigned.psbt"; // Nunchuk's exported PSBT (base64 or binary)
const SIGNED_PSBT_FILE: &str = "signed.psbt"; // we write base64 for Nunchuk to load
const EXPORT_KEY_FILE: &str = "passport-key.txt"; // key-with-origin for Nunchuk signer import
const VERIFY_ADDRESS_FILE: &str = "verify-address.txt"; // sim bridge for address verification
const EXPORT_DIR: &str = "nunchuk"; // subdir used when the user picks a location root

/// Live app state shared across UI callbacks.
struct AppState {
    secp: Secp256k1<All>,
    seed: [u8; 32],
    fp: Fingerprint,
    data_dir: PathBuf,
    policies: store::PolicyStore,
    xpub_network: Network,
    pending: Option<Pending>,
    /// A parsed-but-not-yet-committed policy awaiting the user's confirmation in
    /// the guided import-review flow.
    pending_import: Option<RegisteredPolicy>,
    /// The most recently signed PSBT (serialized), kept in memory so "Save to
    /// file" can export it via the file picker without a std::fs round-trip
    /// (which doesn't work on device).
    last_signed: Option<Vec<u8>>,
    /// On-device spending policy (per-tx + velocity caps) Prime enforces.
    spend_policy: gate::SpendPolicy,
    /// Append-only spend ledger (velocity windows + activity log).
    history: history::SpendHistory,
    /// Last PSBT txid the HSM poller acted on, so it is processed once.
    last_hsm_txid: Option<String>,
    /// USB-thread -> UI signals, drained by the main-thread poll timer. A descriptor
    /// arrived over USB and is staged in `pending_import` awaiting on-device approval.
    usb_register_pending: bool,
    /// An over-policy PSBT was queued and needs the review screen surfaced.
    usb_sign_pending: bool,
    /// A background thread mutated the store; the home screen needs a redraw.
    needs_refresh: bool,
    /// Over-policy PSBTs awaiting on-device approval (the agent can push several
    /// before you tap), surfaced one at a time. `pending` holds the one on screen.
    pending_queue: std::collections::VecDeque<Pending>,
    /// txid -> signed PSBT bytes. Makes re-pushing the same PSBT idempotent (one
    /// activity row, not three) and lets the host retrieve an approved signature
    /// by re-sending the sign request. Bounded via `signed_cache_order`.
    signed_cache: std::collections::HashMap<String, Vec<u8>>,
    /// FIFO of cached txids, so `signed_cache` can't grow without bound over a
    /// long unattended session (oldest signatures are evicted first).
    signed_cache_order: std::collections::VecDeque<String>,
    /// Txids currently being signed off-thread by `on_approve`. Prevents a host
    /// that re-sends the same over-policy PSBT mid-sign from queueing a duplicate
    /// approval (the signature isn't in `signed_cache` until the worker finishes).
    signing_in_flight: std::collections::HashSet<String>,
    /// Fail-closed switch. Set when a saved file (ledger / policy) was corrupt at
    /// boot, a debit failed to persist, or the user pressed "freeze". While set,
    /// auto-signing is PAUSED: every spend is forced to an on-device approval. The
    /// velocity budget can't be silently bypassed by corrupting the ledger.
    safe_mode: bool,
    /// Human-readable reason safe mode is active (shown on the home banner).
    safe_mode_reason: String,
    /// Per-wallet spending-policy overrides, keyed by descriptor checksum. A wallet
    /// with no entry uses `spend_policy` (the global default). This isolates wallets:
    /// a runaway agent on one wallet can't spend another's budget or escape another's
    /// allowlist. Velocity budgets are computed per-wallet via `history.for_wallet`.
    wallet_policies: WalletPolicies,
}

impl AppState {
    /// The effective spending policy for a wallet: its override if set, else the
    /// global default. Returns an owned clone so callers can read it while the
    /// ledger is mutated for the same wallet.
    fn policy_for(&self, checksum: &str) -> gate::SpendPolicy {
        self.wallet_policies.get(checksum).cloned().unwrap_or_else(|| self.spend_policy.clone())
    }
}

/// Cap on `signed_cache` entries (each is a full serialized PSBT). Generous for the
/// pending-queue model while bounding memory on a long-running device.
const SIGNED_CACHE_MAX: usize = 256;

impl AppState {
    /// Cache a signed PSBT by txid, evicting the oldest if over `SIGNED_CACHE_MAX`.
    fn cache_signed(&mut self, txid: String, bytes: Vec<u8>) {
        if self.signed_cache.insert(txid.clone(), bytes).is_none() {
            self.signed_cache_order.push_back(txid);
            while self.signed_cache_order.len() > SIGNED_CACHE_MAX {
                if let Some(old) = self.signed_cache_order.pop_front() {
                    self.signed_cache.remove(&old);
                }
            }
        }
    }
}

/// A PSBT awaiting the user's sign/reject decision, with the policy + match it
/// was reviewed against (so the signing gate is re-checked at approve time).
struct Pending {
    psbt: Psbt,
    policy: RegisteredPolicy,
    matched: lpsbt::MatchResult,
    /// Net outflow (payment + fee) the gate metered, in sats.
    outflow: u64,
}

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Nunchuk Signer");

    // Apply the app theme (resources/theme.json) and track system light/dark.
    theme::init(&ui);

    let secp = Secp256k1::new();
    let seed = match master_key::app_seed() {
        Ok(seed) => seed,
        Err(_) => {
            show_startup_error(&ui, tr::lookup_id(TrId::ErrorSeedUnavailable));
            ui.run().expect("UI running");
            return;
        }
    };
    let master = master_for_network(&seed, DEFAULT_NETWORK).expect("master xpriv");
    let fp = master.fingerprint(&secp);

    let data_dir = data_dir();
    #[cfg(not(keyos))]
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }

    #[allow(unused_mut)] // mutated only on device (clock downgrade below)
    let (mut spend_policy, policy_unsafe) = load_spend_policy(&data_dir);
    // The device has no trusted RTC, so rolling time-window (daily/weekly) caps
    // can't be honest there. Downgrade the clock to None on device: the gate then
    // enforces the clock-free session + lifetime caps only, and the UI labels the
    // time-window caps as inactive instead of pretending they roll over.
    #[cfg(keyos)]
    {
        spend_policy.clock = gate::Clock::None;
    }
    // No auto-seed: first run shows the onboarding choice (Home empty state),
    // where the user picks the wallet model (self-custodied vs + Platform Key).
    #[allow(unused_mut)] // `policies` is only mutated by the cfg(not keyos) dev autoseed
    let mut policies = load_policies(&data_dir);
    // Dev-only (sim): PRIME_DEV_AUTOSEED=selfcustody|platform seeds a wallet and
    // drops an in-policy demo PSBT on the bridge, so the HSM poller can be observed
    // signing it unattended. Never compiled for device.
    #[cfg(not(keyos))]
    if policies.is_empty() {
        if let Ok(model) = std::env::var("PRIME_DEV_AUTOSEED") {
            let wpk = model == "platform";
            if let Ok(reg) = seed_demo_wallet(&seed, &secp, fp, spend_policy.recovery_blocks, wpk) {
                let _ = save_policy(&data_dir, &reg);
                if let Ok(demo) = build_demo_psbt(&seed, &secp, fp, &reg, 50_000) {
                    write_bridge_file(&data_dir, UNSIGNED_PSBT_FILE, &demo.serialize());
                }
                // A second demo (different amount -> different txid) saved as base64,
                // so `prime-signer sign --psbt $(cat demo-unsigned.b64.txt)` can drive
                // the live shim->poller loop without being deduped.
                if let Ok(demo2) = build_demo_psbt(&seed, &secp, fp, &reg, 60_000) {
                    write_bridge_file(&data_dir, "demo-unsigned.b64.txt", psbt_base64(&demo2).as_bytes());
                }
                let _ = policies.add(reg);
            }
        }
    }
    let (mut history, hist_unsafe) = load_history(&data_dir);
    history.dedup_by_txid(); // clean any stale duplicate rows from older builds
    // NOTE: we deliberately do NOT begin_session() on every boot. The session
    // budget is now persisted (session_start lives in history.json), so a host
    // that controls USB power can't reset the budget by power-cycling the device.
    // The user resets it explicitly via "Reset budget" on the Policy screen.
    // First run (no persisted session_start) starts at 0, which is correct.

    let (wallet_policies, wp_unsafe) = load_wallet_policies(&data_dir);

    // Fail closed: a corrupt ledger or policy at boot pauses auto-signing until the
    // user resolves it. The velocity budget can never be silently reset to zero.
    let (safe_mode, safe_mode_reason) = if hist_unsafe {
        (true, "Couldn't read the spend ledger; auto-signing is paused. Reset the budget on the Policy screen to resume.".to_string())
    } else if policy_unsafe || wp_unsafe {
        (true, "Couldn't read your saved limits; auto-signing is paused. Review and re-save your spending policy to resume.".to_string())
    } else {
        (false, String::new())
    };

    let state = Arc::new(Mutex::new(AppState {
        secp,
        seed,
        fp,
        data_dir,
        policies,
        xpub_network: DEFAULT_NETWORK,
        pending: None,
        pending_import: None,
        last_signed: None,
        spend_policy,
        history,
        last_hsm_txid: None,
        usb_register_pending: false,
        usb_sign_pending: false,
        needs_refresh: false,
        pending_queue: std::collections::VecDeque::new(),
        signed_cache: std::collections::HashMap::new(),
        signed_cache_order: std::collections::VecDeque::new(),
        signing_in_flight: std::collections::HashSet::new(),
        safe_mode,
        safe_mode_reason,
        wallet_policies,
    }));

    refresh_home(&ui, &state);
    set_status(&ui, tr::lookup_id(TrId::StatusReady));
    // Process anything already waiting on the bridge at startup.
    hsm_poll(&ui, &state);
    // Background HSM poller: drives unattended signing on the hosted sim, where the
    // Slint timer does not tick while idle. On device the transport (HWI/QuantumLink)
    // delivers PSBTs instead, so this poller is host-only.
    #[cfg(not(keyos))]
    {
        let state_poll = state.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = hsm_poll_core(&state_poll);
        });
    }
    // On device, the same requests arrive over the host transport instead of the
    // file bridge. STUB: the QuantumLink v2 (os/ql) endpoint is not yet wired, so
    // this currently no-ops. See src/transport.rs and MIGRATION-QLV2.md.
    #[cfg(keyos)]
    {
        let state_transport = state.clone();
        std::thread::Builder::new()
            .name("nunchuk-transport".into())
            .spawn(move || {
                if let Err(e) = transport::serve(state_transport) {
                    log::error!("host transport exited: {e}");
                }
            })
            .ok();
    }

    // -- select policy -> populate detail -----------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_select_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let found = {
                let st = state.lock().unwrap();
                if let Some(reg) = st.policies.find_by_checksum(id.as_str()) {
                    populate_detail(&ui, reg);
                    true
                } else {
                    false
                }
            };
            // detail-id is now set; refresh so the per-wallet limits/budget/freeze/
            // allowlist controls reflect THIS wallet's policy.
            if found {
                refresh_home(&ui, &state);
            }
        });
    }

    // -- export xpub --------------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_xpub(move || {
            let Some(ui) = weak.upgrade() else { return };
            set_xpub_export(&ui, &state, DEFAULT_NETWORK);
        });
    }

    // -- switch exported key network ---------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_xpub_network(move |network| {
            let Some(ui) = weak.upgrade() else { return };
            set_xpub_export(&ui, &state, network_from_label(network.as_str()).unwrap_or(DEFAULT_NETWORK));
        });
    }

    // -- export key to a chosen location via the file picker ----------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_key_file(move || {
            let Some(ui) = weak.upgrade() else { return };
            let key = {
                let st = state.lock().unwrap();
                key_with_origin(&st.seed, &st.secp, st.fp, st.xpub_network).unwrap_or_else(|_| String::new())
            };
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            if key.is_empty() {
                cb.set_export_error(tr::lookup_id(TrId::ErrorXpubDeriveFailed).into());
                return;
            }
            match export_via_picker(EXPORT_KEY_FILE, key.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportKeySavedTitle).into());
                    cb.set_export_done_detail(
                        format!("{}\n{}", format_saved_to(&dest), tr::lookup_id(TrId::ExportKeySavedDetail))
                            .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    let msg = format!("{e}");
                    // A user cancel is not an error to surface.
                    cb.set_export_error(if msg.contains("cancelled") { "".into() } else { msg.into() });
                }
            }
        });
    }

    // -- sign psbt: build a demo owner-path PSBT, match, show review --------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_sign_psbt(move |_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Gate navigation: the home button only opens the review screen when
            // this is set, so a cancelled picker stays on home (no stale screen).
            {
                let cb = ui.global::<Callbacks>();
                cb.set_review_ready(false);
                cb.set_psbt_loading(false);
                review_message(&ui, "");
                let mut st = state.lock().unwrap();
                st.pending = None;
                st.last_signed = None;
            }

            // Load the PSBT. The sim bridge (DATA_SUBDIR/unsigned.psbt) wins if
            // present; otherwise open the file picker so the user can choose any
            // .psbt from USB / Airlock / internal. Don't hold the lock across the
            // modal picker.
            let bridge = { sim_bridge_file(&state.lock().unwrap().data_dir, UNSIGNED_PSBT_FILE) };
            let psbt = if let Some(bridge) = bridge {
                match read_psbt_file(&bridge) {
                    Ok(p) => p,
                    Err(e) => {
                        let err = format!("{e}");
                        review_message(&ui, &trfmt(TrId::ErrorReadNamedFile, &[UNSIGNED_PSBT_FILE, &err]));
                        ui.global::<Callbacks>().set_review_ready(true);
                        return;
                    }
                }
            } else {
                // No host-bridge PSBT: build a built-in demo PSBT from the
                // registered wallet so the simulator exercises the gate. The real
                // Signet test drops the nunchuk-cli PSBT at DATA_SUBDIR/unsigned.psbt.
                let built = {
                    let st = state.lock().unwrap();
                    match st.policies.all().iter().find(|p| !p.archived).cloned() {
                        Some(reg) => build_demo_psbt(&st.seed, &st.secp, st.fp, &reg, 50_000),
                        None => Err(anyhow::anyhow!("no wallet registered")),
                    }
                };
                match built {
                    Ok(p) => p,
                    Err(e) => {
                        review_message(&ui, &trfmt(TrId::ErrorReadPsbt, &[&format!("{e}")]));
                        ui.global::<Callbacks>().set_review_ready(true);
                        return;
                    }
                }
            };

            // The PSBT itself identifies its wallet (scriptPubKeys), so we match
            // across every registered policy — no need to pre-select one.
            // Matching derives up to GAP addresses per policy path — seconds of
            // EC work. Show a spinner and run it on a worker thread so the UI stays
            // responsive, then post the result back to the event loop.
            let (policies, fp) = {
                let st = state.lock().unwrap();
                (st.policies.all().to_vec(), st.fp)
            };
            {
                let cb = ui.global::<Callbacks>();
                cb.set_psbt_loading(true);
                cb.set_review_ready(true); // navigate to the review (loading) screen
            }
            let weak2 = ui.as_weak();
            let state2 = state.clone();
            spawn_local(async move {
                // Heavy work off the UI thread; returns the psbt back with the match.
                let res = spawn_worker(async move {
                    let m = match_owned(&psbt, &policies, fp, GAP);
                    (psbt, m)
                })
                .await;
                let Some(ui) = weak2.upgrade() else { return };
                let (psbt, matched) = res;
                match matched {
                    Ok(Some((reg, m))) => {
                        let outflow = lpsbt::outflow_sats(&psbt, &reg, GAP).unwrap_or(0);
                        let (decision, can_sign) = {
                            let st = state2.lock().unwrap();
                            (
                                gate::decide(&st.spend_policy, &st.history, outflow, now_secs()),
                                m.passport_can_sign && m.matched,
                            )
                        };
                        populate_review(&ui, &reg, &psbt, &m, outflow, &decision);
                        // Recovery-path spends ALWAYS require a physical tap, regardless
                        // of amount (the agent isn't involved; this is an emergency sweep).
                        let is_recovery = matches!(m.active_path, Some(SpendPathKind::Recovery));
                        // Autonomous path: within policy AND signable AND not recovery.
                        if can_sign && !decision.requires_approval() && !is_recovery {
                            auto_sign_pending(
                                &ui,
                                &state2,
                                Pending { psbt, policy: reg, matched: m, outflow },
                            );
                        } else {
                            state2.lock().unwrap().pending =
                                Some(Pending { psbt, policy: reg, matched: m, outflow });
                            set_status(&ui, tr::lookup_id(TrId::StatusLoadedPsbt));
                        }
                    }
                    Ok(None) => review_message(&ui, tr::lookup_id(TrId::ReviewNoMatch)),
                    Err(e) => review_message(&ui, &trfmt(TrId::ErrorMatchFailed, &[&format!("{e}")])),
                }
                ui.global::<Callbacks>().set_psbt_loading(false);
            })
            .detach();
        });
    }

    // -- verify address: scan a QR (or read the sim bridge file) and check
    //    whether the address is derived from the registered policy -----------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_verify_address(move |_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Gate navigation: the Verify screen only opens when a code was
            // actually scanned, so cancelling the scan stays put (no stale result).
            clear_verify(&ui);
            // Snapshot every policy's descriptor + name, then DROP the lock
            // before any modal scan.
            let (policies, bridge) = {
                let st = state.lock().unwrap();
                let ps: Vec<(String, String, Network)> = st
                    .policies
                    .all()
                    .iter()
                    .map(|r| {
                        (
                            r.descriptor.clone(),
                            r.name.clone(),
                            network_from_policy(r).unwrap_or(DEFAULT_NETWORK),
                        )
                    })
                    .collect();
                (ps, sim_bridge_file(&st.data_dir, VERIFY_ADDRESS_FILE))
            };

            // Sim bridge: a verify-address.txt in the data folder wins; else scan a QR.
            let scanned = if let Some(bridge) = bridge {
                read_text_path_limited(&bridge, MAX_DESCRIPTOR_BYTES, "address")
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                scan_address_qr()
            };
            let Some(raw) = scanned.filter(|s| !s.is_empty()) else {
                set_status(&ui, tr::lookup_id(TrId::StatusAddressScanCancelled));
                return;
            };
            let addr = normalize_address(&raw);

            // Check the address against every registered wallet; report which.
            let hit = policies.iter().find_map(|(desc, name, network)| {
                verify_address_in_policy(desc, &addr, *network).map(|(k, i)| (name, k, i))
            });

            let cb = ui.global::<Callbacks>();
            cb.set_verify_ready(true);
            cb.set_verify_addr(addr.clone().into());
            match hit {
                Some((name, kind, index)) => {
                    cb.set_verify_matched(true);
                    cb.set_verify_title(tr::lookup_id(TrId::VerifySuccessTitle).into());
                    let kind = match kind.as_str() {
                        "change" => tr::lookup_id(TrId::VerifyChangeKind).to_string(),
                        _ => tr::lookup_id(TrId::VerifyReceiveKind).to_string(),
                    };
                    cb.set_verify_detail(
                        trfmt(TrId::VerifySuccessDetail, &[name, &kind, &index.to_string()]).into(),
                    );
                }
                None => {
                    cb.set_verify_matched(false);
                    cb.set_verify_title(tr::lookup_id(TrId::VerifyNotRegisteredTitle).into());
                    cb.set_verify_detail(tr::lookup_id(TrId::VerifyNotRegisteredDetail).into());
                }
            }
        });
    }

    // -- reject/defer: drop the on-screen pending PSBT so the queue advances --
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_reject_pending_sign(move || {
            let Some(ui) = weak.upgrade() else { return };
            {
                let mut st = state.lock().unwrap();
                // Record the decline in the audit trail before dropping it: "the agent
                // tried this and I said no." Display-only (excluded from the budget).
                if let Some(p) = st.pending.take() {
                    let txid = p.psbt.unsigned_tx.compute_txid().to_string();
                    let dest = primary_dest(&p.psbt, &p.policy);
                    let rec = history::SpendRecord {
                        unix_time: now_secs(),
                        amount_sats: p.outflow,
                        dest,
                        kind: history::SignKind::Declined,
                        txid,
                        wallet: p.policy.name.clone(),
                        wallet_id: p.policy.descriptor_checksum.clone(),
                    };
                    st.history.record(rec);
                    let _ = save_history(&st.data_dir, &st.history);
                }
                st.needs_refresh = true;
            }
            refresh_home(&ui, &state);
        });
    }

    // -- approve: sign + finalize the pending PSBT --------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_approve(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Prepare on the UI thread (take pending, security re-check, derive the
            // key), then sign on a WORKER so the ~35s on-device BDK sign doesn't
            // freeze the screen. The spinner keeps animating while the worker runs.
            let prepared = {
                let mut st = state.lock().unwrap();
                let Some(pending) = st.pending.take() else {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, tr::lookup_id(TrId::StatusNothingToSign));
                    return;
                };
                // Security gate (defence-in-depth): refuse unless the PSBT matched the
                // policy and Passport owns a key on the active path.
                if let signing::SignDecision::Refuse(reason) =
                    signing::decide(&pending.matched, &pending.policy)
                {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, &trfmt(TrId::ErrorRefused, &[&reason]));
                    return;
                }
                let network = network_from_policy(&pending.policy).unwrap_or(DEFAULT_NETWORK);
                let master = match master_for_network(&st.seed, network) {
                    Ok(master) => master,
                    Err(e) => {
                        ui.global::<Callbacks>().set_signing(false);
                        set_status(&ui, &trfmt(TrId::ErrorSigningRefused, &[&format!("{e}")]));
                        return;
                    }
                };
                let txid = pending.psbt.unsigned_tx.compute_txid().to_string();
                let dest = primary_dest(&pending.psbt, &pending.policy);
                let wallet = pending.policy.name.clone();
                let wallet_id = pending.policy.descriptor_checksum.clone();
                // Mark in-flight so a host re-sending this PSBT mid-sign doesn't queue
                // a duplicate approval (the signature isn't cached until we finish).
                st.signing_in_flight.insert(txid.clone());
                (pending.psbt, master, pending.outflow, txid, dest, wallet, wallet_id)
            };
            let (psbt, master, outflow, txid, dest, wallet, wallet_id) = prepared;
            let weak2 = ui.as_weak();
            let state2 = state.clone();
            spawn_local(async move {
                // Sign only — Nunchuk (the coordinator) combines + finalizes. Heavy
                // work off the UI thread so the spinner animates during the ~35s.
                let signed: Result<Vec<u8>, String> = spawn_worker(async move {
                    // Reuse the process-wide secp context (building the full
                    // sign+verify tables costs ~tens of ms; do it once, not per sign).
                    signing::sign(psbt, &master, shared_secp()).map(|p| p.serialize()).map_err(|e| format!("{e}"))
                })
                .await;
                let Some(ui) = weak2.upgrade() else {
                    state2.lock().unwrap().signing_in_flight.remove(&txid);
                    return;
                };
                let cb = ui.global::<Callbacks>();
                cb.set_signing(false);
                match signed {
                    Ok(bytes) => {
                        {
                            let mut st = state2.lock().unwrap();
                            st.signing_in_flight.remove(&txid);
                            st.last_signed = Some(bytes.clone());
                            // Cache by txid so the agent re-sending this sign over USB
                            // gets the approved signature back (and it is not re-signed).
                            st.cache_signed(txid.clone(), bytes.clone());
                            st.history.record(history::SpendRecord {
                                unix_time: now_secs(),
                                amount_sats: outflow,
                                dest,
                                kind: history::SignKind::Approved,
                                txid,
                                wallet,
                                wallet_id,
                            });
                            let _ = save_history(&st.data_dir, &st.history);
                            st.needs_refresh = true;
                        }
                        cb.set_review_signed(true);
                        cb.set_review_saved(false);
                        refresh_home(&ui, &state2);
                        set_status(&ui, tr::lookup_id(TrId::StatusPsbtSigned));
                    }
                    Err(e) => {
                        state2.lock().unwrap().signing_in_flight.remove(&txid);
                        set_status(&ui, &trfmt(TrId::ErrorSigningRefused, &[&e]));
                    }
                }
            })
            .detach(); // without this the handle drops and the sign task is cancelled
        });
    }

    // -- import policy: pick a descriptor file via the file-browser overlay -
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_policy(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Host-bridge for the hosted sim test: if Nunchuk (same Mac) dropped a
            // descriptor in the app-data folder, use it. Otherwise open the
            // device file picker (the real-Prime path). Don't hold the lock
            // across the modal picker.
            let bridge = {
                let st = state.lock().unwrap();
                sim_bridge_file(&st.data_dir, IMPORT_DESCRIPTOR_FILE)
            };
            {
                let cb = ui.global::<Callbacks>();
                cb.set_import_error("".into());
                cb.set_import_committed(false);
            }
            let text = if let Some(bridge) = bridge {
                match read_text_path_limited(&bridge, MAX_DESCRIPTOR_BYTES, "descriptor") {
                    Ok(t) => t,
                    Err(e) => {
                        ui.global::<Callbacks>()
                            .set_import_error(trfmt(TrId::ErrorReadFile, &[&format!("{e}")]).into());
                        return;
                    }
                }
            } else {
                match import_via_picker() {
                    Ok(t) => t,
                    Err(e) => {
                        // "cancelled" is a normal user action, not an error to show.
                        let msg = format!("{e}");
                        if !msg.contains("cancelled") {
                            ui.global::<Callbacks>()
                                .set_import_error(trfmt(TrId::ErrorReadFile, &[&msg]).into());
                        }
                        return;
                    }
                }
            };
            // Parse + classify the descriptor, but DON'T commit yet — stage it
            // for the guided review screen. Reject a duplicate up front.
            let parsed = {
                let mut st = state.lock().unwrap();
                match register_descriptor(&text, st.fp, &st.seed, &st.secp) {
                    Ok(reg) => {
                        if st.policies.find_by_checksum(&reg.descriptor_checksum).is_some() {
                            Err(trfmt(TrId::ImportErrorDuplicate, &[&reg.descriptor_checksum]))
                        } else {
                            st.pending_import = Some(reg.clone());
                            Ok(reg)
                        }
                    }
                    Err(e) => Err(format!("{e}")),
                }
            };
            let cb = ui.global::<Callbacks>();
            match parsed {
                Ok(reg) => {
                    // Fill the detail-* fields so the review screen can explain it.
                    populate_detail(&ui, &reg);
                    // Pre-fill an editable default name for the review screen.
                    cb.set_import_name(tr::lookup_id(TrId::ImportDefaultWalletName).into());
                    cb.set_import_error("".into());
                    cb.set_import_parsed(true);
                }
                Err(e) => {
                    cb.set_import_parsed(false);
                    cb.set_import_error(trfmt(TrId::ImportErrorReadDescriptor, &[&e]).into());
                }
            }
        });
    }

    // -- confirm import: commit the staged policy ---------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_confirm_import(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Apply the user-chosen name (fall back to the default if blank).
            let chosen = ui.global::<Callbacks>().get_import_name().trim().to_string();
            let result = {
                let mut st = state.lock().unwrap();
                match st.pending_import.take() {
                    Some(mut reg) => {
                        if !chosen.is_empty() {
                            reg.name = chosen;
                        }
                        match save_policy(&st.data_dir, &reg) {
                            Ok(()) => {
                                st.policies.add(reg.clone()).map(|_| reg).map_err(|e| anyhow::anyhow!("{e}"))
                            }
                            Err(e) => {
                                st.pending_import = Some(reg);
                                Err(e)
                            }
                        }
                    }
                    None => Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorNothingToImport))),
                }
            };
            let cb = ui.global::<Callbacks>();
            cb.set_import_committed(false);
            match result {
                Ok(reg) => {
                    populate_detail(&ui, &reg);
                    cb.set_import_parsed(false);
                    cb.set_import_error("".into());
                    cb.set_import_committed(true);
                    // The guided flow ends here: the real wallet is now registered,
                    // so leave the wizard (and any "add wallet" model-choice state).
                    cb.set_platform_setup_step(0);
                    cb.set_adding_wallet(false);
                    refresh_home(&ui, &state);
                    set_status(&ui, tr::lookup_id(TrId::StatusPolicyAdded));
                }
                Err(e) => {
                    cb.set_import_error(format!("{e}").into());
                    set_status(&ui, &format!("{e}"));
                }
            }
        });
    }

    // -- cancel import: discard the staged policy ---------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_cancel_import(move || {
            let Some(ui) = weak.upgrade() else { return };
            state.lock().unwrap().pending_import = None;
            let cb = ui.global::<Callbacks>();
            cb.set_import_parsed(false);
            cb.set_import_committed(false);
        });
    }

    // -- archive / restore policy (reversible) ------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_archive_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let result = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                if let Some(updated) = st.policies.set_archived(id.as_str(), true) {
                    save_policy(&dir, &updated)
                } else {
                    Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound)))
                }
            };
            match result {
                Ok(()) => {
                    refresh_home(&ui, &state);
                    set_status(&ui, &trfmt(TrId::StatusArchivedPolicy, &[id.as_str()]));
                }
                Err(e) => set_status(&ui, &format!("{e}")),
            }
        });
    }
    // -- rename policy ------------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_rename_policy(move |id, name| {
            let Some(ui) = weak.upgrade() else { return };
            let name = name.trim().to_string();
            if !name.is_empty() {
                let result = {
                    let mut st = state.lock().unwrap();
                    let dir = st.data_dir.clone();
                    match st.policies.set_name(id.as_str(), &name) {
                        Some(updated) => save_policy(&dir, &updated).map(|_| updated),
                        None => Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound))),
                    }
                };
                // Refresh the open detail view so the new name shows immediately.
                match result {
                    Ok(updated) => populate_detail(&ui, &updated),
                    Err(e) => set_status(&ui, &format!("{e}")),
                }
            }
            refresh_home(&ui, &state);
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_restore_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let result = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                if let Some(updated) = st.policies.set_archived(id.as_str(), false) {
                    save_policy(&dir, &updated)
                } else {
                    Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound)))
                }
            };
            match result {
                Ok(()) => {
                    refresh_home(&ui, &state);
                    set_status(&ui, &trfmt(TrId::StatusRestoredPolicy, &[id.as_str()]));
                }
                Err(e) => set_status(&ui, &format!("{e}")),
            }
        });
    }

    // -- delete policy (permanent, from the archive): store + disk ----------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_delete_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let removed = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                let ok = st.policies.remove(id.as_str());
                if ok {
                    if let Err(e) = delete_policy_file(&dir, id.as_str()) {
                        log::warn!("failed to delete policy backing file #{id}: {e}");
                    }
                    // Drop the wallet's per-wallet policy override too, so a future
                    // wallet that happens to reuse the checksum starts clean.
                    if st.wallet_policies.remove(id.as_str()).is_some() {
                        let _ = save_wallet_policies(&dir, &st.wallet_policies);
                    }
                    true
                } else {
                    false
                }
            };
            refresh_home(&ui, &state);
            if removed {
                set_status(&ui, &trfmt(TrId::StatusDeletedPolicy, &[id.as_str()]));
            } else {
                set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
            }
        });
    }

    // -- export descriptor (advanced): save the miniscript to a file --------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_descriptor(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Callbacks>().set_export_ok(false);
            // Build descriptor + bridge path, then drop the lock before the modal.
            let (descriptor, bridge, filename) = {
                let st = state.lock().unwrap();
                match st.policies.find_by_checksum(id.as_str()) {
                    Some(reg) => {
                        let filename = format!("nunchuk-descriptor-{id}.txt");
                        (reg.descriptor.clone(), st.data_dir.join(&filename), filename)
                    }
                    None => {
                        set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
                        return;
                    }
                }
            };
            // Always write to the app-data bridge (hosted sim / dev).
            write_bridge_path(&bridge, descriptor.as_bytes());
            // On device, save to a chosen location via the picker.
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            match export_via_picker(&filename, descriptor.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportDescriptorSavedTitle).into());
                    cb.set_export_done_detail(
                        format!(
                            "{}\n{}",
                            format_saved_to(&dest),
                            tr::lookup_id(TrId::ExportDescriptorSavedDetail)
                        )
                        .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    let msg = format!("{e}");
                    cb.set_export_error(if msg.contains("cancelled") { "".into() } else { msg.into() });
                }
            }
        });
    }

    // -- activity: load recent signing history --------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_show_activity(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (rows, multi_wallet): (Vec<ActivityRow>, bool) = {
                let st = state.lock().unwrap();
                let rows = st
                    .history
                    .recent(40)
                    .iter()
                    .map(|r| ActivityRow {
                        amount: format!("{} sats", commas(r.amount_sats)).into(),
                        dest: r.dest.clone().into(),
                        txid: format!("tx {}", &r.txid[..r.txid.len().min(12)]).into(),
                        kind: match r.kind {
                            history::SignKind::Auto => "Auto-signed · Passport",
                            history::SignKind::Approved => "You approved",
                            history::SignKind::External => "Agent + Platform Key",
                            history::SignKind::Declined => "Declined",
                        }
                        .into(),
                        wallet: r.wallet.clone().into(),
                    })
                    .collect();
                (rows, st.policies.all().len() > 1)
            };
            let cb = ui.global::<Callbacks>();
            cb.set_activity_multi_wallet(multi_wallet);
            cb.set_activity_rows(ModelRc::new(VecModel::from(rows)));
        });
    }

    // -- onboarding: enter the guided setup for the chosen model -----------
    // Both models follow the same Nunchuk-native flow (export Prime's key -> Nunchuk
    // builds the wallet -> Prime confirms it over USB). Prime is the policy co-signer,
    // not the wallet creator, so nothing is minted on-device. See docs/ARCHITECTURE.md.
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_setup_self_custody(move || {
            let Some(ui) = weak.upgrade() else { return };
            begin_wallet_setup(&ui, &state, false);
        });
    }
    // Recovery timelock: clamp to a sane block range and publish a human-readable
    // summary (blocks + approx time) so the picker shows a real scale, not a bare
    // number. Routed through a callback so the stepper / presets share one path.
    {
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_setup_recovery_blocks(move |n| {
            let Some(ui) = weak.upgrade() else { return };
            let blocks = (n.max(1) as u32).min(RECOVERY_BLOCKS_MAX);
            let cb = ui.global::<Callbacks>();
            cb.set_setup_recovery_blocks(blocks as i32);
            cb.set_setup_recovery_summary(recovery_summary(blocks).into());
        });
    }
    // Enter the guided 2-of-3 flow (Nunchuk Platform Key + Prime).
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_begin_platform_setup(move || {
            let Some(ui) = weak.upgrade() else { return };
            begin_wallet_setup(&ui, &state, true);
        });
    }

    // -- edit spending policy: per-tx auto-sign limit (off-chain; editable live) -
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_per_tx_limit(move |n| {
            let Some(ui) = weak.upgrade() else { return };
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            {
                let mut st = state.lock().unwrap();
                apply_policy_edit(&mut st, &active_id, |p| p.per_tx_limit_sats = n.max(0) as u64);
            }
            refresh_home(&ui, &state);
            set_status(&ui, &format!("Per-transaction limit set to {} sats", commas(n.max(0) as u64)));
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_daily_cap(move |n| {
            let Some(ui) = weak.upgrade() else { return };
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            {
                let mut st = state.lock().unwrap();
                apply_policy_edit(&mut st, &active_id, |p| {
                    p.daily_cap_sats = if n <= 0 { None } else { Some(n as u64) };
                });
            }
            refresh_home(&ui, &state);
            let msg = if n <= 0 { "Daily cap turned off".to_string() } else { format!("Daily cap set to {} sats", commas(n as u64)) };
            set_status(&ui, &msg);
        });
    }
    // -- edit spending policy from the numeric keypad (comma-tolerant string) ----
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_custom_limit(move |target, s| {
            let Some(ui) = weak.upgrade() else { return };
            // The keypad emits a plain string; tolerate grouping commas/whitespace.
            let parsed: u64 = s.trim().replace(',', "").parse().unwrap_or(0);
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            let msg = {
                let mut st = state.lock().unwrap();
                let m = match target.as_str() {
                    "pertx" => {
                        let v = parsed.max(1).min(2_000_000_000);
                        apply_policy_edit(&mut st, &active_id, |p| p.per_tx_limit_sats = v);
                        format!("Per-transaction limit set to {} sats", commas(v))
                    }
                    "daily" => {
                        let v = parsed.min(2_000_000_000);
                        apply_policy_edit(&mut st, &active_id, |p| {
                            p.daily_cap_sats = if v == 0 { None } else { Some(v) };
                        });
                        if v == 0 { "Daily cap turned off".to_string() } else { format!("Daily cap set to {} sats", commas(v)) }
                    }
                    _ => return,
                };
                m
            };
            refresh_home(&ui, &state);
            set_status(&ui, &msg);
        });
    }
    // -- freeze auto-signing (user kill-switch) -------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_frozen(move |frozen| {
            let Some(ui) = weak.upgrade() else { return };
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            {
                let mut st = state.lock().unwrap();
                apply_policy_edit(&mut st, &active_id, |p| p.frozen = frozen);
            }
            refresh_home(&ui, &state);
            set_status(&ui, if frozen { "Auto-signing frozen. Every spend now needs your approval." } else { "Auto-signing resumed (within your limits)." });
        });
    }
    // -- reset spend budget + clear a fail-closed pause -----------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_reset_budget(move || {
            let Some(ui) = weak.upgrade() else { return };
            {
                let mut st = state.lock().unwrap();
                // Fresh session baseline, and re-persist a known-good ledger + policy
                // so a corruption pause is resolved.
                st.history.begin_session();
                st.safe_mode = false;
                st.safe_mode_reason = String::new();
                let _ = save_history(&st.data_dir, &st.history);
                let _ = save_spend_policy(&st.data_dir, &st.spend_policy);
            }
            refresh_home(&ui, &state);
            set_status(&ui, "Spend budget reset. Auto-signing resumed within your limits.");
        });
    }
    // -- destination allowlist: add (scan QR) / remove ------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_add_allowlist_address(move || {
            let Some(ui) = weak.upgrade() else { return };
            let Some(scanned) = scan_address_qr() else { return };
            let addr = normalize_address(&scanned);
            if addr.is_empty() {
                set_status(&ui, "Couldn't read an address from that QR.");
                return;
            }
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            {
                let mut st = state.lock().unwrap();
                let a = addr.clone();
                apply_policy_edit(&mut st, &active_id, move |p| {
                    if !p.allowlist.iter().any(|x| x.eq_ignore_ascii_case(&a)) {
                        p.allowlist.push(a);
                    }
                });
            }
            refresh_home(&ui, &state);
            set_status(&ui, &format!("Added {addr} to the allowlist."));
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_remove_allowlist_address(move |addr| {
            let Some(ui) = weak.upgrade() else { return };
            let active_id = ui.global::<Callbacks>().get_detail_id().to_string();
            {
                let mut st = state.lock().unwrap();
                let a = addr.to_string();
                apply_policy_edit(&mut st, &active_id, move |p| {
                    p.allowlist.retain(|x| !x.eq_ignore_ascii_case(&a));
                });
            }
            refresh_home(&ui, &state);
            set_status(&ui, "Removed from the allowlist.");
        });
    }

    // -- HSM mode: poll the host bridge + auto-sign in-policy PSBTs unattended -
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_hsm_poll(move || {
            let Some(ui) = weak.upgrade() else { return };
            hsm_poll(&ui, &state);
        });
    }

    // -- USB -> UI bridge: drain background signals on the main thread (a 1s Slint
    //    timer drives this). Refresh the home screen after a USB sign, and surface a
    //    pushed descriptor on the import-review screen for on-device approval.
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_poll_usb_events(move || {
            let Some(ui) = weak.upgrade() else { return };
            // 1) Redraw the home screen after a background-thread store change.
            let do_refresh = { std::mem::take(&mut state.lock().unwrap().needs_refresh) };
            if do_refresh {
                refresh_home(&ui, &state);
            }
            let cb = ui.global::<Callbacks>();
            let mut st = state.lock().unwrap();
            let reg_signal = std::mem::take(&mut st.usb_register_pending);
            let sign_signal = std::mem::take(&mut st.usb_sign_pending);
            // Pull the next queued over-policy PSBT onto the screen if nothing is showing.
            let popped = if st.pending.is_none() {
                st.pending = st.pending_queue.pop_front();
                st.pending.is_some()
            } else {
                false
            };
            // 2a) A pushed descriptor awaiting approval -> import-review screen.
            if reg_signal {
                if let Some(reg) = st.pending_import.clone() {
                    drop(st);
                    populate_detail(&ui, &reg);
                    cb.set_import_name(tr::lookup_id(TrId::ImportDefaultWalletName).into());
                    cb.set_import_error("".into());
                    cb.set_import_parsed(true);
                    cb.set_usb_review_pending(true);
                    return;
                }
            }
            // 2b) A newly-arrived over-policy spend -> sign-review screen. Only on arrival
            // (signal or a fresh pop), never every tick, so the user can leave the screen.
            if (sign_signal || popped) && st.pending.is_some() {
                let p = st.pending.as_ref().unwrap();
                let decision = gate::decide(&st.spend_policy, &st.history, p.outflow, now_secs());
                populate_review(&ui, &p.policy, &p.psbt, &p.matched, p.outflow, &decision);
                cb.set_review_ready(true);
                cb.set_usb_sign_pending(true);
            }
        });
    }

    ui.run().expect("UI running");
}

enum HsmOutcome {
    Signed,
    NeedsApproval,
    Recovery,
}

#[cfg(not(keyos))]
fn remove_bridge_file(dir: &Path, name: &str) {
    let _ = std::fs::remove_file(dir.join(name));
}
#[cfg(keyos)]
fn remove_bridge_file(_dir: &Path, _name: &str) {}

/// HSM tick: if a PSBT is waiting on the host bridge and it is in-policy, sign it
/// with no human present (unattended) and consume it. Over-policy + recovery are
/// left for an on-device approval. Idempotent via `last_hsm_txid`.
/// Outcome of the shared sign path (used by both the file bridge and USB-CDC).
#[allow(dead_code)]
enum SignResult {
    Signed { bytes: Vec<u8>, outflow: u64, txid: String },
    /// Over-policy or recovery: held for an on-device approval.
    Pending { reason: String, recovery: bool },
    Refused { reason: String },
}

/// THE one place a host-submitted PSBT is gated + signed. Matches the registered
/// wallet, applies the policy gate, signs in-policy (recording it), or returns
/// Pending (over-policy / recovery) / Refused. Both transports call this, so the
/// USB sign path is identical to the file-bridge one.
/// True for a 2-of-3 cloud-assisted wallet (Nunchuk Platform Key present): two or
/// more distinct external signers besides Prime. In these, Prime is the over-limit
/// approval gate, not an auto-signer.
fn is_cloud_assisted(reg: &RegisteredPolicy) -> bool {
    let mut seen = std::collections::HashSet::new();
    reg.signers
        .iter()
        .filter(|s| !s.owned_by_passport)
        .filter(|s| seen.insert(s.fingerprint.clone()))
        .count()
        >= 2
}

fn sign_within_policy(st: &mut AppState, psbt: Psbt) -> SignResult {
    let policies = st.policies.all().to_vec();
    let fp = st.fp;
    let (reg, m) = match lpsbt::match_against_all(&psbt, &policies, fp, GAP) {
        Ok(Some((reg, m))) => (reg.clone(), m),
        _ => return SignResult::Refused { reason: "does not match a registered wallet".into() },
    };
    if !m.matched || !m.passport_can_sign {
        return SignResult::Refused { reason: "Passport owns no key on this PSBT's spend path".into() };
    }
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let outflow = lpsbt::outflow_sats(&psbt, &reg, GAP).unwrap_or(0);
    let recovery = matches!(m.active_path, Some(SpendPathKind::Recovery));
    let network = network_from_policy(&reg).unwrap_or(DEFAULT_NETWORK);
    // Per-wallet policy + budget: this wallet's override (or the global default) and
    // ONLY this wallet's spend history. A runaway agent on one wallet can't consume
    // another's budget or slip past another's allowlist.
    let checksum = reg.descriptor_checksum.clone();
    let wpolicy = st.policy_for(&checksum);
    let whistory = st.history.for_wallet(&checksum);
    // Destination allowlist: when set, every non-change output must be on the list
    // to auto-sign; anything else needs a tap. Fail closed if we can't resolve the
    // destinations. Bounds WHERE the agent can send, not just how much.
    let dests_allowed = if wpolicy.allowlist.is_empty() {
        true
    } else {
        match lpsbt::outgoing_addresses(&psbt, &reg, GAP, network) {
            Ok(dests) => dests.iter().all(|d| {
                !d.is_empty() && wpolicy.allowlist.iter().any(|a| a.eq_ignore_ascii_case(d))
            }),
            Err(_) => false,
        }
    };
    // Decide whether this needs an on-device tap. Recovery always does. In a 2-of-3
    // (cloud-assisted), Prime NEVER auto-signs: the agent handles routine spends with
    // the Platform Key, so anything that reaches Prime is your over-limit approval.
    // In a 2-of-2 (sovereign), Prime auto-signs within policy and the gate decides.
    let approval_reason: Option<String> = if recovery {
        Some("recovery spend: approve on device".to_string())
    } else if st.safe_mode {
        // Fail-closed: a corrupt ledger/policy or a failed debit-write pauses all
        // auto-signing until the user resolves it on the Policy screen.
        Some("auto-signing is paused (see the alert on Home); approve on device".to_string())
    } else if wpolicy.frozen {
        // The user's deliberate kill-switch: everything needs a tap.
        Some("auto-signing is frozen; approve on device".to_string())
    } else if !dests_allowed {
        Some("a destination isn't on your allowlist; approve on device".to_string())
    } else {
        let gate_reason = match gate::decide(&wpolicy, &whistory, outflow, now_secs()) {
            gate::Decision::RequireApproval { reason, .. } => Some(reason),
            _ => None,
        };
        if is_cloud_assisted(&reg) {
            Some(gate_reason.unwrap_or_else(|| "Routed to Passport for your approval".to_string()))
        } else {
            gate_reason
        }
    };
    if let Some(reason) = approval_reason {
        // Don't re-queue a PSBT we're already handling: on screen, in the queue,
        // currently being signed off-thread, or already signed + cached. Without the
        // last two, a host re-sending mid-/post-sign would surface a phantom approval.
        let queued = st.signing_in_flight.contains(&txid)
            || st.signed_cache.contains_key(&txid)
            || st.pending.as_ref().is_some_and(|p| p.psbt.unsigned_tx.compute_txid().to_string() == txid)
            || st.pending_queue.iter().any(|p| p.psbt.unsigned_tx.compute_txid().to_string() == txid);
        if !queued {
            st.pending_queue.push_back(Pending { psbt, policy: reg, matched: m, outflow });
            st.usb_sign_pending = true;
        }
        return SignResult::Pending { reason, recovery };
    }
    let master = match master_for_network(&st.seed, network) {
        Ok(m) => m,
        Err(e) => return SignResult::Refused { reason: format!("{e}") },
    };
    let dest = primary_dest(&psbt, &reg);
    match signing::sign(psbt, &master, &st.secp) {
        Ok(signed) => {
            let bytes = signed.serialize();
            st.history.record(history::SpendRecord {
                unix_time: now_secs(),
                amount_sats: outflow,
                dest,
                kind: history::SignKind::Auto,
                txid: txid.clone(),
                wallet: reg.name.clone(),
                wallet_id: reg.descriptor_checksum.clone(),
            });
            // Persist the debit BEFORE releasing the signature. If it can't be
            // persisted, roll the debit back, enter safe mode, and WITHHOLD the
            // signature: a signature must never leave the device without a durable
            // debit, or a power-cut could reset the budget (the S1/S3 attack).
            if let Err(e) = save_history(&st.data_dir, &st.history) {
                st.history.records.pop();
                st.safe_mode = true;
                st.safe_mode_reason =
                    "Couldn't record the last spend to the ledger; auto-signing is paused.".to_string();
                return SignResult::Refused { reason: format!("ledger write failed, signature withheld: {e}") };
            }
            st.last_signed = Some(bytes.clone());
            SignResult::Signed { bytes, outflow, txid }
        }
        Err(e) => SignResult::Refused { reason: format!("{e}") },
    }
}

fn bytes_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Derive a wallet address from a registered wallet descriptor (receive or change).
#[allow(dead_code)]
fn address_at(reg: &RegisteredPolicy, index: u32, change: bool) -> anyhow::Result<String> {
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed.descriptor.into_single_descriptors().map_err(|e| anyhow::anyhow!("{e}"))?;
    let si = if change { 1 } else { 0 };
    let single = singles.get(si).ok_or_else(|| anyhow::anyhow!("descriptor has no path {si}"))?;
    let def = single.at_derivation_index(index).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(def.address(network).map_err(|e| anyhow::anyhow!("{e}"))?.to_string())
}

/// Dispatch one device-protocol request against the live key + gate. The transport
/// (USB-CDC on device, or a test) parses JSON -> Request, calls this, serializes the
/// Response. Same handler regardless of transport.
#[allow(dead_code)] // USB-CDC transport entry point (cfg keyos) + tests
fn process_request(state: &Arc<Mutex<AppState>>, req: device_protocol::Request) -> device_protocol::Response {
    use device_protocol::{Request, Response};
    let mut st = state.lock().unwrap();
    match req {
        Request::Fingerprint => Response::Fingerprint { fingerprint: st.fp.to_string() },
        Request::Xpub { path } => {
            if !is_allowed_xpub_path(&path) {
                return Response::error(
                    "xpub path not allowed: only standard wallet account paths (BIP44/48/49/84/86) are served",
                );
            }
            match xpub_with_origin_at(&st.seed, &st.secp, st.fp, DEFAULT_NETWORK, path.trim()) {
                Ok(key) => Response::Key { key },
                Err(e) => Response::error(format!("{e}")),
            }
        }
        Request::Sign { psbt } => match parse_psbt_bytes(psbt.as_bytes()) {
            Ok(p) => {
                let txid = p.unsigned_tx.compute_txid().to_string();
                // Already signed (auto, or approved on-device): return it idempotently,
                // no re-sign and no duplicate activity row.
                if let Some(bytes) = st.signed_cache.get(&txid) {
                    Response::Signed { psbt: bytes_base64(bytes) }
                } else {
                    match sign_within_policy(&mut st, p) {
                        SignResult::Signed { bytes, txid, .. } => {
                            st.cache_signed(txid, bytes.clone());
                            st.needs_refresh = true; // activity log changed -> redraw home
                            Response::Signed { psbt: bytes_base64(&bytes) }
                        }
                        // Over-policy / recovery: sign_within_policy queued it for an
                        // on-device tap; the poll timer surfaces the approval screen.
                        SignResult::Pending { reason, .. } => Response::Pending { reason },
                        SignResult::Refused { reason } => Response::error(reason),
                    }
                }
            }
            Err(e) => Response::error(format!("{e}")),
        },
        Request::Showaddr { index, change } => {
            match st.policies.all().iter().find(|p| !p.archived).cloned() {
                Some(reg) => match address_at(&reg, index, change) {
                    Ok(address) => Response::Address { address },
                    Err(e) => Response::error(format!("{e}")),
                },
                None => Response::error("no wallet registered"),
            }
        }
        Request::Register { descriptor } => match register_descriptor(&descriptor, st.fp, &st.seed, &st.secp) {
            Ok(reg) => {
                // Already enrolled (a prior push was approved on-device) -> done.
                if st.policies.find_by_checksum(&reg.descriptor_checksum).is_some() {
                    Response::Registered {
                        name: reg.name.clone(),
                        checksum: reg.descriptor_checksum,
                    }
                } else if st
                    .pending_import
                    .as_ref()
                    .is_some_and(|p| p.descriptor_checksum == reg.descriptor_checksum)
                {
                    // Staged and waiting for the tap; have the host poll again.
                    Response::Pending { reason: "awaiting on-device approval".into() }
                } else {
                    // Stage it and raise the approval screen. Enrolment only happens on
                    // an on-device tap (the host retries register until Registered).
                    st.pending_import = Some(reg);
                    st.usb_register_pending = true;
                    Response::Pending { reason: "review + approve on Passport".into() }
                }
            }
            Err(e) => Response::error(format!("{e}")),
        },
        // Agent reports a spend it signed with the Platform Key (Prime not involved).
        // Record it once (dedupe by txid) as the "without you" lane in the ledger.
        Request::Log { amount_sats, dest, txid, wallet } => {
            let already = st.history.has_txid(&txid);
            if !already {
                st.history.record(history::SpendRecord {
                    unix_time: now_secs(),
                    amount_sats,
                    dest,
                    kind: history::SignKind::External,
                    txid: txid.clone(),
                    wallet,
                    // Host-reported external spends carry no stable wallet id and
                    // don't count toward enforcement anyway, so leave it empty.
                    wallet_id: String::new(),
                });
                let _ = save_history(&st.data_dir, &st.history);
                st.needs_refresh = true;
            }
            Response::Logged { txid }
        }
        // Report the onboarding setup the user chose (model + recovery timelock).
        // begin_wallet_setup writes both into spend_policy before the wait step, so
        // the agent reads the picker's value here instead of being told it.
        Request::Spec => Response::Spec {
            model: if st.spend_policy.with_platform_key { "2-of-3".into() } else { "2-of-2".into() },
            recovery_blocks: st.spend_policy.recovery_blocks,
        },
    }
}

fn hsm_poll_core(state: &Arc<Mutex<AppState>>) -> Option<(HsmOutcome, u64)> {
    let outcome: Option<(HsmOutcome, u64)> = {
        let mut st = state.lock().unwrap();
        // Serve a standard-path xpub request (HWI get_pubkey_at_path). Works even
        // before a wallet exists, since fetching a key needs no wallet. The path is
        // allowlisted (see is_allowed_xpub_path) so a host can't map the key tree.
        if let Some(req) = sim_bridge_file(&st.data_dir, "xpub-request.txt") {
            if let Ok(path) = read_text_path_limited(&req, 256, "xpub path") {
                if is_allowed_xpub_path(&path) {
                    if let Ok(key) =
                        xpub_with_origin_at(&st.seed, &st.secp, st.fp, DEFAULT_NETWORK, path.trim())
                    {
                        write_bridge_file(&st.data_dir, "xpub-response.txt", key.as_bytes());
                    }
                } else {
                    write_bridge_file(&st.data_dir, "xpub-response.txt", b"error: xpub path not allowed");
                }
            }
            remove_bridge_file(&st.data_dir, "xpub-request.txt");
            return None;
        }
        if !st.spend_policy.hsm_enabled || st.policies.is_empty() {
            return None;
        }
        let Some(bridge) = sim_bridge_file(&st.data_dir, UNSIGNED_PSBT_FILE) else { return None };
        let Ok(psbt) = read_psbt_file(&bridge) else { return None };
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        if st.last_hsm_txid.as_deref() == Some(txid.as_str()) {
            return None; // already handled
        }
        // Same gated sign path the USB transport uses.
        match sign_within_policy(&mut st, psbt) {
            SignResult::Signed { bytes, outflow, txid } => {
                write_bridge_file(&st.data_dir, SIGNED_PSBT_FILE, &bytes);
                write_bridge_file(&st.data_dir, "signed-psbt.b64.txt", bytes_base64(&bytes).as_bytes());
                remove_bridge_file(&st.data_dir, UNSIGNED_PSBT_FILE);
                log::info!("HSM auto-signed {outflow} sats (txid {txid})");
                st.last_hsm_txid = Some(txid);
                Some((HsmOutcome::Signed, outflow))
            }
            SignResult::Pending { recovery, .. } => {
                st.last_hsm_txid = Some(txid);
                Some((if recovery { HsmOutcome::Recovery } else { HsmOutcome::NeedsApproval }, 0))
            }
            SignResult::Refused { .. } => {
                st.last_hsm_txid = Some(txid);
                None
            }
        }
    };
    outcome
}

fn hsm_poll(ui: &AppWindow, state: &Arc<Mutex<AppState>>) {
    if let Some((outcome, amount)) = hsm_poll_core(state) {
        match outcome {
            HsmOutcome::Signed => set_status(ui, &format!("HSM auto-signed {} sats", commas(amount))),
            HsmOutcome::NeedsApproval => set_status(ui, "Spend over policy: tap Sign PSBT to approve"),
            HsmOutcome::Recovery => set_status(ui, "Recovery spend: tap Sign PSBT to approve"),
        }
        refresh_home(ui, state);
    }
}

/// Enter the guided wallet-setup wizard for the chosen model. Records Passport's
/// policy (model + the recovery-timelock recommendation) and steps straight into the
/// wait state — the agent reads Passport's key over USB and builds the wallet, so there
/// is no on-device export action. Passport is the policy co-signer, NOT the wallet
/// creator: Nunchuk builds the wallet and pushes it back for Passport to confirm.
/// Nothing is minted on-device. See ARCHITECTURE.md.
fn begin_wallet_setup(ui: &AppWindow, state: &Arc<Mutex<AppState>>, with_platform_key: bool) {
    {
        let mut st = state.lock().unwrap();
        st.spend_policy.with_platform_key = with_platform_key;
        let n = ui.global::<Callbacks>().get_setup_recovery_blocks().max(1) as u32;
        st.spend_policy.recovery_blocks = n;
        let _ = save_spend_policy(&st.data_dir, &st.spend_policy);
    }
    // Populate xpub-fingerprint so the wait state can show Passport's key for
    // verification (the agent reads the same key off the device over USB).
    set_xpub_export(ui, state, DEFAULT_NETWORK);
    let cb = ui.global::<Callbacks>();
    cb.set_import_error("".into());
    cb.set_setup_with_platform(with_platform_key);
    cb.set_platform_setup_step(1);
}

/// Apply an edit to the ACTIVE spending policy: the open wallet's override (cloned
/// from the global default if it has none yet) when a wallet detail is showing, or
/// the global default (onboarding template) otherwise. Persists the right file.
fn apply_policy_edit(st: &mut AppState, active_id: &str, f: impl FnOnce(&mut gate::SpendPolicy)) {
    if !active_id.is_empty() && st.policies.find_by_checksum(active_id).is_some() {
        let default = st.spend_policy.clone();
        {
            let p = st.wallet_policies.entry(active_id.to_string()).or_insert(default);
            f(p);
        }
        let _ = save_wallet_policies(&st.data_dir, &st.wallet_policies);
    } else {
        f(&mut st.spend_policy);
        let _ = save_spend_policy(&st.data_dir, &st.spend_policy);
    }
}

// ---------------------------------------------------------------------------
// UI population
// ---------------------------------------------------------------------------

fn policy_row(p: &RegisteredPolicy) -> PolicyRow {
    let network = network_from_policy(p).map(network_display).unwrap_or(p.network.as_str());
    PolicyRow {
        id: p.descriptor_checksum.clone().into(),
        name: p.name.clone().into(),
        checksum: format!("#{}", p.descriptor_checksum).into(),
        network: network.into(),
        summary: policy_summary(p).into(),
    }
}

fn refresh_home(ui: &AppWindow, state: &Arc<Mutex<AppState>>) {
    let st = state.lock().unwrap();
    // Active policies drive the home list; archived ones live in the archive.
    let active: Vec<PolicyRow> = st.policies.all().iter().filter(|p| !p.archived).map(policy_row).collect();
    let archived: Vec<PolicyRow> = st.policies.all().iter().filter(|p| p.archived).map(policy_row).collect();
    let cb = ui.global::<Callbacks>();
    cb.set_policy_count(active.len() as i32);
    cb.set_archived_count(archived.len() as i32);
    cb.set_policies(ModelRc::new(VecModel::from(active)));
    cb.set_archived_policies(ModelRc::new(VecModel::from(archived)));
    cb.set_recovery_blocks(st.spend_policy.recovery_blocks as i32);
    cb.set_hsm_enabled(st.spend_policy.hsm_enabled);
    // Per-wallet display: if a wallet detail is open (detail-id names an enrolled
    // wallet) show THAT wallet's policy + budget; otherwise the global default
    // (onboarding / home). The limit/budget/freeze/allowlist controls then govern
    // the wallet they're shown on.
    let active_id = cb.get_detail_id().to_string();
    let is_wallet = !active_id.is_empty() && st.policies.find_by_checksum(&active_id).is_some();
    let pol = if is_wallet { st.policy_for(&active_id) } else { st.spend_policy.clone() };
    let whist = if is_wallet { st.history.for_wallet(&active_id) } else { st.history.clone() };
    cb.set_per_tx_limit(pol.per_tx_limit_sats.min(i32::MAX as u64) as i32);
    cb.set_daily_cap(pol.daily_cap_sats.unwrap_or(0).min(i32::MAX as u64) as i32);
    // Comma-formatted strings for display (Slint int interpolation has no commas).
    cb.set_per_tx_limit_display(commas(pol.per_tx_limit_sats).into());
    cb.set_daily_cap_display(commas(pol.daily_cap_sats.unwrap_or(0)).into());
    // Keep the onboarding recovery-timelock summary populated (startup + after edits).
    let setup_blocks = (cb.get_setup_recovery_blocks().max(1) as u32).min(RECOVERY_BLOCKS_MAX);
    cb.set_setup_recovery_summary(recovery_summary(setup_blocks).into());
    // Over-policy spends waiting for an on-device tap (queue + the one on screen).
    let waiting = st.pending_queue.len() + st.pending.is_some() as usize;
    cb.set_pending_approvals(waiting.min(i32::MAX as usize) as i32);

    // Security state: fail-closed banner (global); freeze + clock + allowlist + budget
    // per the active wallet's policy.
    cb.set_safe_mode(st.safe_mode);
    cb.set_safe_mode_reason(st.safe_mode_reason.clone().into());
    cb.set_frozen(pol.frozen);
    cb.set_time_caps_active(pol.clock.time_caps_enforceable());
    let allow: Vec<SharedString> = pol.allowlist.iter().map(|a| SharedString::from(a.as_str())).collect();
    cb.set_allowlist_rows(ModelRc::new(VecModel::from(allow)));

    // Remaining auto-sign budget before the next approval (most-binding cap).
    match gate::remaining_budget(&pol, &whist, now_secs()) {
        Some((cap, spent, limit, remaining)) => {
            cb.set_budget_active(true);
            cb.set_budget_binding_label(cap.label().into());
            cb.set_budget_spent_display(commas(spent).into());
            cb.set_budget_cap_display(commas(limit).into());
            cb.set_budget_remaining_display(commas(remaining).into());
        }
        None => {
            cb.set_budget_active(false);
            cb.set_budget_remaining_display("".into());
        }
    }
}

fn populate_detail(ui: &AppWindow, reg: &RegisteredPolicy) {
    let cb = ui.global::<Callbacks>();
    cb.set_detail_id(reg.descriptor_checksum.clone().into());
    cb.set_detail_name(reg.name.clone().into());
    // Keep the rename field in sync with the selected policy's current name.
    cb.set_rename_value(reg.name.clone().into());
    cb.set_detail_checksum(format!("#{}", reg.descriptor_checksum).into());
    cb.set_detail_network(
        network_from_policy(reg).map(network_display).unwrap_or(reg.network.as_str()).into(),
    );
    cb.set_detail_descriptor(reg.descriptor.clone().into());
    cb.set_detail_archived(reg.archived);

    // Number recovery tiers when there is more than one (a decaying policy), so
    // "Recovery path 1 / 2 / 3" disambiguate the cards; a lone recovery stays
    // just "Recovery path".
    let mut paths: Vec<PathRow> = Vec::with_capacity(reg.paths.len());
    for p in &reg.paths {
        let is_recovery = matches!(p.kind, SpendPathKind::Recovery);
        // Agent-native copy: this is an agent wallet, not an inheritance wallet.
        let (kind_label, headline, detail) = if is_recovery {
            let n = p.relative_timelock_blocks.unwrap_or(0);
            (
                "Recovery".to_string(),
                format!("Passport alone, after {} blocks", commas(n)),
                format!(
                    "If the agent key is lost, Passport can recover the funds on its own once a coin is {} blocks old ({}). Always needs your approval on this device.",
                    commas(n),
                    approx_time(n)
                ),
            )
        } else if p.total_keys > 2 {
            (
                "Everyday spending".to_string(),
                format!("Agent + Platform Key ({} of {})", p.threshold, p.total_keys),
                "Routine spends: the agent and Nunchuk's Platform Key co-sign automatically, within Nunchuk's limit, so the agent keeps running even when Passport is unplugged. Bigger spends route to Passport instead, which co-signs only after you approve them on this device.".to_string(),
            )
        } else {
            (
                "Everyday spending".to_string(),
                "Agent + Passport".to_string(),
                "The agent proposes a spend; Passport co-signs. Under your limits Passport signs automatically; over them it asks for your approval on this device. Needs both keys.".to_string(),
            )
        };
        paths.push(PathRow {
            kind_label: kind_label.into(),
            is_recovery,
            headline: headline.into(),
            detail: detail.into(),
        });
    }
    cb.set_detail_paths(ModelRc::new(VecModel::from(paths)));

    // One row per distinct key. Prime's xpub appears twice in the descriptor
    // (multisig <0;1> + recovery <2;3>), so dedupe by fingerprint: it is ONE key
    // sitting on two spend paths, not two separate keys.
    let mut seen_fps = std::collections::HashSet::new();
    let mut external_seen = 0usize;
    let signers: Vec<SignerRow> = reg
        .signers
        .iter()
        .filter(|s| seen_fps.insert(s.fingerprint.clone()))
        .map(|s| {
            // Prime = this device. First external key = the agent; a second
            // external key (2-of-3) = the Nunchuk Platform Key.
            let role = if s.owned_by_passport {
                "This Passport".to_string()
            } else {
                external_seen += 1;
                if external_seen == 1 {
                    "Agent Key".to_string()
                } else if external_seen == 2 {
                    "Platform Key".to_string()
                } else {
                    // A further external key (e.g. a recovery co-signer the agent added)
                    // isn't the Platform Key; don't mislabel it.
                    "Other key".to_string()
                }
            };
            SignerRow { fingerprint: s.fingerprint.clone().into(), owned: s.owned_by_passport, detail: role.into() }
        })
        .collect();
    // Two or more external keys => a Platform Key is present (2-of-3), so Nunchuk
    // enforces the everyday limit and Prime's policy is the Prime-routed gate.
    cb.set_detail_has_platform_key(external_seen >= 2);
    cb.set_detail_signers(ModelRc::new(VecModel::from(signers)));
}

fn populate_review(ui: &AppWindow, reg: &RegisteredPolicy, psbt: &Psbt, m: &lpsbt::MatchResult, outflow: u64, decision: &gate::Decision) {
    let cb = ui.global::<Callbacks>();
    let is_recovery = matches!(m.active_path, Some(SpendPathKind::Recovery));
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    cb.set_review_matched(m.matched);
    cb.set_review_can_sign(m.passport_can_sign);
    cb.set_review_is_recovery(is_recovery);
    cb.set_review_wallet_name(reg.name.clone().into());
    // Fresh review: clear any prior success state.
    cb.set_signing(false);
    cb.set_review_signed(false);
    cb.set_review_saved(false);
    cb.set_review_signed_detail("".into());

    let path_label = match m.active_path {
        Some(SpendPathKind::Primary) => tr::lookup_id(TrId::ReviewPathPrimary).to_string(),
        Some(SpendPathKind::Recovery) => {
            trfmt(TrId::ReviewPathRecovery, &[&m.active_timelock_blocks.unwrap_or(0).to_string()])
        }
        None => tr::lookup_id(TrId::ReviewPathUnknown).to_string(),
    };
    cb.set_review_path_label(path_label.into());

    // Outputs + fee. Build one row per output, flagging the ones that pay back
    // into this wallet (change) vs the ones actually leaving (destinations), so
    // the UI can separate them visually and we can total what's truly sent.
    let out_sum: u64 = psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let in_sum: u64 =
        psbt.inputs.iter().filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat())).sum();

    let mut rows: Vec<OutputRow> = Vec::new();
    let mut leaving: u64 = 0;
    for o in &psbt.unsigned_tx.output {
        let sats = o.value.to_sat();
        let (address, is_change) = match Address::from_script(&o.script_pubkey, network) {
            Ok(addr) => {
                let a = addr.to_string();
                let change = verify_address_in_policy(&reg.descriptor, &a.to_lowercase(), network).is_some();
                (a, change)
            }
            Err(_) => (tr::lookup_id(TrId::ReviewNonStandardScript).to_string(), false),
        };
        if !is_change {
            leaving += sats;
        }
        rows.push(OutputRow {
            address: address.into(),
            amount: format!("{} sats", commas(sats)).into(),
            is_change,
        });
    }
    // Destinations first, change last (de-emphasized at the bottom).
    rows.sort_by_key(|r| r.is_change);
    cb.set_review_output_rows(ModelRc::new(VecModel::from(rows)));

    let fee = in_sum.saturating_sub(out_sum);
    cb.set_review_fee(format!("{} sats", commas(fee)).into());
    // What actually leaves the wallet's control = amount sent + miner fee.
    // Change returns to the wallet, so it is excluded.
    cb.set_review_total_out(format!("{} sats", commas(leaving + fee)).into());

    let warning =
        if is_recovery { tr::lookup_id(TrId::ReviewRecoveryWarning).to_string() } else { String::new() };
    cb.set_review_warning(warning.into());

    let status = if !m.matched {
        tr::lookup_id(TrId::ReviewNotPolicy).to_string()
    } else if !m.passport_can_sign {
        tr::lookup_id(TrId::ReviewNoKeyOnPath).to_string()
    } else {
        String::new()
    };
    cb.set_review_status(status.into());

    let _ = outflow;
    cb.set_review_gate_auto(!decision.requires_approval());
    cb.set_review_gate_reason(
        match decision {
            gate::Decision::RequireApproval { reason, .. } => reason.clone(),
            _ => String::new(),
        }
        .into(),
    );
}

/// Put the review screen into a clean refusal/empty state with a message (used
/// when there is no PSBT to load or it matches no policy).
fn review_message(ui: &AppWindow, msg: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_review_ready(false);
    cb.set_signing(false);
    cb.set_review_signed(false);
    cb.set_review_saved(false);
    cb.set_review_signed_detail("".into());
    cb.set_review_matched(false);
    cb.set_review_can_sign(false);
    cb.set_review_is_recovery(false);
    cb.set_review_wallet_name("".into());
    cb.set_review_path_label("".into());
    cb.set_review_output_rows(ModelRc::new(VecModel::from(Vec::<OutputRow>::new())));
    cb.set_review_total_out("".into());
    cb.set_review_fee("".into());
    cb.set_review_warning("".into());
    cb.set_review_status(msg.into());
}

fn clear_verify(ui: &AppWindow) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(false);
    cb.set_verify_matched(false);
    cb.set_verify_title("".into());
    cb.set_verify_addr("".into());
    cb.set_verify_detail("".into());
}

fn set_status(ui: &AppWindow, msg: &str) { ui.global::<Callbacks>().set_status(msg.to_string().into()); }

fn trfmt(id: TrId, args: &[&str]) -> String {
    let mut text = tr::lookup_id(id).to_string();
    for (idx, arg) in args.iter().enumerate() {
        text = text.replace(&format!("{{{idx}}}"), arg);
    }
    text
}

fn format_saved_to(dest: &str) -> String { format!("{} {dest}", tr::lookup_id(TrId::ExportSavedTo)) }

// ---------------------------------------------------------------------------
// Policy building / persistence
// ---------------------------------------------------------------------------

/// Owned-result PSBT match, for running on a worker thread (no borrows escape).
fn match_owned(
    psbt: &Psbt,
    policies: &[RegisteredPolicy],
    fp: Fingerprint,
    gap: u32,
) -> std::result::Result<Option<(RegisteredPolicy, lpsbt::MatchResult)>, String> {
    match lpsbt::match_against_all(psbt, policies, fp, gap) {
        Ok(Some((p, m))) => Ok(Some((p.clone(), m))),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

fn master_for_network(seed: &[u8; 32], network: Network) -> anyhow::Result<Xpriv> {
    Xpriv::new_master(network, seed).map_err(|e| anyhow::anyhow!("master xpriv: {e}"))
}

fn account_path(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => MAINNET_ACCOUNT_PATH,
        _ => TEST_ACCOUNT_PATH,
    }
}

fn account_xpub(seed: &[u8; 32], secp: &Secp256k1<All>, network: Network) -> anyhow::Result<Xpub> {
    let master = master_for_network(seed, network)?;
    let acct = DerivationPath::from_str(account_path(network))?;
    Ok(Xpub::from_priv(secp, &master.derive_priv(secp, &acct)?))
}

/// Derive `[fp/path]xpub` at an ARBITRARY BIP32 path. This is HWI's
/// `get_pubkey_at_path` capability: the host asks for any path, Prime derives it.
fn xpub_with_origin_at(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    fp: Fingerprint,
    network: Network,
    path_str: &str,
) -> anyhow::Result<String> {
    let master = master_for_network(seed, network)?;
    let path = DerivationPath::from_str(path_str)?;
    let xpub = Xpub::from_priv(secp, &master.derive_priv(secp, &path)?);
    Ok(format!("[{}/{}]{}", fp, path_str.trim_start_matches("m/"), xpub))
}

fn key_with_origin(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    fp: Fingerprint,
    network: Network,
) -> anyhow::Result<String> {
    xpub_with_origin_at(seed, secp, fp, network, account_path(network))
}

/// Whether the host may request an xpub at `path_str` over the wire. Only standard
/// wallet account paths are served: a host that could ask for an ARBITRARY path
/// (e.g. the bare master `m`, or any deep path) could enumerate the entire key
/// tree and every address the device controls. We require a hardened, purpose-
/// rooted path (BIP44/48/49/84/86) at least three levels deep, which covers every
/// legitimate HWI `get_pubkey_at_path` request while blocking tree-mapping probes.
fn is_allowed_xpub_path(path_str: &str) -> bool {
    let Ok(path) = DerivationPath::from_str(path_str.trim()) else {
        return false;
    };
    let comps: Vec<ChildNumber> = path.into_iter().copied().collect();
    if comps.len() < 3 {
        return false;
    }
    matches!(comps[0], ChildNumber::Hardened { index } if matches!(index, 44 | 48 | 49 | 84 | 86))
}

fn set_xpub_export(ui: &AppWindow, state: &Arc<Mutex<AppState>>, network: Network) {
    let result = {
        let mut st = state.lock().unwrap();
        st.xpub_network = network;
        key_with_origin(&st.seed, &st.secp, st.fp, network).map(|key| {
            let path = account_path(network).to_string();
            let fp = st.fp.to_string();
            write_bridge_file(&st.data_dir, EXPORT_KEY_FILE, key.as_bytes());
            (key, path, fp)
        })
    };
    let cb = ui.global::<Callbacks>();
    cb.set_export_ok(false);
    cb.set_export_error("".into());
    cb.set_xpub_network(network_label(network).into());
    match result {
        Ok((key, path, fp)) => {
            cb.set_xpub_fingerprint(fp.into());
            cb.set_xpub_path(path.into());
            cb.set_xpub_value(key.into());
        }
        Err(e) => {
            cb.set_xpub_value("".into());
            cb.set_export_error(format!("{e}").into());
        }
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Signet => "signet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
    }
}

fn network_display(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "Bitcoin",
        Network::Signet => "Signet",
        Network::Testnet => "Testnet",
        Network::Testnet4 => "Testnet4",
        Network::Regtest => "Regtest",
    }
}

fn network_from_label(label: &str) -> Option<Network> {
    match label {
        "bitcoin" | "mainnet" | "Bitcoin" | "Mainnet" => Some(Network::Bitcoin),
        "signet" | "Signet" => Some(Network::Signet),
        "testnet" | "Testnet" => Some(Network::Testnet),
        "testnet4" | "Testnet4" => Some(Network::Testnet4),
        "regtest" | "Regtest" => Some(Network::Regtest),
        _ => None,
    }
}

fn network_from_policy(policy: &RegisteredPolicy) -> Option<Network> {
    network_from_label(policy.network.as_str())
}

fn network_from_descriptor(descriptor: &str) -> Network {
    if descriptor.contains("xpub") || descriptor.contains("ypub") || descriptor.contains("zpub") {
        Network::Bitcoin
    } else {
        // Testnet/Signet exports both use testnet-style extended keys (tpub) and
        // share the `tb` address prefix, so they are indistinguishable from the
        // descriptor alone. Default to Testnet — the network the nunchuk-cli
        // integration uses (signet is still selectable on the Export Xpub screen).
        Network::Testnet
    }
}

fn register_descriptor(
    text: &str,
    passport_fp: Fingerprint,
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
) -> anyhow::Result<RegisteredPolicy> {
    let parsed = descriptor::import(text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = parsed.checksum.clone();
    let network = network_from_descriptor(&parsed.canonical);
    let reg =
        policy::build_registered_policy(id, "Imported policy", network_label(network), &parsed, passport_fp)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !reg.signers.iter().any(|s| s.owned_by_passport) {
        anyhow::bail!("{}", tr::lookup_id(TrId::ImportErrorNoPassportKey));
    }
    // Bind ownership to the real key, not just the 4-byte fingerprint: the device's
    // own account xpub must actually appear in the descriptor. A forged-fingerprint
    // key could never produce a usable signature anyway, but this rejects it up front
    // instead of mislabeling it as Prime-owned.
    let dev_xpub = account_xpub(seed, secp, network)?.to_string();
    if !text.contains(&dev_xpub) {
        anyhow::bail!("descriptor names a Passport fingerprint but not Passport's actual key");
    }
    Ok(reg)
}

// Test-only fixtures (no longer seeded into the app — placeholder policy removed).
#[cfg(test)]
fn seed_sample(
    secp: &Secp256k1<All>,
    device_account_xpub: &Xpub,
    device_fp: Fingerprint,
) -> anyhow::Result<RegisteredPolicy> {
    let desc = sample_descriptor(secp, device_account_xpub, device_fp);
    let parsed = descriptor::import(&desc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let reg = policy::build_registered_policy(
        parsed.checksum.clone(),
        "Inheritance (demo)",
        "signet",
        &parsed,
        device_fp,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(reg)
}

#[cfg(test)]
fn sample_descriptor(secp: &Secp256k1<All>, device_account_xpub: &Xpub, device_fp: Fingerprint) -> String {
    let rec_master = Xpriv::new_master(DEFAULT_NETWORK, &[0x22; 32]).unwrap();
    let rec_fp = rec_master.fingerprint(secp);
    let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
    let rec_xpub = Xpub::from_priv(secp, &rec_master.derive_priv(secp, &acct).unwrap());
    let p = TEST_ACCOUNT_PATH.trim_start_matches("m/");
    format!(
        "wsh(or_d(pk([{device_fp}/{p}]{device_account_xpub}/<0;1>/*),and_v(v:pkh([{rec_fp}/{p}]{rec_xpub}/<0;1>/*),older({RECOVERY_BLOCKS}))))"
    )
}

/// Build a demo owner-path PSBT spending the policy's index-0 output (test only).
#[cfg(test)]
fn build_owner_psbt(
    secp: &Secp256k1<All>,
    reg: &RegisteredPolicy,
    device_account_xpub: &Xpub,
    device_fp: Fingerprint,
) -> anyhow::Result<Psbt> {
    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed.descriptor.into_single_descriptors().map_err(|e| anyhow::anyhow!("{e}"))?;
    let def = singles[0].at_derivation_index(0).map_err(|e| anyhow::anyhow!("{e}"))?;
    let spk = def.script_pubkey();
    let ws = def.explicit_script().map_err(|e| anyhow::anyhow!("{e}"))?;

    let child = DerivationPath::from_str("m/0/0").unwrap();
    let dev_pk = PublicKey::new(device_account_xpub.derive_pub(secp, &child)?.public_key);
    let full = DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap();

    let value = Amount::from_sat(100_000);
    let prevout = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
        vout: 0,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut input = Input {
        witness_utxo: Some(TxOut { value, script_pubkey: spk }),
        witness_script: Some(ws),
        ..Default::default()
    };
    input.bip32_derivation.insert(dev_pk.inner, (device_fp, full));
    psbt.inputs[0] = input;
    Ok(psbt)
}

fn policy_summary(p: &RegisteredPolicy) -> String {
    let network = network_from_policy(p).map(network_display).unwrap_or(p.network.as_str());
    let recovery = p
        .paths
        .iter()
        .find(|x| matches!(x.kind, SpendPathKind::Recovery))
        .and_then(|x| x.relative_timelock_blocks);
    match recovery {
        Some(n) => format!("{network} - recovery after {}", approx_time(n)),
        None => trfmt(TrId::SummarySinglePath, &[network]),
    }
}

fn load_policies(dir: &Path) -> store::PolicyStore { load_policies_impl(dir) }

#[cfg(not(keyos))]
fn load_policies_impl(dir: &Path) -> store::PolicyStore {
    let mut s = store::PolicyStore::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return s };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(reg) = store::from_json(&text) {
                let _ = s.add(reg);
            }
        }
    }
    s
}

#[cfg(keyos)]
fn load_policies_impl(_dir: &Path) -> store::PolicyStore {
    let fs = FileSystem::default();
    let mut s = store::PolicyStore::new();
    let Ok(dir) = fs.open_dir("", fs::Location::AppData) else { return s };
    while let Ok(Some(entry)) = dir.next_entry() {
        if !entry.name.starts_with("policy_") || !entry.name.ends_with(".json") || entry.is_dir {
            continue;
        }
        let Ok(text) =
            read_text_fs_limited(&fs, &entry.name, fs::Location::AppData, MAX_DESCRIPTOR_BYTES, "policy")
        else {
            continue;
        };
        if let Ok(reg) = store::from_json(&text) {
            let _ = s.add(reg);
        }
    }
    s
}

fn save_policy(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> { save_policy_impl(dir, reg) }

#[cfg(not(keyos))]
fn save_policy_impl(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = dir.join(format!("policy_{}.json", reg.descriptor_checksum));
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(keyos)]
fn save_policy_impl(_dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = format!("policy_{}.json", reg.descriptor_checksum);
    let mut fs = FileSystem::default();
    {
        let mut file = fs
            .open_file(&path, fs::Location::AppData, fs::OpenFlags { read: true, write: true, create: true })
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.truncate().map_err(|e| anyhow::anyhow!("truncate {path}: {e:?}"))?;
        file.flush()?;
    }
    fs.flush(fs::Location::AppData).map_err(|e| anyhow::anyhow!("flush app data: {e:?}"))?;
    Ok(())
}

fn delete_policy_file(dir: &Path, checksum: &str) -> anyhow::Result<()> {
    delete_policy_file_impl(dir, checksum)
}

#[cfg(not(keyos))]
fn delete_policy_file_impl(dir: &Path, checksum: &str) -> anyhow::Result<()> {
    std::fs::remove_file(dir.join(format!("policy_{checksum}.json")))?;
    Ok(())
}

#[cfg(keyos)]
fn delete_policy_file_impl(_dir: &Path, checksum: &str) -> anyhow::Result<()> {
    let path = format!("policy_{checksum}.json");
    FileSystem::default()
        .remove(&path, fs::Location::AppData)
        .map_err(|e| anyhow::anyhow!("remove {path}: {e:?}"))
}

fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(DATA_SUBDIR)
}

#[cfg(not(keyos))]
fn sim_bridge_file(dir: &Path, filename: &str) -> Option<PathBuf> {
    let path = dir.join(filename);
    path.exists().then_some(path)
}

#[cfg(keyos)]
fn sim_bridge_file(_dir: &Path, _filename: &str) -> Option<PathBuf> { None }

#[cfg(not(keyos))]
fn write_bridge_file(dir: &Path, filename: &str, bytes: &[u8]) {
    write_bridge_path(&dir.join(filename), bytes);
}

#[cfg(keyos)]
fn write_bridge_file(_dir: &Path, _filename: &str, _bytes: &[u8]) {}

#[cfg(not(keyos))]
fn write_bridge_path(path: &Path, bytes: &[u8]) {
    if let Err(e) = std::fs::write(path, bytes) {
        log::warn!("failed to write sim bridge file {}: {e}", path.display());
    }
}

#[cfg(keyos)]
fn write_bridge_path(_path: &Path, _bytes: &[u8]) {}

fn show_startup_error(ui: &AppWindow, msg: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_policy_count(0);
    cb.set_archived_count(0);
    cb.set_import_error(msg.into());
}

/// Open the QR scanner overlay and return the scanned text (address / BIP21 URI).
fn scan_address_qr() -> Option<String> {
    match open_qr_scanner::<GuiPermissions>(ScanQrOptions::new()) {
        Ok(Some(ScanQrResult::Qr { data, .. })) => String::from_utf8(data).ok(),
        _ => None, // cancelled, UR payload, or error
    }
}

/// Normalize a scanned address: strip a `bitcoin:` URI prefix + query params,
/// lowercase (bech32 is case-insensitive; derived addresses are lowercase).
fn normalize_address(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")).unwrap_or(s);
    s.split('?').next().unwrap_or(s).trim().to_lowercase()
}

fn read_bytes_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        anyhow::bail!("{label} file is too large ({} bytes, max {max_bytes})", meta.len());
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} file is too large (max {max_bytes})");
    }
    Ok(bytes)
}

fn read_text_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_bytes_path_limited(path, max_bytes, label)?)
        .map_err(|_| anyhow::anyhow!("{label} file is not valid UTF-8"))?)
}

fn read_bytes_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let meta = filesystem.metadata(path, location).map_err(|e| anyhow::anyhow!("metadata {path}: {e:?}"))?;
    if meta.size > max_bytes {
        anyhow::bail!("{label} file is too large ({} bytes, max {max_bytes})", meta.size);
    }
    let file = filesystem
        .open_file(path, location, fs::OpenFlags { read: true, write: false, create: false })
        .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
    let mut bytes = Vec::with_capacity(meta.size as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes).map_err(|e| anyhow::anyhow!("read {path}: {e:?}"))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} file is too large (max {max_bytes})");
    }
    Ok(bytes)
}

fn read_text_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_bytes_fs_limited(filesystem, path, location, max_bytes, label)?)
        .map_err(|_| anyhow::anyhow!("{label} file is not valid UTF-8"))?)
}

/// Is `target` an address derived from this policy's descriptor? Returns the
/// path ("receive"/"change") and derivation index if found.
fn verify_address_in_policy(descriptor_str: &str, target: &str, network: Network) -> Option<(String, u32)> {
    let parsed = descriptor::import(descriptor_str).ok()?;
    let singles = parsed.descriptor.into_single_descriptors().ok()?;
    for (si, single) in singles.iter().enumerate() {
        for idx in 0..GAP {
            if let Ok(def) = single.at_derivation_index(idx) {
                if let Ok(addr) = def.address(network) {
                    if addr.to_string().to_lowercase() == target {
                        let kind = if si == 0 { "receive" } else { "change" };
                        return Some((kind.to_string(), idx));
                    }
                }
            }
        }
    }
    None
}

/// Format an integer with thousands separators (52596 -> "52,596").
fn commas(n: impl Into<u64>) -> String {
    let s = n.into().to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Read a PSBT from a file, accepting raw binary (BIP-174) or base64 text
/// (Nunchuk can export either).
/// Parse a PSBT from raw bytes — accepts either binary or base64-encoded.
fn parse_psbt_bytes(bytes: &[u8]) -> anyhow::Result<Psbt> {
    use base64::Engine;
    if let Ok(psbt) = Psbt::deserialize(bytes) {
        return Ok(psbt);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(text.trim()) {
            if let Ok(psbt) = Psbt::deserialize(&raw) {
                return Ok(psbt);
            }
        }
    }
    Err(anyhow::anyhow!("not a valid PSBT (binary or base64)"))
}

fn read_psbt_file(path: &Path) -> anyhow::Result<Psbt> {
    parse_psbt_bytes(&read_bytes_path_limited(path, MAX_PSBT_BYTES, "PSBT")?)
}

/// Open the file-browser picker (directory-selection) so the user chooses where
/// to save, then write `filename` with `bytes` into that folder + location.
/// Returns a "location:path" string for the status. Requires the per-location
/// access grants in manifest.toml (USB / Airlock / User), else "Access Denied".
/// Open the file picker in folder-selection mode, then write `filename` into the
/// chosen folder/location. Mirrors the Bitcoin app's save flow exactly: open with
/// `{ read: false, write: true, create: true }` and a single `overwrite` — no
/// `set_len` (which errors on the FAT/SD path and aborts the write). `overwrite`
/// Write `bytes` to a fresh file inside `dir` at `location`, committing it in the
/// order that survives card removal on FAT media: chunked write -> `File::flush`
/// (which writes the directory entry: size / first_cluster / mtime) -> close the
/// file -> `FileSystem::flush` (which flushes the block cache to the medium).
///
/// The directory-entry flush on close is the critical step (see SFT-7122): in
/// rust-fatfs the FAT and data bytes hit the block cache during the write, but the
/// directory entry only persists on `File::flush` / close. A bare
/// `FileSystem::flush` on a still-open file leaves a stale entry and a torn image.
fn write_export(
    filename: &str,
    bytes: &[u8],
    location: fs::Location,
    dir: &str,
) -> anyhow::Result<String> {
    use std::io::Write;
    let mut filesystem = FileSystem::default();
    let directory = filesystem.create_dir(dir, location).map_err(|e| {
        if matches!(e, fs::Error::NoMedia) {
            match location {
                // Airlock is owned by the host while Passport is plugged in over USB.
                fs::Location::Airlock => anyhow::anyhow!(
                    "Disconnect Passport from your computer first, then save (Airlock is in use while connected)"
                ),
                fs::Location::Usb => anyhow::anyhow!("No SD card or USB drive found"),
                _ => anyhow::anyhow!("Storage not available"),
            }
        } else {
            anyhow::anyhow!("open {dir}: {e:?}")
        }
    })?;
    let unique =
        directory.pick_next_filename(filename, None).map_err(|e| anyhow::anyhow!("pick filename: {e:?}"))?;
    let path = format!("{dir}/{unique}");
    {
        let mut file = filesystem
            .open_file(
                path.clone(),
                location,
                fs::OpenFlags { read: false, write: true, create: true },
            )
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        let mut written = 0usize;
        while written < bytes.len() {
            let end = (written + 512).min(bytes.len());
            let n = file
                .write(&bytes[written..end])
                .map_err(|e| anyhow::anyhow!("write {path} @{written}: {e:?}"))?;
            if n == 0 {
                anyhow::bail!("write returned 0 at offset {written} of {}", bytes.len());
            }
            written += n;
        }
        // Commit the directory entry (NOT done by FileSystem::flush alone).
        file.flush().map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    } // drop file -> CloseFile (re-commits the directory entry)
    drop(directory); // CloseDir
    filesystem.flush(location).map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
    Ok(format!("{}{}", loc_label(location), path))
}

/// Open the folder picker and write `filename` into the chosen folder/location
/// (SD, USB, internal, or Airlock), using the close-before-flush sequence above.
fn export_via_picker(filename: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let options = SelectFileOptions::default()
        .with_dir_selection_mode(true)
        .with_allowed_locations(AllowedLocations::All);
    let result = select_file::<GuiPermissions>(options)
        .map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((dir, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no folder selected");
    };
    let dir = dir.trim_end_matches('/').to_string();
    // Picking a location root gives an empty path; tuck files into a `nunchuk/` subdir.
    let dir = if dir.is_empty() { EXPORT_DIR.to_string() } else { dir };
    write_export(filename, bytes, map_location(loc), &dir)
}

fn loc_label(loc: fs::Location) -> &'static str {
    match loc {
        fs::Location::Usb => "usb:/",
        fs::Location::Airlock => "airlock:/",
        fs::Location::User => "user:/",
        _ => "",
    }
}

/// Open the file picker (file-selection mode), read the chosen file, and return
/// its text contents. Used to import a Nunchuk descriptor.
fn import_via_picker() -> anyhow::Result<String> {
    let options = SelectFileOptions::default().with_allowed_locations(AllowedLocations::All);
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((path, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no file selected");
    };
    let filesystem = FileSystem::default();
    read_text_fs_limited(&filesystem, &path, map_location(loc), MAX_DESCRIPTOR_BYTES, "descriptor")
}

fn map_location(loc: PickLocation) -> fs::Location {
    match loc {
        PickLocation::Internal => fs::Location::User,
        PickLocation::Airlock => fs::Location::Airlock,
        PickLocation::External => fs::Location::Usb,
    }
}

/// Base64-encode a PSBT (Nunchuk's import-from-text / paste format).
fn psbt_base64(psbt: &Psbt) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}


// ---------------------------------------------------------------------------
// Nunchuk spending-policy gate: glue (seed, demo PSBT, persistence, clock)
// ---------------------------------------------------------------------------

/// Current time in epoch seconds. Host (simulator) reads the system clock; on
/// device there is no trusted RTC wired yet, so it returns 0 -> the time-window
/// caps are disabled and only the clock-free session/lifetime caps apply.
#[cfg(not(keyos))]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
#[cfg(keyos)]
fn now_secs() -> u64 {
    0
}

// ---------------------------------------------------------------------------
// Crash-safe persistence (the velocity ledger depends on this).
//
// The on-device FAT `rename` refuses to overwrite an existing file, so we can't
// use the usual write-tmp-then-rename atomic swap. Instead each logical file
// (`history.json`, `policy.json`) is stored as TWO physical slots (`name.0`,
// `name.1`) carrying a monotonic `seq`. A write always lands on the OLDER slot,
// leaving the current-newest intact until it completes; the loader picks the
// newer slot that still parses. A torn write (power loss mid-write) corrupts at
// most the slot being written, so the previous good copy always survives. This
// is what stops a power-controlling host from blanking the spend budget by
// cutting USB power during a ledger write.
// ---------------------------------------------------------------------------

/// Tri-state load result: distinguish "never written" (first run, defaults are
/// fine) from "written but unreadable" (corruption -> the caller MUST fail closed,
/// never silently reset to permissive defaults).
enum Loaded<T> {
    Absent,
    Valid(T),
    Corrupt,
}

/// A/B slot envelope: `seq` orders the two slots; JSON-parse validity is the
/// integrity check (a truncated write won't deserialize).
#[derive(serde::Serialize, serde::Deserialize)]
struct Versioned {
    seq: u64,
    data: serde_json::Value,
}

/// Low-level: write all bytes to one app-data file, flushed to disk.
#[cfg(not(keyos))]
fn write_one(dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(dir.join(name))?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?; // fsync the data before we treat the slot as committed
    Ok(())
}
#[cfg(keyos)]
fn write_one(_dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut fs = FileSystem::default();
    {
        let mut file = fs
            .open_file(name, fs::Location::AppData, fs::OpenFlags { read: true, write: true, create: true })
            .map_err(|e| anyhow::anyhow!("open {name}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.truncate().map_err(|e| anyhow::anyhow!("truncate {name}: {e:?}"))?;
        file.flush()?;
    }
    fs.flush(fs::Location::AppData).map_err(|e| anyhow::anyhow!("flush app data: {e:?}"))?;
    Ok(())
}

/// Low-level: read one app-data file's bytes (None if absent/unreadable).
#[cfg(not(keyos))]
fn read_one(dir: &Path, name: &str) -> Option<Vec<u8>> {
    read_bytes_path_limited(&dir.join(name), MAX_DESCRIPTOR_BYTES, "json").ok()
}
#[cfg(keyos)]
fn read_one(_dir: &Path, name: &str) -> Option<Vec<u8>> {
    let fs = FileSystem::default();
    read_bytes_fs_limited(&fs, name, fs::Location::AppData, MAX_DESCRIPTOR_BYTES, "json").ok()
}

fn read_versioned_slot(dir: &Path, name: &str) -> Option<Versioned> {
    read_one(dir, name).and_then(|b| serde_json::from_slice::<Versioned>(&b).ok())
}

/// Persist `value` to the older of the two slots, with a higher `seq`.
fn save_versioned<T: serde::Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<()> {
    let (slot_a, slot_b) = (format!("{name}.0"), format!("{name}.1"));
    let seq_a = read_versioned_slot(dir, &slot_a).map(|v| v.seq);
    let seq_b = read_versioned_slot(dir, &slot_b).map(|v| v.seq);
    let next_seq = seq_a.unwrap_or(0).max(seq_b.unwrap_or(0)).wrapping_add(1);
    // Write the new copy to the older/invalid slot so the newest stays intact.
    let target = match (seq_a, seq_b) {
        (None, _) => slot_a,
        (_, None) => slot_b,
        (Some(a), Some(b)) => {
            if a <= b {
                slot_a
            } else {
                slot_b
            }
        }
    };
    let env = Versioned { seq: next_seq, data: serde_json::to_value(value)? };
    write_one(dir, &target, serde_json::to_string(&env)?.as_bytes())
}

/// Load the newer valid slot. Falls back to a legacy single-file `name` (pre-A/B
/// builds) for a one-time migration.
fn load_versioned<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> Loaded<T> {
    let (slot_a, slot_b) = (format!("{name}.0"), format!("{name}.1"));
    let raw_a = read_one(dir, &slot_a);
    let raw_b = read_one(dir, &slot_b);
    if raw_a.is_none() && raw_b.is_none() {
        // No A/B slots: migrate a legacy single file if present, else first run.
        return match read_one(dir, name) {
            Some(bytes) => match serde_json::from_slice::<T>(&bytes) {
                Ok(v) => Loaded::Valid(v),
                Err(_) => Loaded::Corrupt,
            },
            None => Loaded::Absent,
        };
    }
    // At least one slot file exists. Pick the newer one that still parses.
    let a = raw_a.and_then(|b| serde_json::from_slice::<Versioned>(&b).ok());
    let b = raw_b.and_then(|b| serde_json::from_slice::<Versioned>(&b).ok());
    let best = match (a, b) {
        (Some(a), Some(b)) => Some(if a.seq >= b.seq { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    match best.and_then(|env| serde_json::from_value::<T>(env.data).ok()) {
        Some(v) => Loaded::Valid(v),
        // A slot file existed but nothing parsed -> data was there and is now
        // unreadable. Fail closed; do NOT silently reset.
        None => Loaded::Corrupt,
    }
}

/// Load the spending policy. Returns (policy, unsafe) where `unsafe` = the saved
/// policy was corrupt, so the device must pause auto-signing until the user
/// re-confirms it (we surface defaults for display but force approval meanwhile).
fn load_spend_policy(dir: &Path) -> (gate::SpendPolicy, bool) {
    match load_versioned::<gate::SpendPolicy>(dir, "policy.json") {
        Loaded::Valid(p) => (p, false),
        Loaded::Absent => (gate::SpendPolicy::default(), false),
        Loaded::Corrupt => (gate::SpendPolicy::default(), true),
    }
}
fn save_spend_policy(dir: &Path, p: &gate::SpendPolicy) -> anyhow::Result<()> {
    save_versioned(dir, "policy.json", p)
}
/// Load the spend ledger. Returns (history, unsafe) where `unsafe` = the ledger
/// was corrupt: the velocity budget can't be trusted, so pause auto-signing.
fn load_history(dir: &Path) -> (history::SpendHistory, bool) {
    match load_versioned::<history::SpendHistory>(dir, "history.json") {
        Loaded::Valid(h) => (h, false),
        Loaded::Absent => (history::SpendHistory::new(), false),
        Loaded::Corrupt => (history::SpendHistory::new(), true),
    }
}
fn save_history(dir: &Path, h: &history::SpendHistory) -> anyhow::Result<()> {
    save_versioned(dir, "history.json", h)
}

/// Per-wallet policy overrides, keyed by descriptor checksum. A wallet with no
/// entry uses the global default policy. Stored as one map file (atomic). Returns
/// (map, unsafe): a corrupt map pauses auto-signing (fail closed), same as the
/// other security files.
type WalletPolicies = std::collections::HashMap<String, gate::SpendPolicy>;
fn load_wallet_policies(dir: &Path) -> (WalletPolicies, bool) {
    match load_versioned::<WalletPolicies>(dir, "wallet_policies.json") {
        Loaded::Valid(m) => (m, false),
        Loaded::Absent => (WalletPolicies::new(), false),
        Loaded::Corrupt => (WalletPolicies::new(), true),
    }
}
fn save_wallet_policies(dir: &Path, m: &WalletPolicies) -> anyhow::Result<()> {
    save_versioned(dir, "wallet_policies.json", m)
}

/// Human-readable estimate of a relative block count (~10 min/block).
/// Upper bound for the recovery timelock picker: 4 weeks (4032 blocks). Keeps the
/// stepper from running away while still spanning hours-to-weeks.
const RECOVERY_BLOCKS_MAX: u32 = 13140; // ~3 months (upper bound for the recovery timelock)

/// Human-readable recovery timelock, e.g. "144 blocks (~1 days)". Pairs the raw
/// block count (what the descriptor encodes) with an approximate wall-clock scale.
fn recovery_summary(blocks: u32) -> String {
    format!("{} blocks ({})", commas(blocks), approx_time(blocks))
}

fn approx_time(blocks: u32) -> String {
    let mins = blocks as u64 * 10;
    if mins < 120 {
        format!("~{mins} min")
    } else if mins < 2 * 24 * 60 {
        format!("~{} hours", mins / 60)
    } else if blocks < 60 * 144 {
        format!("~{} days", blocks / 144)
    } else {
        format!("~{} months", blocks / 4380)
    }
}

/// The primary (non-change) destination address of a PSBT, for the activity log.
fn primary_dest(psbt: &Psbt, reg: &RegisteredPolicy) -> String {
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    let cands = lpsbt::candidate_spks(reg, GAP).ok();
    for o in &psbt.unsigned_tx.output {
        let is_change = cands.as_ref().map(|c| c.contains(&o.script_pubkey)).unwrap_or(false);
        if !is_change {
            return Address::from_script(&o.script_pubkey, network)
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".into());
        }
    }
    "unknown".into()
}

/// Build the miniscript demo wallet and register it:
///   wsh(or_d(multi(2, agent, prime), and_v(v:pk(prime), older(N))))
/// Normal: agent + Prime 2-of-2 (policy-gated). Recovery: Prime ALONE after N
/// blocks, so funds are not locked if the agent key disappears. The device (Prime)
/// owns its multisig key (<0;1>) AND the recovery key (<2;3>, same xpub).
fn seed_demo_wallet(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    device_fp: Fingerprint,
    recovery_blocks: u32,
    with_platform_key: bool,
) -> anyhow::Result<RegisteredPolicy> {
    let network = DEFAULT_NETWORK;
    let dev_key = key_with_origin(seed, secp, device_fp, network)?; // [fp/48'/1'/0'/2']xpub
    let p = account_path(network).trim_start_matches("m/");
    let acct = DerivationPath::from_str(account_path(network))?;
    // A deterministic external key-with-origin (host-side parties in the demo).
    let det_key = |bytes: [u8; 32]| -> anyhow::Result<String> {
        let m = Xpriv::new_master(network, &bytes)?;
        let f = m.fingerprint(secp);
        let x = Xpub::from_priv(secp, &m.derive_priv(secp, &acct)?);
        Ok(format!("[{f}/{p}]{x}"))
    };
    let agent_key = det_key([0x42; 32])?; // the automated agent's hot key
    // Primary path: 2-of-2 (agent + Prime) or 2-of-3 (agent + Nunchuk Platform Key
    // + Prime). Recovery key reuses Prime's xpub at <2;3> so its addresses never
    // collide with the multisig ones.
    let multi_keys = if with_platform_key {
        let platform_key = det_key([0x77; 32])?; // stand-in for the Nunchuk Platform Key
        format!("{agent_key}/<0;1>/*,{dev_key}/<0;1>/*,{platform_key}/<0;1>/*")
    } else {
        format!("{agent_key}/<0;1>/*,{dev_key}/<0;1>/*")
    };
    let desc = format!(
        "wsh(or_d(multi(2,{multi_keys}),and_v(v:pk({dev_key}/<2;3>/*),older({recovery_blocks}))))"
    );
    let parsed = descriptor::import(&desc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let reg = policy::build_registered_policy(
        parsed.checksum.clone(),
        "Agent Wallet (demo)",
        network_label(network),
        &parsed,
        device_fp,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(reg)
}

/// Build an unsigned RECOVERY-path PSBT: spends the wallet via the Prime-only
/// branch with an nSequence that satisfies older(N), so the device can sign it
/// alone. Used to test/demo recovery when the agent key is gone.
#[cfg(test)]
fn build_recovery_demo_psbt(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    device_fp: Fingerprint,
    reg: &RegisteredPolicy,
    amount: u64,
    recovery_blocks: u32,
) -> anyhow::Result<Psbt> {
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed.descriptor.into_single_descriptors().map_err(|e| anyhow::anyhow!("{e}"))?;
    let def = singles[0].at_derivation_index(0).map_err(|e| anyhow::anyhow!("{e}"))?;
    let spk = def.script_pubkey();
    let ws = def.explicit_script().map_err(|e| anyhow::anyhow!("{e}"))?;

    let master = master_for_network(seed, network)?;
    let acct = DerivationPath::from_str(account_path(network))?;
    let acct_xpub = Xpub::from_priv(secp, &master.derive_priv(secp, &acct)?);
    // Recovery branch uses the <2;3> multipath -> receive index 2.
    let rec_child = DerivationPath::from_str("m/2/0")?;
    let rec_pk = PublicKey::new(acct_xpub.derive_pub(secp, &rec_child)?.public_key);
    let rec_full = DerivationPath::from_str(&format!("{}/2/0", account_path(network)))?;

    let value = Amount::from_sat(amount + 1_000);
    let prevout = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
        vout: 0,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            // Relative timelock satisfying older(N) -> unlocks the recovery branch.
            sequence: Sequence::from_height(recovery_blocks as u16),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut input = Input { witness_utxo: Some(TxOut { value, script_pubkey: spk }), witness_script: Some(ws), ..Default::default() };
    input.bip32_derivation.insert(rec_pk.inner, (device_fp, rec_full));
    psbt.inputs[0] = input;
    Ok(psbt)
}

/// Build an unsigned 2-of-2 PSBT spending the wallet's index-0 output, with the
/// device key's bip32 origin attached so the device can contribute its signature.
/// `amount` sats leave to a dummy address; outflow = amount + a small fee.
fn build_demo_psbt(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    device_fp: Fingerprint,
    reg: &RegisteredPolicy,
    amount: u64,
) -> anyhow::Result<Psbt> {
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed.descriptor.into_single_descriptors().map_err(|e| anyhow::anyhow!("{e}"))?;
    let def = singles[0].at_derivation_index(0).map_err(|e| anyhow::anyhow!("{e}"))?;
    let spk = def.script_pubkey();
    let ws = def.explicit_script().map_err(|e| anyhow::anyhow!("{e}"))?;

    let master = master_for_network(seed, network)?;
    let acct = DerivationPath::from_str(account_path(network))?;
    let acct_xpub = Xpub::from_priv(secp, &master.derive_priv(secp, &acct)?);
    let child = DerivationPath::from_str("m/0/0")?;
    let dev_pk = PublicKey::new(acct_xpub.derive_pub(secp, &child)?.public_key);
    let full = DerivationPath::from_str(&format!("{}/0/0", account_path(network)))?;

    let value = Amount::from_sat(amount + 1_000);
    let prevout = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
        vout: 0,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut input = Input { witness_utxo: Some(TxOut { value, script_pubkey: spk }), witness_script: Some(ws), ..Default::default() };
    input.bip32_derivation.insert(dev_pk.inner, (device_fp, full));
    psbt.inputs[0] = input;
    Ok(psbt)
}

/// Sign a pending PSBT autonomously (within policy, no human tap), record it in
/// the ledger as an auto-sign, and show in-screen success.
fn auto_sign_pending(ui: &AppWindow, state: &Arc<Mutex<AppState>>, pending: Pending) {
    let signed_ok = {
        let mut st = state.lock().unwrap();
        let network = network_from_policy(&pending.policy).unwrap_or(DEFAULT_NETWORK);
        let master = match master_for_network(&st.seed, network) {
            Ok(m) => m,
            Err(e) => {
                set_status(ui, &format!("auto-sign failed: {e}"));
                return;
            }
        };
        let rec_outflow = pending.outflow;
        let rec_txid = pending.psbt.unsigned_tx.compute_txid().to_string();
        let rec_dest = primary_dest(&pending.psbt, &pending.policy);
        let rec_wallet = pending.policy.name.clone();
        let rec_wallet_id = pending.policy.descriptor_checksum.clone();
        match signing::sign(pending.psbt, &master, &st.secp) {
            Ok(signed) => {
                // Persist the debit BEFORE releasing the signature (history.rs rule:
                // a power-cut after release must not be able to reset the budget).
                let now = now_secs();
                st.history.record(history::SpendRecord {
                    unix_time: now,
                    amount_sats: rec_outflow,
                    dest: rec_dest,
                    kind: history::SignKind::Auto,
                    txid: rec_txid,
                    wallet: rec_wallet,
                    wallet_id: rec_wallet_id,
                });
                // Block release if the debit can't be persisted: roll back, enter
                // safe mode, and DON'T expose the signature (S3).
                if let Err(e) = save_history(&st.data_dir, &st.history) {
                    st.history.records.pop();
                    st.safe_mode = true;
                    st.safe_mode_reason =
                        "Couldn't record the last spend to the ledger; auto-signing is paused.".to_string();
                    set_status(ui, &format!("auto-sign withheld: ledger write failed ({e})"));
                    return;
                }
                // Now expose the signed PSBT to the host.
                st.last_signed = Some(signed.serialize());
                write_bridge_file(&st.data_dir, SIGNED_PSBT_FILE, &signed.serialize());
                write_bridge_file(&st.data_dir, "signed-psbt.b64.txt", psbt_base64(&signed).as_bytes());
                true
            }
            Err(e) => {
                set_status(ui, &format!("auto-sign failed: {e}"));
                false
            }
        }
    };
    if signed_ok {
        let cb = ui.global::<Callbacks>();
        cb.set_signing(false);
        cb.set_review_signed(true);
        cb.set_review_saved(false);
        cb.set_review_signed_detail("Auto-signed within policy (no approval needed).".into());
        set_status(ui, tr::lookup_id(TrId::StatusPsbtSigned));
    }
}

// ---------------------------------------------------------------------------
// Tests for the app-specific glue (no GUI). The policy/PSBT/signing logic
// itself is covered by nunchuk-signer-core's own test suite.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> (Secp256k1<All>, Xpub, Fingerprint) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(DEFAULT_NETWORK, &[0x11; 32]).unwrap();
        let fp = master.fingerprint(&secp);
        let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct).unwrap());
        (secp, xpub, fp)
    }

    // Regression: a REAL descriptor exported by Nunchuk (Signet, P2WSH simple
    // inheritance) parses, our recomputed checksum matches Nunchuk's exactly, and
    // the paths/timelock/signers classify correctly. (Ported from the retired
    // nunchuk-signer-core reference crate.)
    #[test]
    fn real_nunchuk_descriptor_parses_and_matches_checksum() {
        const REAL: &str = "wsh(or_d(pk([22663c8a/48'/1'/0'/2']tpubDDz15PcqAurpydRu3ZD7EB9nGRFEttDcbge8sPTqBo2fGXQkdoLjwAkoHjKFkqBFpkrZ8dS6DSDB5bG5EC5XcbJ5LuTRbgtgoCugm7puBAX/<0;1>/*),and_v(v:pkh([22663c8a/48'/1'/0'/2']tpubDDz15PcqAurpydRu3ZD7EB9nGRFEttDcbge8sPTqBo2fGXQkdoLjwAkoHjKFkqBFpkrZ8dS6DSDB5bG5EC5XcbJ5LuTRbgtgoCugm7puBAX/<2;3>/*),older(52596))))#9xtyycfv";
        let parsed = descriptor::import(REAL).expect("real Nunchuk descriptor imports");
        assert_eq!(parsed.checksum, "9xtyycfv", "our checksum must match Nunchuk's");
        let fp = Fingerprint::from_str("22663c8a").unwrap();
        let reg = policy::build_registered_policy("real", "Real", "signet", &parsed, fp).unwrap();
        assert_eq!(reg.paths.len(), 2);
        let recovery = reg.paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(recovery.relative_timelock_blocks, Some(52596));
        assert!(reg.signers.iter().all(|s| s.fingerprint == "22663c8a" && s.owned_by_passport));
    }

    #[test]
    fn sample_descriptor_is_valid_nunchuk_p2wsh() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        assert!(desc.starts_with("wsh("));
        let parsed = descriptor::import(&desc).expect("imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| matches!(p.kind, SpendPathKind::Primary)));
        let rec = paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(RECOVERY_BLOCKS));
    }

    // A key-with-origin string (`[fp/path]xpub`) from a deterministic seed, for
    // building descriptors in tests without hardcoding xpubs.
    fn test_key(seed: u8) -> String {
        let secp = Secp256k1::new();
        let m = Xpriv::new_master(DEFAULT_NETWORK, &[seed; 32]).unwrap();
        let fp = m.fingerprint(&secp);
        let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
        let xpub = Xpub::from_priv(&secp, &m.derive_priv(&secp, &acct).unwrap());
        format!("[{fp}/48'/1'/0'/2']{xpub}")
    }

    // A decaying policy (primary + two recovery tiers at different timelocks)
    // must flatten into three distinct spend paths, not merge the nested
    // recovery branches into one.
    #[test]
    fn decaying_policy_flattens_into_distinct_tiers() {
        let (a, b, c) = (test_key(0x21), test_key(0x22), test_key(0x23));
        let desc = format!(
            "wsh(or_d(pk({a}/<0;1>/*),or_i(and_v(v:pkh({b}/<0;1>/*),older(1000)),and_v(v:pkh({c}/<0;1>/*),older(2000)))))"
        );
        let parsed = descriptor::import(&desc).expect("decaying descriptor imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 3, "primary + 2 recovery tiers");
        assert_eq!(paths.iter().filter(|p| matches!(p.kind, SpendPathKind::Primary)).count(), 1);
        let mut tls: Vec<u32> = paths
            .iter()
            .filter(|p| matches!(p.kind, SpendPathKind::Recovery))
            .filter_map(|p| p.relative_timelock_blocks)
            .collect();
        tls.sort();
        assert_eq!(tls, vec![1000, 2000], "each tier keeps its own timelock");
    }

    // CLI-driven plain 2-of-3 (Nunchuk sortedmulti, no recovery leg): Passport must
    // classify it as ONE everyday path (2 of 3) with no recovery branch, and see the
    // agent + Platform Key as the two external signers. (test_key(0x11) == device().)
    #[test]
    fn plain_two_of_three_has_no_recovery_path() {
        let (_secp, _xpub, fp) = device();
        let (agent, prime, platform) = (test_key(0x42), test_key(0x11), test_key(0x99));
        let desc = format!("wsh(sortedmulti(2,{agent}/<0;1>/*,{prime}/<0;1>/*,{platform}/<0;1>/*))");
        let parsed = descriptor::import(&desc).expect("plain 2-of-3 imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 1, "no recovery branch");
        assert!(matches!(paths[0].kind, SpendPathKind::Primary));
        assert_eq!((paths[0].threshold, paths[0].total_keys), (2, 3));
        let reg = policy::build_registered_policy("p", "Plain", "testnet", &parsed, fp).unwrap();
        assert!(reg.signers.iter().any(|s| s.fingerprint == fp.to_string() && s.owned_by_passport));
        assert_eq!(reg.signers.iter().filter(|s| !s.owned_by_passport).count(), 2, "agent + Platform Key");
    }

    // CLI-driven 2-of-3 WITH a recovery leg (distinct recovery key, as Nunchuk's CLI
    // requires): Passport must surface BOTH the everyday 2-of-3 path and the recovery
    // path with its timelock, so the detail screen can display them.
    #[test]
    fn two_of_three_with_recovery_leg_classifies_both_paths() {
        let (agent, prime, platform, recovery) =
            (test_key(0x42), test_key(0x11), test_key(0x99), test_key(0xAB));
        let desc = format!(
            "wsh(or_d(multi(2,{agent}/<0;1>/*,{prime}/<0;1>/*,{platform}/<0;1>/*),and_v(v:pk({recovery}/<0;1>/*),older(26280))))"
        );
        let parsed = descriptor::import(&desc).expect("2-of-3 + recovery imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 2, "everyday + recovery");
        let primary = paths.iter().find(|p| matches!(p.kind, SpendPathKind::Primary)).unwrap();
        assert_eq!((primary.threshold, primary.total_keys), (2, 3));
        let rec = paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(26280));
    }

    // The xpub-over-USB path allowlist: standard wallet account paths only; the bare
    // master and non-purpose / too-shallow paths are refused (no key-tree mapping).
    #[test]
    fn xpub_path_allowlist_blocks_master_and_nonstandard() {
        assert!(is_allowed_xpub_path("m/48'/1'/0'/2'"));
        assert!(is_allowed_xpub_path("m/84'/1'/0'"));
        assert!(is_allowed_xpub_path("m/86'/0'/0'"));
        assert!(!is_allowed_xpub_path("m"), "bare master refused");
        assert!(!is_allowed_xpub_path("m/0/0"), "non-purpose refused");
        assert!(!is_allowed_xpub_path("m/48'"), "too shallow refused");
        assert!(!is_allowed_xpub_path("not a path"), "garbage refused");
    }

    // Crash-safe persistence: a torn write corrupts at most one A/B slot, and the
    // previous good slot survives. Two bad slots fail CLOSED (Corrupt), never
    // silently default. This is what stops a power-controlling host from blanking
    // the spend budget.
    #[test]
    fn versioned_persistence_survives_a_torn_write() {
        let dir = std::env::temp_dir().join("nunchuk-versioned-torn-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = gate::SpendPolicy::default();
        save_versioned(&dir, "t.json", &p).unwrap();
        save_versioned(&dir, "t.json", &p).unwrap(); // both slots now hold valid copies
        std::fs::write(dir.join("t.json.1"), b"{ truncated").unwrap(); // simulate a power-cut
        assert!(
            matches!(load_versioned::<gate::SpendPolicy>(&dir, "t.json"), Loaded::Valid(_)),
            "the other good slot must survive a torn write"
        );
        std::fs::write(dir.join("t.json.0"), b"garbage").unwrap();
        assert!(
            matches!(load_versioned::<gate::SpendPolicy>(&dir, "t.json"), Loaded::Corrupt),
            "both slots bad must report Corrupt, never silently default"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A present-but-unreadable policy must pause auto-signing (fail closed), not
    // silently revert to the permissive defaults.
    #[test]
    fn corrupt_policy_load_is_fail_closed() {
        let dir = std::env::temp_dir().join("nunchuk-corrupt-policy-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policy.json.0"), b"{ not valid").unwrap();
        let (_, unsafe_) = load_spend_policy(&dir);
        assert!(unsafe_, "corrupt policy must set the fail-closed flag");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A Taproot Nunchuk descriptor (tr) must import and classify its paths.
    #[test]
    fn taproot_nunchuk_descriptor_imports_and_analyzes() {
        let (a, b) = (test_key(0x31), test_key(0x32));
        let desc = format!("tr({a}/<0;1>/*,and_v(v:pk({b}/<0;1>/*),older(4032)))");
        let parsed = descriptor::import(&desc).expect("taproot descriptor imports");
        assert!(parsed.canonical.starts_with("tr("));
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| matches!(p.kind, SpendPathKind::Primary)));
        let rec = paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(4032));
    }

    #[test]
    fn seeded_policy_is_owned_by_device() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).expect("seed");
        // Exactly one signer, the device, owns a key.
        let owned = reg.signers.iter().filter(|s| s.owned_by_passport).count();
        assert_eq!(owned, 1);
        assert!(reg.signers.iter().any(|s| s.fingerprint == fp.to_string() && s.owned_by_passport));
    }

    #[test]
    fn owner_psbt_matches_and_signs_with_device_key() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "demo PSBT must match the seeded policy");
        assert_eq!(m.active_path, Some(SpendPathKind::Primary));
        assert!(m.passport_can_sign);

        // The decision gate must allow, and signing must finalize.
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Allow { path: SpendPathKind::Primary, .. }
        ));
        let master = Xpriv::new_master(DEFAULT_NETWORK, &[0x11; 32]).unwrap();
        let finalized = signing::sign_and_finalize(psbt, &master, &secp).expect("sign");
        assert!(finalized.inputs[0].final_script_witness.is_some());
    }

    #[test]
    fn register_descriptor_rejects_garbage() {
        let (secp, _, fp) = device();
        assert!(register_descriptor("definitely not a descriptor", fp, &[0x11; 32], &secp).is_err());
    }

    #[test]
    fn register_descriptor_rejects_policy_without_passport_key() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        let wrong_fp = Fingerprint::from_str("deadbeef").unwrap();
        let err = register_descriptor(&desc, wrong_fp, &[0x11; 32], &secp).unwrap_err().to_string();
        assert!(err.contains("does not contain this Passport"), "got: {err}");
    }

    // Pubkey-bound ownership: a descriptor that names Passport's fingerprint but a
    // DIFFERENT (forged) xpub is rejected, even though the 4-byte fp "matches".
    #[test]
    fn register_descriptor_rejects_forged_fingerprint_key() {
        let (secp, _xpub, fp) = device();
        // A foreign key carrying Passport's fingerprint but someone else's xpub.
        let foreign = Xpriv::new_master(DEFAULT_NETWORK, &[0xAB; 32]).unwrap();
        let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
        let foreign_xpub = Xpub::from_priv(&secp, &foreign.derive_priv(&secp, &acct).unwrap());
        let p = TEST_ACCOUNT_PATH.trim_start_matches("m/");
        let rec = Xpriv::new_master(DEFAULT_NETWORK, &[0x22; 32]).unwrap();
        let rec_xpub = Xpub::from_priv(&secp, &rec.derive_priv(&secp, &acct).unwrap());
        let rec_fp = rec.fingerprint(&secp);
        // `fp` (Passport's) is claimed, but the xpub is the foreign one.
        let desc = format!(
            "wsh(or_d(pk([{fp}/{p}]{foreign_xpub}/<0;1>/*),and_v(v:pkh([{rec_fp}/{p}]{rec_xpub}/<0;1>/*),older(52560))))"
        );
        let err = register_descriptor(&desc, fp, &[0x11; 32], &secp).unwrap_err().to_string();
        assert!(err.contains("not Passport's actual key"), "got: {err}");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();

        let dir = std::env::temp_dir().join("nunchuk-signer-test-store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_policy(&dir, &reg).expect("save");
        let store = load_policies(&dir);
        assert_eq!(store.len(), 1);
        assert!(store.find_by_checksum(&reg.descriptor_checksum).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn psbt_file_roundtrip_binary_and_base64() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).unwrap();

        let dir = std::env::temp_dir().join("nunchuk-signer-test-psbt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // binary
        let bin = dir.join("a.psbt");
        std::fs::write(&bin, psbt.serialize()).unwrap();
        assert_eq!(read_psbt_file(&bin).unwrap(), psbt);

        // base64 text
        let b64 = dir.join("b.psbt");
        std::fs::write(&b64, psbt_base64(&psbt)).unwrap();
        assert_eq!(read_psbt_file(&b64).unwrap(), psbt);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_summary_mentions_recovery_months() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let summary = policy_summary(&reg);
        assert!(summary.contains("recovery"), "got: {summary}");
        assert!(summary.contains("months"), "got: {summary}");
    }

    // -- Nunchuk 2-of-2 + policy-gate integration ---------------------------

    #[test]
    fn demo_wallet_is_miniscript_2of2_plus_recovery() {
        let (secp, _x, fp) = device();
        let reg = seed_demo_wallet(&[0x11; 32], &secp, fp, 20, false).unwrap();
        assert!(reg.descriptor.starts_with("wsh(or_d("), "got: {}", reg.descriptor);
        assert!(reg.descriptor.contains("older(20)"), "got: {}", reg.descriptor);
        // Two spend paths: a 2-of-2 primary and a timelocked recovery.
        assert_eq!(reg.paths.len(), 2);
        let primary = reg.paths.iter().find(|p| matches!(p.kind, SpendPathKind::Primary)).unwrap();
        assert_eq!((primary.threshold, primary.total_keys), (2, 2));
        let rec = reg.paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(20));
        // Device (Prime) owns a key (multisig + recovery both reference its fp).
        assert!(reg.signers.iter().any(|s| s.owned_by_passport));
    }

    #[test]
    fn recovery_path_signs_with_prime_alone_after_timelock() {
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, false).unwrap();
        let psbt = build_recovery_demo_psbt(&seed, &secp, fp, &reg, 40_000, 20).unwrap();
        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).unwrap();
        assert!(m.matched);
        assert_eq!(m.active_path, Some(SpendPathKind::Recovery), "nSequence must select recovery");
        assert!(m.passport_can_sign, "Prime owns the recovery key");
        // Recovery always demands explicit confirmation (never silent).
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Allow { requires_confirmation: true, .. }
        ));
        // Prime signs the recovery branch ALONE and it finalizes (pk + older satisfied).
        let master = master_for_network(&seed, DEFAULT_NETWORK).unwrap();
        let finalized = signing::sign_and_finalize(psbt, &master, &secp).expect("recovery finalizes");
        assert!(finalized.inputs[0].final_script_witness.is_some());
    }

    #[test]
    fn two_of_three_with_platform_key_classifies_and_prime_signs() {
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, true).unwrap();
        assert!(reg.descriptor.starts_with("wsh(or_d(multi(2,"), "got: {}", reg.descriptor);
        let primary = reg.paths.iter().find(|p| matches!(p.kind, SpendPathKind::Primary)).unwrap();
        assert_eq!((primary.threshold, primary.total_keys), (2, 3), "2-of-3 primary");
        let fps: std::collections::HashSet<_> = reg.signers.iter().map(|s| s.fingerprint.clone()).collect();
        assert_eq!(fps.len(), 3, "agent + prime + platform key");
        // Prime signs its slot; a 2-of-3 still needs one more, so not finalizable alone.
        let psbt = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).unwrap();
        assert!(m.matched && m.passport_can_sign);
        let master = master_for_network(&seed, DEFAULT_NETWORK).unwrap();
        let signed = signing::sign(psbt, &master, &secp).unwrap();
        assert!(!signed.inputs[0].partial_sigs.is_empty());
        assert!(!signing::is_finalizable(&signed, &secp), "needs agent or platform key too");
    }

    fn test_state(with_platform: bool) -> Arc<Mutex<AppState>> {
        let secp = Secp256k1::new();
        let seed = [0x11u8; 32];
        let master = Xpriv::new_master(DEFAULT_NETWORK, &seed).unwrap();
        let fp = master.fingerprint(&secp);
        let dir = std::env::temp_dir().join(format!("nunchuk-proc-{}", with_platform as u8));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut policies = store::PolicyStore::new();
        policies.add(seed_demo_wallet(&seed, &secp, fp, 20, with_platform).unwrap()).unwrap();
        Arc::new(Mutex::new(AppState {
            secp,
            seed,
            fp,
            data_dir: dir,
            policies,
            xpub_network: DEFAULT_NETWORK,
            pending: None,
            pending_import: None,
            last_signed: None,
            spend_policy: gate::SpendPolicy::default(),
            history: history::SpendHistory::new(),
            last_hsm_txid: None,
            usb_register_pending: false,
            usb_sign_pending: false,
            needs_refresh: false,
            pending_queue: std::collections::VecDeque::new(),
            signed_cache: std::collections::HashMap::new(),
            signed_cache_order: std::collections::VecDeque::new(),
            signing_in_flight: std::collections::HashSet::new(),
            safe_mode: false,
            safe_mode_reason: String::new(),
            wallet_policies: WalletPolicies::new(),
        }))
    }

    // The device-protocol dispatch (USB-CDC path) end to end on host.
    #[test]
    fn process_request_dispatches_all_ops() {
        use device_protocol::{Request, Response};
        let st = test_state(false);
        match process_request(&st, Request::Fingerprint) {
            Response::Fingerprint { fingerprint } => assert_eq!(fingerprint.len(), 8),
            o => panic!("fingerprint: {o:?}"),
        }
        match process_request(&st, Request::Xpub { path: "m/48'/1'/0'/2'".into() }) {
            Response::Key { key } => assert!(key.contains("tpub")),
            o => panic!("xpub: {o:?}"),
        }
        match process_request(&st, Request::Showaddr { index: 0, change: false }) {
            Response::Address { address } => assert!(address.starts_with("tb1"), "got: {address}"),
            o => panic!("showaddr: {o:?}"),
        }
        // In-policy sign -> Signed.
        let (fp, reg) = {
            let g = st.lock().unwrap();
            (g.fp, g.policies.all()[0].clone())
        };
        let psbt = build_demo_psbt(&[0x11; 32], &Secp256k1::new(), fp, &reg, 50_000).unwrap();
        match process_request(&st, Request::Sign { psbt: psbt_base64(&psbt) }) {
            Response::Signed { psbt } => assert!(!psbt.is_empty()),
            o => panic!("sign: {o:?}"),
        }
        // Re-signing an already-signed in-policy tx is idempotent: cached, one log row.
        let hist_before = st.lock().unwrap().history.recent(99).len();
        match process_request(&st, Request::Sign { psbt: psbt_base64(&psbt) }) {
            Response::Signed { psbt } => assert!(!psbt.is_empty()),
            o => panic!("re-sign: {o:?}"),
        }
        assert_eq!(st.lock().unwrap().history.recent(99).len(), hist_before, "no duplicate log");

        // Over-policy sign -> Pending + queued for an on-device tap (not signed).
        let big = build_demo_psbt(&[0x11; 32], &Secp256k1::new(), fp, &reg, 500_000).unwrap();
        match process_request(&st, Request::Sign { psbt: psbt_base64(&big) }) {
            Response::Pending { .. } => {}
            o => panic!("over-policy should be Pending, got {o:?}"),
        }
        assert_eq!(st.lock().unwrap().pending_queue.len(), 1, "over-policy queued");
        // Re-pushing the same over-policy PSBT does not double-queue.
        let _ = process_request(&st, Request::Sign { psbt: psbt_base64(&big) });
        assert_eq!(st.lock().unwrap().pending_queue.len(), 1, "dedup queue");
        // Register the already-known descriptor over USB -> idempotent Registered.
        match process_request(&st, Request::Register { descriptor: reg.descriptor.clone() }) {
            Response::Registered { checksum, .. } => assert_eq!(checksum, reg.descriptor_checksum),
            o => panic!("register: {o:?}"),
        }
        // Garbage descriptor -> Error, not a panic.
        match process_request(&st, Request::Register { descriptor: "not a descriptor".into() }) {
            Response::Error { .. } => {}
            o => panic!("garbage register should Error, got {o:?}"),
        }
        // Spec reports the onboarding model + recovery timelock for the agent to read.
        match process_request(&st, Request::Spec) {
            Response::Spec { model, recovery_blocks } => {
                assert!(model == "2-of-2" || model == "2-of-3", "model: {model}");
                assert!(recovery_blocks > 0, "recovery_blocks should be set");
            }
            o => panic!("spec: {o:?}"),
        }
    }

    // The deterministic agent hot key baked into `seed_demo_wallet` (seed [0x42;32]).
    // Returns (master, account-xpub) so a test can sign as the agent and attach its
    // bip32 origin — proving a real agent+Prime 2-of-2 reaches a finalizable PSBT.
    #[cfg(test)]
    fn agent_signer(secp: &Secp256k1<All>) -> (Xpriv, Xpub) {
        let network = DEFAULT_NETWORK;
        let master = Xpriv::new_master(network, &[0x42; 32]).unwrap();
        let acct = DerivationPath::from_str(account_path(network)).unwrap();
        let xpub = Xpub::from_priv(secp, &master.derive_priv(secp, &acct).unwrap());
        (master, xpub)
    }

    // Attach the agent's index-0 origin to a PSBT input so the agent can sign it.
    #[cfg(test)]
    fn add_agent_derivation(psbt: &mut Psbt, secp: &Secp256k1<All>) {
        let (master, acct_xpub) = agent_signer(secp);
        let fp = master.fingerprint(secp);
        let child = DerivationPath::from_str("m/0/0").unwrap();
        let pk = PublicKey::new(acct_xpub.derive_pub(secp, &child).unwrap().public_key);
        let full = DerivationPath::from_str(&format!("{}/0/0", account_path(DEFAULT_NETWORK))).unwrap();
        psbt.inputs[0].bip32_derivation.insert(pk.inner, (fp, full));
    }

    // Outflow hardening: an output on the wallet's CHANGE branch is excluded (real
    // change), but a self-send to the wallet's own RECEIVE address is counted as
    // outflow — so it can't be used to understate the figure the velocity caps meter.
    #[test]
    fn outflow_excludes_change_branch_but_counts_receive_self_send() {
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, false).unwrap();
        let parsed = descriptor::import(&reg.descriptor).unwrap();
        let singles = parsed.descriptor.into_single_descriptors().unwrap();
        let recv0 = singles[0].at_derivation_index(0).unwrap();
        let change0 = singles[1].at_derivation_index(0).unwrap();
        let in_spk = recv0.script_pubkey();
        let ws = recv0.explicit_script().unwrap();

        let master = master_for_network(&seed, DEFAULT_NETWORK).unwrap();
        let acct = DerivationPath::from_str(account_path(DEFAULT_NETWORK)).unwrap();
        let acct_xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct).unwrap());
        let dev_pk =
            PublicKey::new(acct_xpub.derive_pub(&secp, &DerivationPath::from_str("m/0/0").unwrap()).unwrap().public_key);
        let full = DerivationPath::from_str(&format!("{}/0/0", account_path(DEFAULT_NETWORK))).unwrap();
        let dead = ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap();

        let build = |second_spk: ScriptBuf| -> Psbt {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![
                    TxOut { value: Amount::from_sat(50_000), script_pubkey: dead.clone() },
                    TxOut { value: Amount::from_sat(149_700), script_pubkey: second_spk },
                ],
            };
            let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
            let mut input = Input {
                witness_utxo: Some(TxOut { value: Amount::from_sat(200_000), script_pubkey: in_spk.clone() }),
                witness_script: Some(ws.clone()),
                ..Default::default()
            };
            input.bip32_derivation.insert(dev_pk.inner, (fp, full.clone()));
            psbt.inputs[0] = input;
            psbt
        };

        // Change-branch output excluded -> outflow = external payment + fee.
        let with_change = build(change0.script_pubkey());
        assert_eq!(lpsbt::outflow_sats(&with_change, &reg, GAP).unwrap(), 50_300);
        // Receive-address self-send is NOT treated as change -> full input metered.
        let with_recv = build(recv0.script_pubkey());
        assert_eq!(lpsbt::outflow_sats(&with_recv, &reg, GAP).unwrap(), 200_000);
    }

    // Self-custodied 2-of-2 end to end: the agent signs its hot key, routes the PSBT
    // to Prime over the device protocol, and (under policy) Prime auto-signs with NO
    // human present. The result must carry BOTH signatures and finalize — the proof
    // that agent + Prime alone satisfies the wallet. Over policy, Prime instead holds
    // it for a tap.
    #[test]
    fn two_of_two_agent_plus_prime_finalizes_under_policy_taps_over() {
        use base64::Engine;
        use device_protocol::{Request, Response};
        let st = test_state(false); // self-custodied 2-of-2 (no Platform Key)
        let (seed, fp, reg) = {
            let g = st.lock().unwrap();
            (g.seed, g.fp, g.policies.all()[0].clone())
        };
        let secp = Secp256k1::new();

        // --- Under policy: agent signs, Prime auto-signs, 2-of-2 finalizes. ---
        let mut psbt = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        add_agent_derivation(&mut psbt, &secp);
        let (agent_master, _) = agent_signer(&secp);
        let agent_signed = signing::sign(psbt, &agent_master, &secp).unwrap();
        assert_eq!(agent_signed.inputs[0].partial_sigs.len(), 1, "agent contributes one sig");
        assert!(!signing::is_finalizable(&agent_signed, &secp), "one of two is not enough");

        let resp = process_request(&st, Request::Sign { psbt: psbt_base64(&agent_signed) });
        let both = match resp {
            Response::Signed { psbt } => {
                let raw = base64::engine::general_purpose::STANDARD.decode(psbt).unwrap();
                Psbt::deserialize(&raw).unwrap()
            }
            o => panic!("under-policy 2-of-2 must auto-sign unattended, got {o:?}"),
        };
        assert_eq!(both.inputs[0].partial_sigs.len(), 2, "agent + Prime signatures present");
        assert!(signing::is_finalizable(&both, &secp), "agent + Prime finalizes the 2-of-2");
        {
            let g = st.lock().unwrap();
            assert_eq!(g.history.recent(1)[0].kind, history::SignKind::Auto, "logged as unattended auto-sign");
            assert!(g.pending.is_none() && g.pending_queue.is_empty(), "no approval surfaced for an in-policy spend");
        }

        // --- Over policy: routed to Prime for a human tap (NOT auto-signed). ---
        let mut big = build_demo_psbt(&seed, &secp, fp, &reg, 500_000).unwrap();
        add_agent_derivation(&mut big, &secp);
        let big_signed = signing::sign(big, &agent_master, &secp).unwrap();
        match process_request(&st, Request::Sign { psbt: psbt_base64(&big_signed) }) {
            Response::Pending { .. } => {}
            o => panic!("over-policy 2-of-2 must require a tap, got {o:?}"),
        }
        assert_eq!(st.lock().unwrap().pending_queue.len(), 1, "over-policy spend queued for approval");
    }

    // nunchuk-cli builds the Prime-alone recovery branch as a SECOND Prime account
    // (acct 1' for the recovery leg) instead of reusing one xpub on a multipath leg,
    // because the CLI rejects a reused key. This proves Prime parses + registers that
    // two-account form, recognises BOTH of its accounts as its own (ownership is by
    // fingerprint), sees the recovery path, and still auto-signs the everyday leg
    // (agent + Prime) under policy. Signing the recovery LEG itself (acct 1') is a
    // separate on-device step; here we prove the everyday lane the demo uses.
    #[test]
    fn two_account_recovery_descriptor_registers_and_signs_everyday_leg() {
        use base64::Engine;
        use device_protocol::{Request, Response};
        let secp = Secp256k1::new();
        let seed = [0x11u8; 32];
        let network = DEFAULT_NETWORK;
        let fp = Xpriv::new_master(network, &seed).unwrap().fingerprint(&secp);

        // Prime's two accounts: acct 0' everyday (multi leg), acct 1' recovery leg.
        let prime0 = key_with_origin(&seed, &secp, fp, network).unwrap(); // m/48'/1'/0'/2'
        let prime1 = xpub_with_origin_at(&seed, &secp, fp, network, "m/48'/1'/1'/2'").unwrap();
        // The agent's hot key, built to match agent_signer/add_agent_derivation.
        let (agent_master, agent_xpub) = agent_signer(&secp);
        let agent_key = format!(
            "[{}/{}]{}",
            agent_master.fingerprint(&secp),
            account_path(network).trim_start_matches("m/"),
            agent_xpub
        );

        let recovery_blocks = 4320u32;
        let desc = format!(
            "wsh(or_d(multi(2,{agent_key}/<0;1>/*,{prime0}/<0;1>/*),and_v(v:pk({prime1}/<0;1>/*),older({recovery_blocks}))))"
        );
        let parsed = descriptor::import(&desc).expect("two-account recovery descriptor parses");
        let reg = policy::build_registered_policy(
            parsed.checksum.clone(),
            "Recovery 2-of-2",
            network_label(network),
            &parsed,
            fp,
        )
        .unwrap();

        // Prime recognises BOTH its accounts (same fingerprint) as its own; agent is not.
        assert_eq!(
            reg.signers.iter().filter(|s| s.owned_by_passport).count(),
            2,
            "both Prime accounts owned: {:?}",
            reg.signers
        );
        assert!(reg.signers.iter().any(|s| !s.owned_by_passport), "agent key is external");
        // A primary (no timelock) path and a recovery (older=N) path.
        assert!(
            reg.paths.iter().any(|p| p.kind == SpendPathKind::Primary && p.relative_timelock_blocks.is_none()),
            "primary path present: {:?}",
            reg.paths
        );
        assert!(
            reg.paths
                .iter()
                .any(|p| p.kind == SpendPathKind::Recovery && p.relative_timelock_blocks == Some(recovery_blocks)),
            "recovery path with older({recovery_blocks}): {:?}",
            reg.paths
        );

        // Everyday lane: agent signs, route to Prime, Prime auto-signs under policy.
        let mut policies = store::PolicyStore::new();
        policies.add(reg.clone()).unwrap();
        let dir = std::env::temp_dir().join("nunchuk-two-acct-recovery");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let st = Arc::new(Mutex::new(AppState {
            secp: Secp256k1::new(),
            seed,
            fp,
            data_dir: dir,
            policies,
            xpub_network: network,
            pending: None,
            pending_import: None,
            last_signed: None,
            spend_policy: gate::SpendPolicy::default(),
            history: history::SpendHistory::new(),
            last_hsm_txid: None,
            usb_register_pending: false,
            usb_sign_pending: false,
            needs_refresh: false,
            pending_queue: std::collections::VecDeque::new(),
            signed_cache: std::collections::HashMap::new(),
            signed_cache_order: std::collections::VecDeque::new(),
            signing_in_flight: std::collections::HashSet::new(),
            safe_mode: false,
            safe_mode_reason: String::new(),
            wallet_policies: WalletPolicies::new(),
        }));

        let mut psbt = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        add_agent_derivation(&mut psbt, &secp);
        let agent_signed = signing::sign(psbt, &agent_master, &secp).unwrap();
        match process_request(&st, Request::Sign { psbt: psbt_base64(&agent_signed) }) {
            Response::Signed { psbt } => {
                let raw = base64::engine::general_purpose::STANDARD.decode(psbt).unwrap();
                let both = Psbt::deserialize(&raw).unwrap();
                assert_eq!(both.inputs[0].partial_sigs.len(), 2, "agent + Prime signatures present");
                assert!(signing::is_finalizable(&both, &secp), "agent + Prime finalizes the everyday leg");
            }
            o => panic!("everyday leg of the two-account recovery wallet should auto-sign, got {o:?}"),
        }
    }

    // Velocity: each spend is under the per-tx ceiling, but their rolling sum crosses
    // the daily cap — at which point Prime stops auto-signing and demands a tap. Proves
    // the gate meters cumulative outflow, not just single-tx size.
    #[test]
    fn two_of_two_velocity_cap_trips_on_cumulative_small_spends() {
        use device_protocol::{Request, Response};
        let st = test_state(false);
        // Tight daily cap; each tx stays under the 100k per-tx ceiling.
        st.lock().unwrap().spend_policy.daily_cap_sats = Some(120_000);
        let (seed, fp, reg) = {
            let g = st.lock().unwrap();
            (g.seed, g.fp, g.policies.all()[0].clone())
        };
        let secp = Secp256k1::new();
        let push = |amount: u64| -> Response {
            let mut p = build_demo_psbt(&seed, &secp, fp, &reg, amount).unwrap();
            add_agent_derivation(&mut p, &secp);
            let (agent_master, _) = agent_signer(&secp);
            let signed = signing::sign(p, &agent_master, &secp).unwrap();
            process_request(&st, Request::Sign { psbt: psbt_base64(&signed) })
        };
        // ~51k each: two auto-sign (102k cumulative), the third crosses 120k -> tap.
        assert!(matches!(push(50_000), Response::Signed { .. }), "1st in-policy");
        assert!(matches!(push(50_001), Response::Signed { .. }), "2nd in-policy");
        match push(50_002) {
            Response::Pending { .. } => {}
            o => panic!("3rd should trip the daily cap and require a tap, got {o:?}"),
        }
    }

    // Phantom-approval guard: while a PSBT is being signed off-thread (in `signing_in_flight`),
    // a host re-sending the same over-policy PSBT must NOT queue a second approval.
    #[test]
    fn over_policy_resend_while_signing_does_not_double_queue() {
        use device_protocol::{Request, Response};
        let st = test_state(false);
        let (fp, reg) = {
            let g = st.lock().unwrap();
            (g.fp, g.policies.all()[0].clone())
        };
        let big = build_demo_psbt(&[0x11; 32], &Secp256k1::new(), fp, &reg, 500_000).unwrap();
        let txid = big.unsigned_tx.compute_txid().to_string();
        st.lock().unwrap().signing_in_flight.insert(txid.clone()); // pretend on_approve is mid-sign
        match process_request(&st, Request::Sign { psbt: psbt_base64(&big) }) {
            Response::Pending { .. } => {}
            o => panic!("expected Pending, got {o:?}"),
        }
        assert!(st.lock().unwrap().pending_queue.is_empty(), "in-flight txid must not re-queue");
    }

    // Log dedup must scan the whole ledger, not just the last 200 rows.
    #[test]
    fn log_dedupes_against_full_ledger() {
        use device_protocol::Request;
        let st = test_state(false);
        {
            let mut g = st.lock().unwrap();
            for i in 0..250u64 {
                g.history.record(history::SpendRecord {
                    unix_time: i, amount_sats: 1, dest: "d".into(),
                    kind: history::SignKind::External, txid: format!("old{i}"), wallet: String::new(), wallet_id: String::new(),
                });
            }
        }
        let before = st.lock().unwrap().history.len();
        let _ = process_request(&st, Request::Log { amount_sats: 1, dest: "d".into(), txid: "old0".into(), wallet: String::new() });
        assert_eq!(st.lock().unwrap().history.len(), before, "txid older than recent(200) still deduped");
    }

    // signed_cache is bounded: oldest entries evict, newest survive.
    #[test]
    fn signed_cache_is_bounded() {
        let st = test_state(false);
        let mut g = st.lock().unwrap();
        for i in 0..(SIGNED_CACHE_MAX + 50) {
            g.cache_signed(format!("tx{i}"), vec![0u8; 4]);
        }
        assert!(g.signed_cache.len() <= SIGNED_CACHE_MAX, "cache stays bounded");
        assert_eq!(g.signed_cache.len(), g.signed_cache_order.len(), "map + order stay in sync");
        assert!(!g.signed_cache.contains_key("tx0"), "oldest evicted");
        assert!(g.signed_cache.contains_key(&format!("tx{}", SIGNED_CACHE_MAX + 49)), "newest kept");
    }

    #[test]
    fn xpub_at_arbitrary_path_has_origin() {
        let (secp, _x, fp) = device();
        let k48 = xpub_with_origin_at(&[0x11; 32], &secp, fp, Network::Testnet, "m/48'/1'/0'/2'").unwrap();
        assert!(k48.starts_with(&format!("[{fp}/48'/1'/0'/2']")), "got: {k48}");
        assert!(k48.contains("tpub"));
        let k84 = xpub_with_origin_at(&[0x11; 32], &secp, fp, Network::Testnet, "m/84'/1'/0'").unwrap();
        assert!(k84.starts_with(&format!("[{fp}/84'/1'/0']")), "got: {k84}");
        assert_ne!(k48, k84, "different paths -> different xpubs");
    }

    #[test]
    fn real_nunchuk_2of3_platform_key_descriptor_parses() {
        // The ACTUAL descriptor exported by nunchuk-cli for a live testnet 2-of-3
        // (agent + Prime + Nunchuk Platform Key). Proves Prime accepts a real
        // platform-key wallet, classifies it 2-of-3, owns its key, sees the platform key.
        const REAL: &str = "wsh(sortedmulti(2,[de5f4c5b/48'/1'/0'/2']tpubDFCuyzXNagyBMGbqvKPH5muPme1xFXsBcHNv7jpGRRrutruLPBxqEZqoBRF8Kg8YfyQjBAYRkpNtd3DQDKYX9oRDRvYEUGHoouBoN6GtoZv/0/*,[d38570d3/48'/1'/0'/2']tpubDFNDEDKr1VRp71vEtgdn3QD4zgUHzoGNyq5yXBYoodXeKuwdK2vxaoTUcuCChc94hb3yhmosXe3FaF88zxSZjXRdj12BP784JCZRrJTDX8L/0/*,[ecfed4c1/48'/1'/197'/2']tpubDEq5UeAAAPSFSDxk7tfMQ6uoegUrp8WNY5WpZCPtoj1kw3M23t1M9z12d4fkhre2PdHqHfzU3SfvHeYozY1SUEAASvzJ9qcPuxfwcpD3NZC/0/*))#w89kvwwv";
        let parsed = descriptor::import(REAL).expect("real nunchuk 2-of-3 imports");
        assert_eq!(parsed.checksum, "w89kvwwv");
        let prime = Fingerprint::from_str("d38570d3").unwrap();
        let reg = policy::build_registered_policy("real", "Agent Wallet", "testnet", &parsed, prime).unwrap();
        assert_eq!(reg.paths.len(), 1, "single 2-of-3 primary path");
        assert_eq!((reg.paths[0].threshold, reg.paths[0].total_keys), (2, 3));
        assert_eq!(reg.signers.len(), 3, "agent + prime + platform key");
        assert!(reg.signers.iter().any(|x| x.fingerprint == "d38570d3" && x.owned_by_passport), "Prime owns its slot");
        assert!(reg.signers.iter().any(|x| x.fingerprint == "ecfed4c1"), "Nunchuk Platform Key present");
    }

    #[test]
    fn primary_path_still_needs_both_keys() {
        // A primary-path PSBT (no recovery nSequence) classifies as Primary and the
        // device's single signature does NOT finalize a 2-of-2.
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, false).unwrap();
        let psbt = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).unwrap();
        assert_eq!(m.active_path, Some(SpendPathKind::Primary));
        let master = master_for_network(&seed, DEFAULT_NETWORK).unwrap();
        let signed = signing::sign(psbt, &master, &secp).unwrap();
        assert!(!signing::is_finalizable(&signed, &secp), "2-of-2 needs the agent sig too");
    }

    #[test]
    fn demo_psbt_matches_and_device_signs_as_member() {
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, false).unwrap();
        let psbt = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).unwrap();
        assert!(m.matched && m.passport_can_sign);
        assert_eq!(lpsbt::outflow_sats(&psbt, &reg, GAP).unwrap(), 51_000);
        let master = master_for_network(&seed, DEFAULT_NETWORK).unwrap();
        let signed = signing::sign(psbt, &master, &secp).unwrap();
        // 2-of-2: the device adds exactly its own partial signature (not final).
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn gate_auto_signs_small_requires_tap_large() {
        let (secp, _x, fp) = device();
        let seed = [0x11; 32];
        let reg = seed_demo_wallet(&seed, &secp, fp, 20, false).unwrap();
        let pol = gate::SpendPolicy::default(); // per-tx 100k
        let hist = history::SpendHistory::new();
        let small = build_demo_psbt(&seed, &secp, fp, &reg, 50_000).unwrap();
        let of = lpsbt::outflow_sats(&small, &reg, GAP).unwrap();
        assert_eq!(gate::decide(&pol, &hist, of, 1_000_000), gate::Decision::AutoSign);
        let large = build_demo_psbt(&seed, &secp, fp, &reg, 200_000).unwrap();
        let ofl = lpsbt::outflow_sats(&large, &reg, GAP).unwrap();
        assert!(gate::decide(&pol, &hist, ofl, 1_000_000).requires_approval());
    }
}
