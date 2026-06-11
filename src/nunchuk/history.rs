// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! history.rs — append-only spend ledger.
//!
//! Powers two things:
//!  1. **Velocity caps** — sum of outflow inside a rolling time window.
//!  2. **Activity log** — the user's audit trail of every autonomous/approved sign.
//!
//! Security rule (see plan, "Velocity enforcement & the clock problem"): the debit
//! is recorded *before* the signature is released, so a power-cycle after signing
//! cannot erase the debit and reset the budget. Records carry the *signed* outflow
//! (payment + fee), not the confirmed amount — the device has no chain view.

use serde::{Deserialize, Serialize};

/// Whether a spend was auto-signed within policy or required a physical approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignKind {
    /// Under policy — Prime signed with no human interaction (2-of-2 / sovereign).
    Auto,
    /// Over a cap — the user physically approved it on the device.
    Approved,
    /// Signed by the agent + Nunchuk Platform Key (Prime not involved); reported to
    /// Prime by the agent so it shows in the ledger. The "without you" everyday lane.
    External,
    /// A spend that surfaced for approval and the user DECLINED (or deferred) on the
    /// device. Nothing was signed. Recorded for the audit trail — "the agent tried
    /// this and I said no" — and excluded from the velocity budget (no funds moved).
    Declined,
}

/// One entry in the ledger: a single signed transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendRecord {
    /// Wall-clock at signing, seconds since epoch. `0` when no trusted clock was
    /// available (the record is then counted conservatively in every window).
    pub unix_time: u64,
    /// Net outflow that left the wallet's control: payment + miner fee, in sats.
    pub amount_sats: u64,
    /// Primary destination address (for the activity log; display only).
    pub dest: String,
    /// Auto-signed within policy, or physically approved.
    pub kind: SignKind,
    /// The unsigned-tx txid at signing time (identifies the record).
    pub txid: String,
    /// Which registered wallet this spend was for (display name). Lets the activity
    /// log disambiguate when several wallets are enrolled. Empty for older records
    /// and for agent-reported spends that don't name a wallet.
    #[serde(default)]
    pub wallet: String,
    /// Stable wallet id (descriptor checksum) this spend was for. Drives per-wallet
    /// velocity budgets (a name can be renamed; the checksum can't). Empty for
    /// older records and agent-reported spends; those fall outside per-wallet sums.
    #[serde(default)]
    pub wallet_id: String,
}

/// The on-device spend ledger. Persisted to `history.json` in app data.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendHistory {
    pub records: Vec<SpendRecord>,
    /// Index into `records` marking the start of the current power-on session.
    /// Set to `records.len()` at boot. Powers the clock-free session cap.
    #[serde(default)]
    pub session_start: usize,
}

impl SpendHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the start of a power-on session (call at boot, after load).
    pub fn begin_session(&mut self) {
        self.session_start = self.records.len();
    }

    /// Append a record. The caller MUST persist before releasing the signature.
    /// Drop duplicate-txid records (keep the first), repairing ledgers written before
    /// idempotent signing landed. Order-preserving.
    pub fn dedup_by_txid(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.records.retain(|r| {
            // Never dedup Declined rows: an attempt can be declined once and later
            // (re-pushed) approved, and BOTH belong in the audit trail despite sharing
            // the unsigned-tx txid. Only the signed kinds are deduped.
            if matches!(r.kind, SignKind::Declined) {
                return true;
            }
            seen.insert(r.txid.clone())
        });
    }

    pub fn record(&mut self, r: SpendRecord) {
        self.records.push(r);
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Does this record count toward the ENFORCEMENT caps? `External` (agent +
    /// Platform Key, self-reported over the wire with no device signature) does
    /// NOT: it's unverified and the 2-of-3 external lane is enforced server-side by
    /// Nunchuk, so counting it would let a host pollute Prime's budget. It still
    /// shows in the activity log (display), just not in the cap math.
    fn enforced(r: &SpendRecord) -> bool {
        // External (unverified, server-enforced) and Declined (nothing signed) are
        // audit-log entries only; they never count toward the enforcement caps.
        !matches!(r.kind, SignKind::External | SignKind::Declined)
    }

    /// Total enforced outflow ever recorded (clock-free; powers the lifetime cap).
    pub fn total(&self) -> u64 {
        self.records.iter().filter(|r| Self::enforced(r)).map(|r| r.amount_sats).sum()
    }

    /// Enforced outflow recorded in the current power-on session (clock-free;
    /// powers the session cap — holds even if the clock is spoofed).
    pub fn spent_this_session(&self) -> u64 {
        self.records
            .iter()
            .skip(self.session_start.min(self.records.len()))
            .filter(|r| Self::enforced(r))
            .map(|r| r.amount_sats)
            .sum()
    }

    /// Enforced outflow recorded inside `[now - window_secs, now]`. Records with an
    /// unknown clock (`unix_time == 0`) are counted unconditionally — the
    /// conservative (safe) direction: an attacker who suppresses timestamps cannot
    /// also hide the spend from the window total.
    pub fn spent_in_window(&self, now: u64, window_secs: u64) -> u64 {
        let cutoff = now.saturating_sub(window_secs);
        self.records
            .iter()
            .filter(|r| Self::enforced(r))
            .filter(|r| r.unix_time == 0 || r.unix_time >= cutoff)
            .map(|r| r.amount_sats)
            .sum()
    }

    /// The most recent `n` records, newest first (for the activity screen).
    pub fn recent(&self, n: usize) -> Vec<&SpendRecord> {
        self.records.iter().rev().take(n).collect()
    }

    /// Whether a txid is already in the ledger (full scan — used to dedupe
    /// agent-reported `Log` spends regardless of how old the prior row is).
    pub fn has_txid(&self, txid: &str) -> bool {
        self.records.iter().any(|r| r.txid == txid)
    }

    /// A view of this ledger containing only records for `wallet_id`, with the
    /// session boundary re-mapped into the filtered vector. Passing this to the
    /// gate gives a PER-WALLET velocity budget with zero changes to the gate: a
    /// runaway agent on one wallet can't consume another wallet's budget. The
    /// session cap stays meaningful because `session_start` is recomputed as the
    /// count of this wallet's records that predate the global session boundary.
    pub fn for_wallet(&self, wallet_id: &str) -> SpendHistory {
        let mut records = Vec::new();
        let mut session_start = 0usize;
        for (i, r) in self.records.iter().enumerate() {
            if r.wallet_id != wallet_id {
                continue;
            }
            if i < self.session_start {
                session_start += 1;
            }
            records.push(r.clone());
        }
        SpendHistory { records, session_start }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(t: u64, amt: u64, kind: SignKind) -> SpendRecord {
        SpendRecord { unix_time: t, amount_sats: amt, dest: "tb1qdest".into(), kind, txid: format!("tx{t}"), wallet: String::new(), wallet_id: String::new() }
    }

    #[test]
    fn total_and_lifetime() {
        let mut h = SpendHistory::new();
        h.record(rec(100, 10_000, SignKind::Auto));
        h.record(rec(200, 5_000, SignKind::Approved));
        assert_eq!(h.total(), 15_000);
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn session_is_clock_free() {
        let mut h = SpendHistory::new();
        h.record(rec(0, 10_000, SignKind::Auto)); // pre-existing
        h.begin_session(); // session starts here
        assert_eq!(h.spent_this_session(), 0);
        h.record(rec(0, 7_000, SignKind::Auto));
        h.record(rec(0, 3_000, SignKind::Auto));
        assert_eq!(h.spent_this_session(), 10_000);
        // Lifetime still counts everything.
        assert_eq!(h.total(), 20_000);
    }

    #[test]
    fn rolling_window_excludes_old() {
        let mut h = SpendHistory::new();
        h.record(rec(1_000, 50_000, SignKind::Auto)); // old
        h.record(rec(90_000, 8_000, SignKind::Auto)); // within last day of now=100_000
        let day = 86_400;
        assert_eq!(h.spent_in_window(100_000, day), 8_000);
        // A week window catches both.
        assert_eq!(h.spent_in_window(100_000, 604_800), 58_000);
    }

    #[test]
    fn unknown_clock_records_count_conservatively() {
        let mut h = SpendHistory::new();
        h.record(rec(0, 12_000, SignKind::Auto)); // clock unknown
        // Even with a tiny window, the no-clock record is counted.
        assert_eq!(h.spent_in_window(1_000_000, 60), 12_000);
    }

    fn rec_w(t: u64, amt: u64, kind: SignKind, wid: &str) -> SpendRecord {
        SpendRecord { unix_time: t, amount_sats: amt, dest: "d".into(), kind, txid: format!("tx{t}"), wallet: String::new(), wallet_id: wid.into() }
    }

    // External (agent + Platform Key, self-reported) must NOT count toward the
    // enforcement caps, or a host could pollute Prime's budget.
    #[test]
    fn external_excluded_from_enforcement_sums() {
        let mut h = SpendHistory::new();
        h.record(rec(100, 50_000, SignKind::Auto));
        h.record(rec(200, 70_000, SignKind::External));
        assert_eq!(h.total(), 50_000, "External not counted in lifetime");
        // now=300 so both records (t=100, t=200) fall inside the window.
        assert_eq!(h.spent_in_window(300, 604_800), 50_000, "External not in window");
    }

    // Declined (the user said no) is audit-only: never in the enforcement caps.
    #[test]
    fn declined_excluded_from_enforcement_sums() {
        let mut h = SpendHistory::new();
        h.record(rec(100, 50_000, SignKind::Auto));
        h.record(rec(200, 90_000, SignKind::Declined));
        assert_eq!(h.total(), 50_000, "Declined not counted");
    }

    // A declined attempt and a later-approved spend can share the unsigned-tx txid;
    // dedup must keep BOTH (the decline is part of the audit trail).
    #[test]
    fn dedup_keeps_declined_alongside_signed_same_txid() {
        let mut h = SpendHistory::new();
        h.record(rec_w(1, 10, SignKind::Declined, ""));
        let mut signed = rec_w(2, 10, SignKind::Approved, "");
        signed.txid = "tx1".into(); // same txid as the declined record
        h.record(signed);
        h.dedup_by_txid();
        assert_eq!(h.len(), 2, "declined + approved with the same txid both survive");
    }

    // Per-wallet view: only this wallet's records, with the session boundary
    // re-mapped so the session cap stays per-wallet.
    #[test]
    fn for_wallet_filters_and_keeps_session() {
        let mut h = SpendHistory::new();
        h.record(rec_w(1, 10_000, SignKind::Auto, "A"));
        h.record(rec_w(2, 20_000, SignKind::Auto, "B"));
        h.begin_session(); // session starts after the first two records
        h.record(rec_w(3, 5_000, SignKind::Auto, "A"));
        let a = h.for_wallet("A");
        assert_eq!(a.total(), 15_000, "both A records");
        assert_eq!(a.spent_this_session(), 5_000, "only the post-session A record");
        let b = h.for_wallet("B");
        assert_eq!(b.total(), 20_000);
        assert_eq!(b.spent_this_session(), 0, "B's only spend predates the session");
    }

    #[test]
    fn recent_is_newest_first() {
        let mut h = SpendHistory::new();
        h.record(rec(1, 1, SignKind::Auto));
        h.record(rec(2, 2, SignKind::Auto));
        h.record(rec(3, 3, SignKind::Auto));
        let r = h.recent(2);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].txid, "tx3");
        assert_eq!(r[1].txid, "tx2");
    }
}
