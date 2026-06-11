// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! gate.rs — the spending-policy gate. THIS is the self-custodied "Platform Key".
//!
//! A 2-of-2 stops key theft (Prime's signature is always required), but it does
//! NOT bound loss on its own: a compromised host can keep submitting under-limit
//! PSBTs and Prime would auto-sign them. So the velocity caps — not the 2-of-2 —
//! are the real limiter on an automated drain. This module is where Prime decides,
//! per PSBT, whether to release its signature silently or demand a physical tap.
//!
//! Decision: `AutoSign` when the spend is within EVERY configured cap; otherwise
//! `RequireApproval` (a human tap overrides). Time-window caps (daily/weekly) need
//! a trusted clock; the session + lifetime caps are clock-free and hold even if a
//! compromised host fast-forwards the clock. See the plan's
//! "Velocity enforcement & the clock problem".

use serde::{Deserialize, Serialize};

use super::history::SpendHistory;

pub const DAY_SECS: u64 = 86_400;
pub const WEEK_SECS: u64 = 604_800;

/// How Prime knows "now" — determines whether the time-window caps are trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Clock {
    /// Battery-backed RTC: trustworthy wall-clock. Time-window caps are sound.
    Rtc,
    /// Host-supplied time, guarded monotonic. Rejects rewind; cannot stop a
    /// fast-forward. Time-window caps are best-effort; lean on the clock-free caps.
    HostTimeMonotonic,
    /// No trusted clock. Time-window caps are disabled; only the clock-free
    /// session + lifetime caps apply.
    None,
}

impl Clock {
    /// Are wall-clock (daily/weekly) caps trustworthy enough to enforce?
    pub fn time_caps_enforceable(self) -> bool {
        matches!(self, Clock::Rtc | Clock::HostTimeMonotonic)
    }
}

/// The on-device spending policy. Persisted to `policy.json`. All amounts in sats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendPolicy {
    /// Largest single transaction Prime will auto-sign. Always enforced.
    pub per_tx_limit_sats: u64,
    /// Rolling 24h cumulative cap (needs a clock).
    pub daily_cap_sats: Option<u64>,
    /// Rolling 7d cumulative cap (needs a clock).
    pub weekly_cap_sats: Option<u64>,
    /// Per power-on session cumulative cap. Clock-free backstop.
    pub session_cap_sats: Option<u64>,
    /// Absolute lifetime cumulative cap. Clock-free hard floor an attacker
    /// cannot fast-forward past.
    pub lifetime_cap_sats: Option<u64>,
    /// How "now" is sourced (gates whether daily/weekly are enforced).
    pub clock: Clock,
    /// Recovery branch relative timelock, in blocks. Baked into the wallet
    /// descriptor at creation: after this many blocks since a coin confirmed,
    /// Prime can recover that coin ALONE if the agent key is gone. User-set.
    #[serde(default = "default_recovery_blocks")]
    pub recovery_blocks: u32,
    /// Wallet model chosen at onboarding: false = self-custodied 2-of-2
    /// (agent + Prime-HSM); true = 2-of-3 adding the Nunchuk Platform Key.
    #[serde(default)]
    pub with_platform_key: bool,
    /// HSM mode: when on, Prime auto-signs in-policy PSBTs dropped on the host
    /// bridge with no human present (unattended). Over-policy still needs approval.
    #[serde(default = "default_true")]
    pub hsm_enabled: bool,
    /// User "freeze" switch. When true, auto-signing is paused and EVERY spend is
    /// forced to an on-device approval, regardless of caps. Survives reboot (it's
    /// part of the persisted policy). The deliberate kill-switch for a suspected-
    /// compromised agent, separate from the corruption-triggered safe mode.
    #[serde(default)]
    pub frozen: bool,
    /// Destination allowlist (addresses). When non-empty, an auto-sign requires
    /// EVERY non-change output to be on this list; a spend to any other address is
    /// forced to an on-device approval. Empty = no destination restriction. This
    /// bounds WHERE the agent can move funds, not just how much - the highest-value
    /// guard for an autonomous agent (a drain to an attacker address needs a tap).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Default recovery timelock (blocks). Short so the POC can be exercised on Signet;
/// a real wallet would use months/year. ~144 blocks/day.
pub fn default_recovery_blocks() -> u32 {
    4320 // ~30 days: long enough that normal agent activity never matures it, short
         // enough to recover within a month if the agent key is lost.
}

impl Default for SpendPolicy {
    /// A conservative POC default: 100k/tx, 500k/day, 1M/week, 2M/session, and a
    /// 10M-sat LIFETIME ceiling. The lifetime cap is the clock-free, persisted,
    /// power-survivable backstop (`history.json` is crash-safe and `total()` sums
    /// it), so even a host that controls power + clock cannot drain past it without
    /// a physical approval. Clock defaults to host-time on the sim; the device
    /// downgrades it to `None` at boot (no RTC), enforcing session + lifetime only.
    fn default() -> Self {
        Self {
            per_tx_limit_sats: 100_000,
            daily_cap_sats: Some(500_000),
            weekly_cap_sats: Some(1_000_000),
            session_cap_sats: Some(2_000_000),
            lifetime_cap_sats: Some(10_000_000),
            clock: Clock::HostTimeMonotonic,
            recovery_blocks: default_recovery_blocks(),
            with_platform_key: false,
            hsm_enabled: true,
            frozen: false,
            allowlist: Vec::new(),
        }
    }
}

/// Which cap a decision tripped (for the review screen + activity reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapKind {
    PerTx,
    Daily,
    Weekly,
    Session,
    Lifetime,
}

impl CapKind {
    pub fn label(self) -> &'static str {
        match self {
            CapKind::PerTx => "per-transaction limit",
            CapKind::Daily => "daily velocity cap",
            CapKind::Weekly => "weekly velocity cap",
            CapKind::Session => "session cap",
            CapKind::Lifetime => "lifetime cap",
        }
    }
}

/// The gate's verdict for one PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Within every configured cap — sign with no human interaction.
    AutoSign,
    /// One or more caps exceeded — a physical approval on the device is required.
    /// Carries the binding cap (the first/most-restrictive one tripped) + a reason.
    RequireApproval { cap: CapKind, reason: String },
}

impl Decision {
    pub fn requires_approval(&self) -> bool {
        matches!(self, Decision::RequireApproval { .. })
    }
}

/// Decide whether `amount_sats` (net outflow + fee) may be auto-signed under
/// `policy`, given `history` and the current time `now` (epoch secs; ignored when
/// the clock is untrusted). Returns the binding cap if approval is needed.
pub fn decide(policy: &SpendPolicy, history: &SpendHistory, amount_sats: u64, now: u64) -> Decision {
    // Per-tx is always enforced (no clock needed).
    if amount_sats > policy.per_tx_limit_sats {
        return approval(
            CapKind::PerTx,
            amount_sats,
            policy.per_tx_limit_sats,
            "this transaction alone exceeds the per-transaction limit",
        );
    }

    // Time-window caps: only when the clock is trustworthy.
    if policy.clock.time_caps_enforceable() {
        if let Some(cap) = policy.daily_cap_sats {
            let spent = history.spent_in_window(now, DAY_SECS);
            if spent.saturating_add(amount_sats) > cap {
                return approval(CapKind::Daily, spent + amount_sats, cap, "would exceed the 24-hour cap");
            }
        }
        if let Some(cap) = policy.weekly_cap_sats {
            let spent = history.spent_in_window(now, WEEK_SECS);
            if spent.saturating_add(amount_sats) > cap {
                return approval(CapKind::Weekly, spent + amount_sats, cap, "would exceed the 7-day cap");
            }
        }
    }

    // Clock-free caps: always enforced (hold even if the clock is spoofed).
    if let Some(cap) = policy.session_cap_sats {
        let spent = history.spent_this_session();
        if spent.saturating_add(amount_sats) > cap {
            return approval(CapKind::Session, spent + amount_sats, cap, "would exceed this session's cap");
        }
    }
    if let Some(cap) = policy.lifetime_cap_sats {
        let spent = history.total();
        if spent.saturating_add(amount_sats) > cap {
            return approval(CapKind::Lifetime, spent + amount_sats, cap, "would exceed the lifetime cap");
        }
    }

    Decision::AutoSign
}

/// The most-binding active cumulative cap and the room left before it forces an
/// approval: `(cap, spent, limit, remaining)` for the cap with the LEAST headroom,
/// or None if no cumulative cap is active. Per-tx is excluded (it's not a running
/// budget). Mirrors `decide`'s accounting exactly (time caps only when the clock
/// is trusted; `External` already excluded by the history sums) so the on-screen
/// "remaining" readout matches what the gate will actually do.
pub fn remaining_budget(
    policy: &SpendPolicy,
    history: &SpendHistory,
    now: u64,
) -> Option<(CapKind, u64, u64, u64)> {
    let mut caps: Vec<(CapKind, u64, u64)> = Vec::new();
    if policy.clock.time_caps_enforceable() {
        if let Some(c) = policy.daily_cap_sats {
            caps.push((CapKind::Daily, history.spent_in_window(now, DAY_SECS), c));
        }
        if let Some(c) = policy.weekly_cap_sats {
            caps.push((CapKind::Weekly, history.spent_in_window(now, WEEK_SECS), c));
        }
    }
    if let Some(c) = policy.session_cap_sats {
        caps.push((CapKind::Session, history.spent_this_session(), c));
    }
    if let Some(c) = policy.lifetime_cap_sats {
        caps.push((CapKind::Lifetime, history.total(), c));
    }
    caps.into_iter()
        .map(|(k, spent, limit)| (k, spent, limit, limit.saturating_sub(spent)))
        .min_by_key(|(_, _, _, rem)| *rem)
}

fn approval(cap: CapKind, would_be: u64, limit: u64, why: &str) -> Decision {
    Decision::RequireApproval {
        cap,
        reason: format!("{why} ({} > {} sats)", with_commas(would_be), with_commas(limit)),
    }
}

/// Thousands separators, e.g. 150400 -> "150,400". (gate.rs is a leaf module, so it
/// carries its own formatter rather than reaching into main.)
fn with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nunchuk::history::{SignKind, SpendHistory, SpendRecord};

    fn hist(records: &[(u64, u64)]) -> SpendHistory {
        let mut h = SpendHistory::new();
        for (t, amt) in records {
            h.record(SpendRecord {
                unix_time: *t,
                amount_sats: *amt,
                dest: "tb1q".into(),
                kind: SignKind::Auto,
                txid: "tx".into(),
                wallet: String::new(),
                wallet_id: String::new(),
            });
        }
        h
    }

    fn policy() -> SpendPolicy {
        SpendPolicy {
            per_tx_limit_sats: 100_000,
            daily_cap_sats: Some(300_000),
            weekly_cap_sats: Some(1_000_000),
            session_cap_sats: Some(500_000),
            lifetime_cap_sats: None,
            clock: Clock::Rtc,
            recovery_blocks: 20,
            with_platform_key: false,
            hsm_enabled: true,
            frozen: false,
            allowlist: Vec::new(),
        }
    }

    #[test]
    fn small_spend_auto_signs() {
        let p = policy();
        let h = SpendHistory::new();
        assert_eq!(decide(&p, &h, 50_000, 1_000_000), Decision::AutoSign);
    }

    #[test]
    fn over_per_tx_requires_approval() {
        let p = policy();
        let h = SpendHistory::new();
        match decide(&p, &h, 150_000, 1_000_000) {
            Decision::RequireApproval { cap, .. } => assert_eq!(cap, CapKind::PerTx),
            d => panic!("expected approval, got {d:?}"),
        }
    }

    #[test]
    fn daily_velocity_trips_even_when_each_tx_is_small() {
        let p = policy();
        // Three 90k spends today = 270k; a fourth 90k would hit 360k > 300k daily.
        let now = 1_000_000;
        let h = hist(&[(now - 100, 90_000), (now - 200, 90_000), (now - 300, 90_000)]);
        match decide(&p, &h, 90_000, now) {
            Decision::RequireApproval { cap, .. } => assert_eq!(cap, CapKind::Daily),
            d => panic!("expected daily-cap approval, got {d:?}"),
        }
    }

    #[test]
    fn old_spends_age_out_of_the_daily_window() {
        let p = policy();
        let now = 1_000_000;
        // Two big spends, but 2 days ago — outside the 24h window.
        let h = hist(&[(now - 2 * DAY_SECS, 200_000), (now - 3 * DAY_SECS, 200_000)]);
        assert_eq!(decide(&p, &h, 90_000, now), Decision::AutoSign);
    }

    #[test]
    fn untrusted_clock_disables_time_caps_but_keeps_session_cap() {
        let mut p = policy();
        p.clock = Clock::None;
        let now = 1_000_000;
        // 5x 90k = 450k in-window history; daily cap of 300k would normally trip,
        // but with no clock the daily cap is NOT enforced.
        let h = hist(&[(0, 90_000), (0, 90_000), (0, 90_000), (0, 90_000), (0, 90_000)]);
        // Session cap (500k) IS enforced and 450k + 90k = 540k > 500k -> approval.
        match decide(&p, &h, 90_000, now) {
            Decision::RequireApproval { cap, .. } => assert_eq!(cap, CapKind::Session),
            d => panic!("expected session-cap approval, got {d:?}"),
        }
    }

    #[test]
    fn lifetime_cap_is_clock_free_hard_floor() {
        let mut p = policy();
        p.clock = Clock::None;
        p.session_cap_sats = None;
        p.lifetime_cap_sats = Some(1_000_000);
        // Spread across "different days" via timestamps, but lifetime sums all.
        let h = hist(&[(0, 400_000), (0, 400_000), (0, 150_000)]); // 950k total
        match decide(&p, &h, 100_000, 9_999_999) {
            Decision::RequireApproval { cap, .. } => assert_eq!(cap, CapKind::Lifetime),
            d => panic!("expected lifetime-cap approval, got {d:?}"),
        }
        // A spend that stays under the lifetime cap auto-signs.
        assert_eq!(decide(&p, &h, 40_000, 9_999_999), Decision::AutoSign);
    }

    #[test]
    fn remaining_budget_reports_the_tightest_cap() {
        let mut p = policy();
        p.clock = Clock::None; // disable time-window caps
        p.session_cap_sats = Some(500_000);
        p.lifetime_cap_sats = Some(1_000_000);
        let h = hist(&[(0, 100_000)]); // 100k spent
        let (cap, spent, limit, rem) = remaining_budget(&p, &h, 0).unwrap();
        assert_eq!(cap, CapKind::Session, "session (400k left) is tighter than lifetime (900k)");
        assert_eq!((spent, limit, rem), (100_000, 500_000, 400_000));
    }

    #[test]
    fn remaining_budget_none_when_no_cumulative_cap() {
        let mut p = policy();
        p.clock = Clock::None;
        p.session_cap_sats = None;
        p.weekly_cap_sats = None;
        p.daily_cap_sats = None;
        p.lifetime_cap_sats = None;
        assert!(remaining_budget(&p, &SpendHistory::new(), 0).is_none());
    }

    #[test]
    fn exactly_at_the_limit_auto_signs() {
        let p = policy();
        let h = SpendHistory::new();
        // per-tx is "> limit" -> approval, so == limit is fine.
        assert_eq!(decide(&p, &h, 100_000, 1_000), Decision::AutoSign);
    }
}
