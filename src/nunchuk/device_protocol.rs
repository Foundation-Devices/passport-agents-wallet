// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! device_protocol.rs - Prime's host<->device wire protocol.
//!
//! Newline-delimited JSON request/response, transport-agnostic. The SAME messages
//! flow over the host file bridge (sim) and over the device host transport
//! (`src/transport.rs` - currently stubbed pending the QuantumLink v2 endpoint;
//! see MIGRATION-QLV2.md). The host-side `prime.py` HWI driver and `prime-signer`
//! shim speak this protocol; the device dispatches it in `main.rs::process_request`
//! against the live key + gate.
//!
//! This maps onto HWI's `HardwareWalletClient`:
//!   Fingerprint -> get_master_fingerprint
//!   Xpub{path}  -> get_pubkey_at_path
//!   Sign{psbt}  -> sign_tx   (in-policy = Signed; over-policy/recovery = Pending)
//!   Showaddr    -> display_multisig_address

use serde::{Deserialize, Serialize};

/// Host -> device request. `{"cmd":"xpub","path":"m/48'/1'/0'/2'"}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Master fingerprint of the device key.
    Fingerprint,
    /// `[fp/path]xpub` at an arbitrary BIP32 path.
    Xpub { path: String },
    /// Sign a base64 PSBT. In-policy -> signed; over-policy/recovery -> pending.
    Sign { psbt: String },
    /// Display + return a wallet address at `index` (receive, or change).
    Showaddr {
        index: u32,
        #[serde(default)]
        change: bool,
    },
    /// Enrol a wallet descriptor so Prime will sign for it. The host pushes the
    /// Nunchuk-exported descriptor over the cable instead of a microSD import.
    Register { descriptor: String },
    /// Report a spend the agent signed WITHOUT Prime (agent + Platform Key, under the
    /// limit) so it shows in Prime's activity as the "without you" everyday lane.
    /// `wallet` (optional) names which wallet, to disambiguate the activity log.
    Log {
        amount_sats: u64,
        dest: String,
        txid: String,
        #[serde(default)]
        wallet: String,
    },
    /// Read the onboarding setup the user picked on the device (model + recovery
    /// timelock) so the agent builds the matching wallet. At the wait step the device
    /// has already recorded these; the agent reads them here rather than being told,
    /// making the on-device recovery picker the single source of truth.
    Spec,
}

/// Device -> host response. `{"result":"key","key":"[fp/..]tpub.."}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Fingerprint {
        fingerprint: String,
    },
    Key {
        key: String,
    },
    Signed {
        psbt: String,
    },
    /// Over-policy or recovery: the device is holding it for an on-device approval.
    Pending {
        reason: String,
    },
    Address {
        address: String,
    },
    /// A descriptor was enrolled: Prime now recognises this wallet.
    Registered {
        name: String,
        checksum: String,
    },
    /// An agent-reported spend was recorded in the activity log.
    Logged {
        txid: String,
    },
    /// The onboarding setup the user chose. `model` is `"2-of-2"` (self-custodied,
    /// agent + Passport) or `"2-of-3"` (adds Nunchuk's Platform Key). `recovery_blocks`
    /// is the relative-timelock recommendation for the Passport-alone recovery leg
    /// (a 2-of-2 feature; ignore for 2-of-3, which self-recovers).
    Spec {
        model: String,
        recovery_blocks: u32,
    },
    Error {
        message: String,
    },
}

impl Response {
    pub fn error(msg: impl Into<String>) -> Self {
        Response::Error {
            message: msg.into(),
        }
    }

    /// Parse a request from one JSON line.
    pub fn parse_request(line: &[u8]) -> Result<Request, Self> {
        serde_json::from_slice(line).map_err(|e| Response::error(format!("bad request: {e}")))
    }

    /// Serialize a response as one JSON line (no trailing newline).
    pub fn to_line(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .unwrap_or_else(|_| b"{\"result\":\"error\",\"message\":\"serialize\"}".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_roundtrip() {
        let cases = [
            Request::Fingerprint,
            Request::Xpub {
                path: "m/48'/1'/0'/2'".into(),
            },
            Request::Sign {
                psbt: "cHNidP8B".into(),
            },
            Request::Showaddr {
                index: 0,
                change: false,
            },
            Request::Register {
                descriptor: "wsh(sortedmulti(2,...))#abcd".into(),
            },
            Request::Log {
                amount_sats: 12_345,
                dest: "tb1qxyz".into(),
                txid: "deadbeef".into(),
                wallet: "Agent Wallet".into(),
            },
            Request::Spec,
        ];
        for c in cases {
            let line = serde_json::to_vec(&c).unwrap();
            let back = Response::parse_request(&line).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn parses_concrete_wire_lines() {
        assert_eq!(
            Response::parse_request(br#"{"cmd":"xpub","path":"m/84'/1'/0'"}"#).unwrap(),
            Request::Xpub {
                path: "m/84'/1'/0'".into()
            }
        );
        assert_eq!(
            Response::parse_request(br#"{"cmd":"fingerprint"}"#).unwrap(),
            Request::Fingerprint
        );
        assert_eq!(
            Response::parse_request(br#"{"cmd":"spec"}"#).unwrap(),
            Request::Spec
        );
        // change defaults to false when omitted
        assert_eq!(
            Response::parse_request(br#"{"cmd":"showaddr","index":3}"#).unwrap(),
            Request::Showaddr {
                index: 3,
                change: false
            }
        );
    }

    #[test]
    fn bad_request_is_an_error_response() {
        assert!(matches!(
            Response::parse_request(b"not json"),
            Err(Response::Error { .. })
        ));
    }

    #[test]
    fn response_lines() {
        let r = Response::Key {
            key: "[d38570d3/48'/1'/0'/2']tpub".into(),
        };
        let line = r.to_line();
        let s = String::from_utf8(line).unwrap();
        assert!(s.contains("\"result\":\"key\""));
        assert!(s.contains("tpub"));
    }
}
