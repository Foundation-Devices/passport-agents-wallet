// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host <-> device request/response transport (`cfg(keyos)` only).
//!
//! ## STATUS: STUB
//!
//! The USB CDC-ACM transport was **removed**. Passport Prime is moving to
//! **QuantumLink v2** (the `os/ql` service + the `ql` app API); CDC is not used
//! going forward. This module keeps the transport-agnostic dispatch seam
//! ([`dispatch`]) and a stub [`serve`] so the app builds and behaves normally on
//! the simulator (file-bridge) while the qlv2 RPC endpoint is wired up on device.
//!
//! With this stub in place, the on-device app runs but exposes **no** host
//! transport: `xpub` / `register` / `sign` requests only arrive on the simulator
//! file bridge, not over USB. That is intentional and temporary.
//!
//! ## Wiring qlv2 (un-stubbing this)
//!
//! See `MIGRATION-QLV2.md` for the full plan. In short, `serve` becomes a
//! QuantumLink v2 RPC endpoint instead of a USB device:
//!
//! 1. `ql::use_api!()`, then `QlApi::default().peer(PeerTarget::Companion).rpc(worker())`.
//! 2. Define `xpub` / `register` / `sign` as `ql-api` RPC routes (a single
//!    opaque-bytes route can carry today's JSON envelope verbatim).
//! 3. Serve them with `Router::builder_local(..).request::<..>().build(..)` +
//!    `ql.rpc_handlers(worker(), router)`, handing each request payload to
//!    [`dispatch`] and returning `Response::to_line()` bytes.
//!
//! Everything below [`dispatch`] is transport-agnostic and is reused unchanged
//! when the real endpoint lands. The retired CDC implementation lives in git
//! history (`src/usb_cdc.rs`) if the endpoint framing needs cross-referencing.

use std::sync::{Arc, Mutex};

use crate::nunchuk::device_protocol::Response;
use crate::AppState;

/// Transport-agnostic request dispatch. Parses one request payload (opaque bytes:
/// newline-JSON today, CBOR under qlv2) and runs the SAME gated sign / xpub /
/// register handler the simulator file bridge uses, so device and sim behave
/// identically. Reused as-is when the qlv2 RPC endpoint replaces the stub below.
#[allow(dead_code)] // wired up when the qlv2 endpoint replaces `serve`'s stub body
pub fn dispatch(state: &Arc<Mutex<AppState>>, payload: &[u8]) -> Response {
    match Response::parse_request(payload) {
        Ok(req) => crate::process_request(state, req),
        Err(resp) => resp,
    }
}

/// STUB transport entry point (called from `main` on device). The real
/// implementation registers a QuantumLink v2 RPC endpoint (`os/ql`) and pumps
/// records through [`dispatch`]. Until that lands it logs and returns, so the app
/// runs without a host transport. See the module docs and `MIGRATION-QLV2.md`.
pub fn serve(_state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    log::warn!(
        "transport: QuantumLink v2 RPC endpoint not yet wired (CDC removed). \
         Host <-> device requests are unavailable in this build; use the simulator \
         file bridge. See MIGRATION-QLV2.md to wire os/ql."
    );
    Ok(())
}
