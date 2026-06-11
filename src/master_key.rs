// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Device master key, backed by KeyOS `security.app_seed()`.
//!
//! On real hardware the 32-byte app seed is device-bound and only available
//! once the user is logged in. Hosted simulator builds keep a deterministic
//! fallback so local development remains usable without a hardware login.

security::use_api!();

/// Fetch the 32-byte app seed. Hardware must never fall back to a known key.
pub fn app_seed() -> Result<[u8; 32], security::AccessDenied> {
    match Security::default().app_seed() {
        Ok(seed) => Ok(seed),
        #[cfg(not(keyos))]
        Err(_) => {
            log::warn!("security.app_seed unavailable; using dev fallback seed");
            Ok([0x11; 32])
        }
        #[cfg(keyos)]
        Err(e) => Err(e),
    }
}
