// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

use slint_keyos_platform_build::{compile_options, CompileOptions};

fn main() {
    let themes_rust_dir = std::env::var("FOUNDATION_THEMES_RUST_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/.foundation/themes/rust")
    });
    println!("cargo:rustc-env=FOUNDATION_THEMES_RUST_DIR={themes_rust_dir}");
    println!("cargo:rerun-if-env-changed=FOUNDATION_THEMES_RUST_DIR");

    compile_options(CompileOptions {
        module_path: "ui/app.slint",
        include_slint: true,
        include_router: true,
        include_translations: true,
        include_time_localization: false,
    });
}
