//! Build script for uselesskey-aws-lc-rs
//!
//! Checks for NASM availability and sets a cfg flag accordingly.
//! This allows tests to be skipped gracefully when NASM is not available.

use std::process::Command;

fn main() {
    // Tell cargo about our custom cfg to avoid warnings
    println!("cargo::rustc-check-cfg=cfg(has_nasm)");

    // Rerun only when this build script or PATH changes
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=PATH");

    // NASM is only required on Windows for aws-lc-rs.
    // On other platforms, always set has_nasm so the full API is available.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        println!("cargo::rustc-cfg=has_nasm");
        return;
    }

    // On Windows, probe for NASM
    let nasm_available = Command::new("nasm")
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if nasm_available {
        println!("cargo::rustc-cfg=has_nasm");
        println!("cargo::warning=NASM found - aws-lc-rs will be compiled from source");
    } else {
        println!("cargo::warning=NASM not found - aws-lc-rs tests will be skipped");
    }
}
