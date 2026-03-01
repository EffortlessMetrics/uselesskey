//! Build script for uselesskey-interop-tests.
//!
//! Checks for NASM availability so aws-lc-rs interop tests can be gated
//! gracefully on Windows.

use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(has_nasm)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=PATH");

    let nasm_available = Command::new("nasm")
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if nasm_available {
        println!("cargo::rustc-cfg=has_nasm");
    }
}
