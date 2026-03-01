//! Build script for uselesskey-bdd-steps
//!
//! Checks for NASM availability and sets a cfg flag accordingly.
//! This mirrors the same check in uselesskey-aws-lc-rs/build.rs so that
//! BDD step definitions for the aws-lc-rs adapter are gated correctly.

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
