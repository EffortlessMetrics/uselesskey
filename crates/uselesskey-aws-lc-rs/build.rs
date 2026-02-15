//! Build script for uselesskey-aws-lc-rs
//!
//! Checks for NASM availability and sets a cfg flag accordingly.
//! This allows tests to be skipped gracefully when NASM is not available.

use std::process::Command;

fn main() {
    // Tell cargo about our custom cfg to avoid warnings
    println!("cargo::rustc-check-cfg=cfg(has_nasm)");
    // Check if NASM is available
    let nasm_available = Command::new("nasm")
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if nasm_available {
        println!("cargo:rustc-cfg=has_nasm");
        println!("cargo:warning=NASM found - aws-lc-rs will be compiled from source");
    } else {
        println!("cargo:warning=NASM not found - aws-lc-rs tests will be skipped");
    }
}
