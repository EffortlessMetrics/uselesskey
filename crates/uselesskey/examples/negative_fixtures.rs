//! Negative fixtures example demonstrating error testing scenarios.
//!
//! This example demonstrates:
//! - Generating intentionally invalid certificates and keys
//! - Testing error handling paths in your application
//! - Using corrupt PEM variants and truncated DER
//! - Tempfile outputs for testing external tools
//!
//! Run with: cargo run --example negative_fixtures --features "rsa,x509"

use std::io::Read;
use uselesskey::prelude::*;
use uselesskey_core::negative::CorruptPem;

fn main() {
    let fx = Factory::random();

    println!("=== Negative Fixtures for Error Testing ===\n");

    // 1. Expired certificate
    println!("1. Expired Certificate:");
    let valid_cert = fx.x509_self_signed("valid", X509Spec::self_signed("test.com"));
    let _expired_cert = valid_cert.expired();
    println!("   Generated expired certificate variant");
    println!("   (Use this to test certificate expiry validation)\n");

    // 2. Not-yet-valid certificate
    println!("2. Not-Yet-Valid Certificate:");
    let _future_cert = valid_cert.not_yet_valid();
    println!("   Generated future-dated certificate");
    println!("   (Use this to test 'cert not yet valid' errors)\n");

    // 3. Wrong key usage
    println!("3. Wrong Key Usage:");
    let _wrong_ku = valid_cert.wrong_key_usage();
    println!("   Generated certificate with incompatible key usage flags");
    println!("   (Use this to test key usage validation failures)\n");

    // 4. Corrupt PEM variants
    println!("4. Corrupt PEM Variants:");
    let corrupt_variants = vec![
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 50 },
        CorruptPem::ExtraBlankLine,
    ];

    for variant in &corrupt_variants {
        let corrupt = valid_cert.corrupt_cert_pem(*variant);
        let preview: String = corrupt.chars().take(50).collect();
        println!("   {:?}: {}", variant, preview);
    }
    println!("   (Use these to test PEM parsing error handling)\n");

    // 5. Truncated DER
    println!("5. Truncated DER:");
    let truncated_der = valid_cert.truncate_cert_der(10);
    println!(
        "   Original DER length: {} bytes",
        valid_cert.cert_der().len()
    );
    println!("   Truncated length: {} bytes", truncated_der.len());
    println!("   (Use this to test DER parsing error handling)\n");

    // 6. Mismatched keypair
    println!("6. Mismatched Keypair:");
    let rsa_key = fx.rsa("primary", RsaSpec::rs256());
    let mismatched_der = rsa_key.mismatched_public_key_spki_der();
    println!("   Generated RSA keypair with mismatched public key");
    println!(
        "   Mismatched SPKI DER length: {} bytes",
        mismatched_der.len()
    );
    println!("   (Use this to test signature verification failures)\n");

    // 7. Tempfile outputs
    println!("7. Tempfile Outputs for External Tools:");
    let temp_cert = valid_cert
        .write_cert_pem()
        .expect("Failed to create temp file");
    let temp_key = valid_cert
        .write_private_key_pem()
        .expect("Failed to create temp file");

    println!("   Certificate tempfile: {}", temp_cert.path().display());
    println!("   Private key tempfile: {}", temp_key.path().display());

    // Read back and verify
    let mut cert_contents = String::new();
    std::fs::File::open(temp_cert.path())
        .unwrap()
        .read_to_string(&mut cert_contents)
        .unwrap();

    assert!(cert_contents.contains("BEGIN CERTIFICATE"));
    println!("   (Tempfiles have restrictive permissions and auto-cleanup)");

    println!("\n=== All negative fixtures generated successfully ===");
    println!("Use these in your tests to verify error handling paths!");
}
