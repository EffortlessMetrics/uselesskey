//! TLS certificate chain example using uselesskey fixtures.
//!
//! This example demonstrates:
//! - Generating a certificate chain (Root CA → Intermediate → Leaf)
//! - Accessing certificates in PEM/DER formats
//! - Creating self-signed certificates for testing
//!
//! Run with: cargo run --example tls_server --features "x509"

#[cfg(feature = "x509")]
fn main() {
    use uselesskey::prelude::*;

    // Create a deterministic factory for reproducible certificates
    let fx = Factory::deterministic(Seed::new([0u8; 32]));

    // Generate a certificate chain for test.example.com
    let chain_spec = ChainSpec::new("test.example.com")
        .with_sans(vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    let chain = fx.x509_chain("tls-server", chain_spec);

    println!("=== Certificate Chain Generated ===");
    println!("Root CA: {}...", &chain.root_cert_pem()[..50]);
    println!("Intermediate: {}...", &chain.intermediate_cert_pem()[..50]);
    println!("Leaf: {}...", &chain.leaf_cert_pem()[..50]);

    println!("\n=== Chain Components ===");
    println!(
        "Full chain (leaf + intermediate): {} bytes PEM",
        chain.chain_pem().len()
    );
    println!("Leaf cert DER: {} bytes", chain.leaf_cert_der().len());
    println!(
        "Private key: {} bytes PKCS#8",
        chain.leaf_private_key_pkcs8_der().len()
    );

    // Show the intended TLS usage
    println!("\n=== TLS Usage ===");
    println!("Server presents: leaf + intermediate certificates");
    println!("Client verifies: against root CA certificate");
    println!("Server identity: test.example.com");

    // Also demonstrate self-signed cert for simpler testing
    println!("\n=== Self-signed Certificate Option ===");
    let self_signed = fx.x509_self_signed("self-signed-server", X509Spec::self_signed("localhost"));

    println!("Certificate: {}...", &self_signed.cert_pem()[..50]);
    println!(
        "Private key: {}...",
        &self_signed.private_key_pkcs8_pem()[..50]
    );
    println!(
        "Combined identity: {} bytes",
        self_signed.identity_pem().len()
    );

    // Show negative fixture example
    println!("\n=== Negative Fixture: Expired Certificate ===");
    let _expired = self_signed.expired();
    println!("Created expired certificate variant for testing error handling");
    println!("(In a real app, this would fail TLS handshake validation)");

    // Show tempfile outputs
    println!("\n=== Tempfile Outputs ===");
    let temp_cert = self_signed
        .write_cert_pem()
        .expect("Failed to create temp file");
    let temp_key = self_signed
        .write_private_key_pem()
        .expect("Failed to create temp file");
    println!("Certificate tempfile: {}", temp_cert.path().display());
    println!("Private key tempfile: {}", temp_key.path().display());
    println!("(Tempfiles auto-delete when dropped)");
}

#[cfg(not(feature = "x509"))]
fn main() {
    eprintln!("Enable required feature to run this example:");
    eprintln!("  cargo run --example tls_server --features \"x509\"");
}
