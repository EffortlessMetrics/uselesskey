//! Basic usage of uselesskey: generating key fixtures for tests.
//!
//! Demonstrates creating a Factory and generating RSA, ECDSA, and Ed25519
//! keys with access to PEM, DER, and JWK output formats.
//!
//! Run with:
//! ```sh
//! cargo run -p uselesskey --example basic --features "rsa,ecdsa,ed25519,jwk"
//! ```

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn main() {
    use uselesskey::prelude::*;

    // Create a random factory — each process gets fresh keys, cached for reuse
    let fx = Factory::random();

    // ── RSA (RS256) ──────────────────────────────────────────────────────
    println!("=== RSA Key (RS256) ===");
    let rsa = fx.rsa("auth-service", RsaSpec::rs256());

    // PEM-encoded private key (PKCS#8)
    let priv_pem = rsa.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    println!("  Private PKCS#8 PEM: {} bytes", priv_pem.len());

    // DER-encoded private key
    let priv_der = rsa.private_key_pkcs8_der();
    println!("  Private PKCS#8 DER: {} bytes", priv_der.len());

    // PEM-encoded public key (SPKI)
    let pub_pem = rsa.public_key_spki_pem();
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    println!("  Public SPKI PEM:    {} bytes", pub_pem.len());

    // DER-encoded public key
    let pub_der = rsa.public_key_spki_der();
    println!("  Public SPKI DER:    {} bytes", pub_der.len());

    // JWK outputs (requires "jwk" feature)
    println!("  Key ID (kid):       {}", rsa.kid());
    println!("  Public JWK:\n{}", rsa.public_jwk());

    // ── ECDSA (ES256 / P-256) ────────────────────────────────────────────
    println!("\n=== ECDSA Key (ES256) ===");
    let ecdsa = fx.ecdsa("signing-service", EcdsaSpec::es256());

    println!(
        "  Private PKCS#8 PEM: {} bytes",
        ecdsa.private_key_pkcs8_pem().len()
    );
    println!(
        "  Public SPKI PEM:    {} bytes",
        ecdsa.public_key_spki_pem().len()
    );
    println!("  Key ID (kid):       {}", ecdsa.kid());
    println!("  Public JWK:\n{}", ecdsa.public_jwk());

    // P-384 variant
    let ecdsa_384 = fx.ecdsa("signing-384", EcdsaSpec::es384());
    println!(
        "\n  ES384 Public SPKI DER: {} bytes",
        ecdsa_384.public_key_spki_der().len()
    );

    // ── Ed25519 ──────────────────────────────────────────────────────────
    println!("\n=== Ed25519 Key ===");
    let ed = fx.ed25519("edge-signer", Ed25519Spec::new());

    println!(
        "  Private PKCS#8 PEM: {} bytes",
        ed.private_key_pkcs8_pem().len()
    );
    println!(
        "  Public SPKI PEM:    {} bytes",
        ed.public_key_spki_pem().len()
    );
    println!(
        "  Private PKCS#8 DER: {} bytes",
        ed.private_key_pkcs8_der().len()
    );
    println!(
        "  Public SPKI DER:    {} bytes",
        ed.public_key_spki_der().len()
    );
    println!("  Key ID (kid):       {}", ed.kid());
    println!("  Public JWK:\n{}", ed.public_jwk());

    // ── Caching ──────────────────────────────────────────────────────────
    println!("\n=== Cache Demonstration ===");
    let rsa_again = fx.rsa("auth-service", RsaSpec::rs256());
    assert_eq!(
        rsa.private_key_pkcs8_pem(),
        rsa_again.private_key_pkcs8_pem(),
    );
    println!("  Same (label, spec) returns the same cached key ✓");

    println!("\nAll key types generated successfully!");
}

#[cfg(not(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
)))]
fn main() {
    eprintln!("Enable all required features to run this example:");
    eprintln!("  cargo run -p uselesskey --example basic --features \"rsa,ecdsa,ed25519,jwk\"");
}
