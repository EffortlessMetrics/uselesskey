//! Basic Ed25519 key fixture generation.
//!
//! Demonstrates generating Ed25519 keypairs and accessing them in
//! PEM, DER, and JWK formats.
//!
//! Run with: cargo run -p uselesskey --example basic_ed25519 --features "ed25519,jwk"

#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn main() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec, Factory};

    let fx = Factory::random();

    // Ed25519 has no configurable parameters — just create one.
    let keypair = fx.ed25519("signing-key", Ed25519Spec::default());

    // --- PEM formats ---
    let priv_pem = keypair.private_key_pkcs8_pem();
    let pub_pem = keypair.public_key_spki_pem();

    println!("=== Ed25519 Key Pair ===");
    println!(
        "  Private PEM header : {}",
        priv_pem.lines().next().unwrap_or("")
    );
    println!("  Private PEM length : {} bytes", priv_pem.len());
    println!(
        "  Public PEM header  : {}",
        pub_pem.lines().next().unwrap_or("")
    );
    println!("  Public PEM length  : {} bytes", pub_pem.len());

    // --- DER formats ---
    println!(
        "\n  Private DER length : {} bytes",
        keypair.private_key_pkcs8_der().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        keypair.public_key_spki_der().len()
    );

    // --- JWK ---
    let jwk = keypair.public_jwk().to_value();
    println!("\n=== Ed25519 Public JWK ===");
    println!("  kty : {}", jwk["kty"]);
    println!("  crv : {}", jwk["crv"]);
    println!("  alg : {}", jwk["alg"]);
    println!("  kid : {}", keypair.kid());

    // --- JWKS ---
    let jwks = keypair.public_jwks().to_value();
    let key_count = jwks["keys"].as_array().map_or(0, |a| a.len());
    println!("\n=== Ed25519 Public JWKS ===");
    println!("  Key count : {key_count}");

    // Ed25519 keys are compact compared to RSA.
    assert!(
        keypair.private_key_pkcs8_der().len() < 100,
        "Ed25519 private keys should be compact"
    );
    println!(
        "\n✓ Ed25519 key is compact ({} bytes DER)",
        keypair.private_key_pkcs8_der().len()
    );
}

#[cfg(not(all(feature = "ed25519", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'ed25519' and 'jwk' features:");
    eprintln!("  cargo run -p uselesskey --example basic_ed25519 --features \"ed25519,jwk\"");
}
