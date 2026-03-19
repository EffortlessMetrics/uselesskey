//! Basic ECDSA key fixture generation.
//!
//! Demonstrates generating ECDSA keypairs for P-256 (ES256) and P-384 (ES384),
//! and accessing them in PEM, DER, and JWK formats.
//!
//! Run with: cargo run -p uselesskey --example basic_ecdsa --features "ecdsa,jwk"

#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn main() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Factory};

    let fx = Factory::random();

    // --- P-256 (ES256) ---
    let p256 = fx.ecdsa("auth-p256", EcdsaSpec::es256());

    println!("=== ECDSA P-256 (ES256) ===");
    println!(
        "  Private PEM header : {}",
        p256.private_key_pkcs8_pem().lines().next().unwrap_or("")
    );
    println!(
        "  Private PEM length : {} bytes",
        p256.private_key_pkcs8_pem().len()
    );
    println!(
        "  Private DER length : {} bytes",
        p256.private_key_pkcs8_der().len()
    );
    println!(
        "  Public PEM header  : {}",
        p256.public_key_spki_pem().lines().next().unwrap_or("")
    );
    println!(
        "  Public PEM length  : {} bytes",
        p256.public_key_spki_pem().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        p256.public_key_spki_der().len()
    );

    let jwk256 = p256.public_jwk().to_value();
    println!("  JWK kty : {}", jwk256["kty"]);
    println!("  JWK crv : {}", jwk256["crv"]);
    println!("  JWK alg : {}", jwk256["alg"]);
    println!("  kid     : {}", p256.kid());

    // --- P-384 (ES384) ---
    let p384 = fx.ecdsa("auth-p384", EcdsaSpec::es384());

    println!("\n=== ECDSA P-384 (ES384) ===");
    println!(
        "  Private PEM length : {} bytes",
        p384.private_key_pkcs8_pem().len()
    );
    println!(
        "  Private DER length : {} bytes",
        p384.private_key_pkcs8_der().len()
    );
    println!(
        "  Public PEM length  : {} bytes",
        p384.public_key_spki_pem().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        p384.public_key_spki_der().len()
    );

    let jwk384 = p384.public_jwk().to_value();
    println!("  JWK kty : {}", jwk384["kty"]);
    println!("  JWK crv : {}", jwk384["crv"]);
    println!("  JWK alg : {}", jwk384["alg"]);
    println!("  kid     : {}", p384.kid());

    // P-256 and P-384 keys have different sizes.
    assert!(
        p384.private_key_pkcs8_der().len() > p256.private_key_pkcs8_der().len(),
        "P-384 DER should be larger than P-256"
    );
    println!("\n✓ P-384 keys are larger than P-256 as expected");
}

#[cfg(not(all(feature = "ecdsa", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'ecdsa' and 'jwk' features:");
    eprintln!("  cargo run -p uselesskey --example basic_ecdsa --features \"ecdsa,jwk\"");
}
