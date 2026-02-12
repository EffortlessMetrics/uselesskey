//! JWT signing example using uselesskey fixtures.
//!
//! This example demonstrates:
//! - Generating deterministic RSA/ECDSA/HMAC keys for JWT signing
//! - Using JWK outputs for JWT verification
//! - Creating a JWKS for multiple keys
//!
//! Run with: cargo run --example jwt_signing --features "rsa,ecdsa,hmac,jwk"

use uselesskey::prelude::*;

#[cfg(all(feature = "rsa", feature = "jwk"))]
fn main() {
    // Create a deterministic factory for reproducible keys
    let fx = Factory::deterministic(Seed::new([0u8; 32]));

    // Generate an RSA keypair for RS256
    let rsa_key = fx.rsa("issuer", RsaSpec::rs256());

    println!("=== RSA Key (RS256) ===");
    println!("Key ID (kid): {}", rsa_key.kid());
    println!("\nPublic JWK:");
    println!("{}", rsa_key.public_jwk());
    println!("\nJWKS for verification:");
    println!("{}", rsa_key.public_jwks());

    // Also demonstrate ECDSA (ES256)
    #[cfg(feature = "ecdsa")]
    {
        let ecdsa_key = fx.ecdsa("ecdsa-issuer", EcdsaSpec::es256());
        println!("\n=== ECDSA Key (ES256) ===");
        println!("Key ID (kid): {}", ecdsa_key.kid());
        println!("\nPublic JWK:");
        println!("{}", ecdsa_key.public_jwk());
    }

    // Demonstrate HMAC (HS256) for symmetric signing
    #[cfg(feature = "hmac")]
    {
        let hmac_secret = fx.hmac("hmac-issuer", HmacSpec::hs256());
        println!("\n=== HMAC Secret (HS256) ===");
        println!("Key ID (kid): {}", hmac_secret.kid());
        println!("\nJWK (symmetric):");
        println!("{}", hmac_secret.jwk());
    }

    println!("\n=== Key formats available ===");
    println!("Private Key PKCS#8 PEM:");
    println!("{}", rsa_key.private_key_pkcs8_pem());
    println!("\nPublic Key SPKI PEM:");
    println!("{}", rsa_key.public_key_spki_pem());
}

#[cfg(not(all(feature = "rsa", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'rsa' and 'jwk' features to run this example:");
    eprintln!("  cargo run --example jwt_signing --features \"rsa,jwk\"");
    eprintln!("\nFor full functionality with all key types:");
    eprintln!("  cargo run --example jwt_signing --features \"rsa,ecdsa,hmac,jwk\"");
}
