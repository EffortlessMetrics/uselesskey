//! Demonstrates generating RSA keypairs and extracting JWK/JWKS for JWT verification flows.
//!
//! This example shows:
//! - Creating a Factory in both random and deterministic modes
//! - Generating an RSA keypair with RS256 spec
//! - Getting the public JWK and JWKS for use in JWT verification
//! - Accessing the key ID (kid) for JWT header matching
//!
//! Run with:
//! ```sh
//! cargo run --example jwt_rs256_jwks --features "rsa jwk"
//! ```

use std::error::Error;

#[cfg(all(feature = "rsa", feature = "jwk"))]
fn main() -> Result<(), Box<dyn Error>> {
    use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};

    // ==========================================================================
    // Random mode: each run produces different keys (still cached per-process)
    // ==========================================================================
    println!("=== Random Mode ===\n");

    let fx_random = Factory::random();
    let keypair_random = fx_random.rsa("auth-service", RsaSpec::rs256());

    println!("Key ID (kid): {}", keypair_random.kid());
    println!("\nPublic JWK:");
    println!("{}", keypair_random.public_jwk());

    // ==========================================================================
    // Deterministic mode: same seed + same label = same key every time
    // ==========================================================================
    println!("\n=== Deterministic Mode ===\n");

    // Create a deterministic factory with a fixed seed.
    // In CI, you might read this from an environment variable instead.
    let seed = Seed::from_env_value("demo-seed").unwrap();
    let fx_deterministic = Factory::deterministic(seed);

    let keypair_deterministic = fx_deterministic.rsa("issuer", RsaSpec::rs256());

    println!("Key ID (kid): {}", keypair_deterministic.kid());

    // Get the JWKS (JSON Web Key Set) containing the public key.
    // This is what you'd serve at /.well-known/jwks.json in a mock server.
    let jwks = keypair_deterministic.public_jwks();

    println!("\nPublic JWKS (for /.well-known/jwks.json):");
    println!("{jwks}");

    // ==========================================================================
    // Verify determinism: generating the same key again produces identical output
    // ==========================================================================
    println!("\n=== Determinism Verification ===\n");

    let keypair_again = fx_deterministic.rsa("issuer", RsaSpec::rs256());
    assert_eq!(keypair_deterministic.kid(), keypair_again.kid());
    assert_eq!(
        keypair_deterministic.public_jwks().to_string(),
        keypair_again.public_jwks().to_string()
    );
    println!("Verified: same seed + same label produces identical keys");

    Ok(())
}

#[cfg(not(all(feature = "rsa", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'rsa' and 'jwk' features to run this example:");
    eprintln!("  cargo run --example jwt_rs256_jwks --features \"rsa jwk\"");
}
