//! Deterministic mode: seed-stable, order-independent key fixtures.
//!
//! Demonstrates that the same seed + label + spec always produces identical
//! keys, regardless of call order or other fixtures generated in between.
//!
//! Run with:
//! ```sh
//! cargo run -p uselesskey --example deterministic --features "rsa,ecdsa,ed25519,jwk"
//! ```

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn main() {
    use uselesskey::prelude::*;

    // ── Create a deterministic factory from a string seed ────────────────
    let seed = Seed::from_env_value("my-test-seed-v1").unwrap();
    let fx = Factory::deterministic(seed);

    // ── Same seed + same identity = same key ─────────────────────────────
    println!("=== Reproducibility ===");
    let key_a = fx.rsa("issuer", RsaSpec::rs256());
    let key_b = fx.rsa("issuer", RsaSpec::rs256());

    assert_eq!(key_a.private_key_pkcs8_pem(), key_b.private_key_pkcs8_pem());
    assert_eq!(key_a.kid(), key_b.kid());
    println!("  Same label+spec → identical key ✓");

    // ── Order-independent: interleaving other keys doesn't change results ─
    println!("\n=== Order Independence ===");
    let seed2 = Seed::from_env_value("my-test-seed-v1").unwrap();
    let fx2 = Factory::deterministic(seed2);

    // Generate keys in a different order
    let _unrelated_ecdsa = fx2.ecdsa("other", EcdsaSpec::es256());
    let _unrelated_ed = fx2.ed25519("another", Ed25519Spec::new());
    let key_c = fx2.rsa("issuer", RsaSpec::rs256());

    assert_eq!(key_a.private_key_pkcs8_pem(), key_c.private_key_pkcs8_pem());
    assert_eq!(key_a.kid(), key_c.kid());
    println!("  Keys match despite different generation order ✓");

    // ── Different labels produce different keys ──────────────────────────
    println!("\n=== Label Isolation ===");
    let key_x = fx.rsa("service-x", RsaSpec::rs256());
    let key_y = fx.rsa("service-y", RsaSpec::rs256());

    assert_ne!(key_x.private_key_pkcs8_pem(), key_y.private_key_pkcs8_pem());
    assert_ne!(key_x.kid(), key_y.kid());
    println!("  Different labels → different keys ✓");

    // ── Different seeds produce different keys ───────────────────────────
    println!("\n=== Seed Isolation ===");
    let other_seed = Seed::from_env_value("a-different-seed").unwrap();
    let fx_other = Factory::deterministic(other_seed);
    let key_other = fx_other.rsa("issuer", RsaSpec::rs256());

    assert_ne!(
        key_a.private_key_pkcs8_pem(),
        key_other.private_key_pkcs8_pem()
    );
    println!("  Different seeds → different keys ✓");

    // ── Cross-algorithm determinism ──────────────────────────────────────
    println!("\n=== Cross-Algorithm Determinism ===");
    let ecdsa1 = fx.ecdsa("signer", EcdsaSpec::es256());
    let ecdsa2 = fx.ecdsa("signer", EcdsaSpec::es256());
    assert_eq!(ecdsa1.kid(), ecdsa2.kid());
    println!("  ECDSA deterministic ✓");

    let ed1 = fx.ed25519("edge", Ed25519Spec::new());
    let ed2 = fx.ed25519("edge", Ed25519Spec::new());
    assert_eq!(ed1.kid(), ed2.kid());
    println!("  Ed25519 deterministic ✓");

    // ── JWK / JWKS are also deterministic ────────────────────────────────
    println!("\n=== Deterministic JWK Output ===");
    println!("  RSA kid:    {}", key_a.kid());
    println!("  ECDSA kid:  {}", ecdsa1.kid());
    println!("  Ed25519 kid: {}", ed1.kid());
    println!("  (These values are stable across runs with the same seed)");

    println!("\nAll determinism checks passed!");
}

#[cfg(not(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
)))]
fn main() {
    eprintln!("Enable all required features to run this example:");
    eprintln!(
        "  cargo run -p uselesskey --example deterministic --features \"rsa,ecdsa,ed25519,jwk\""
    );
}
