//! Deterministic mode: reproducible fixtures from seeds.
//!
//! Demonstrates how deterministic derivation works: same seed + same label +
//! same spec always produces the same key, regardless of call order.
//!
//! Run with: cargo run -p uselesskey --example deterministic --features full

#[cfg(feature = "rsa")]
fn main() {
    use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};

    // =========================================================================
    // 1. Create a deterministic factory from a string seed
    // =========================================================================
    println!("=== Deterministic Mode ===\n");

    let seed = Seed::from_env_value("my-test-seed-v1").unwrap();
    let fx = Factory::deterministic(seed);

    let key_a = fx.rsa("issuer", RsaSpec::rs256());
    println!(
        "First call  — private DER length : {} bytes",
        key_a.private_key_pkcs8_der().len()
    );

    // Same label + same spec → identical key (cache hit).
    let key_b = fx.rsa("issuer", RsaSpec::rs256());
    assert_eq!(key_a.private_key_pkcs8_pem(), key_b.private_key_pkcs8_pem());
    println!("Second call — same key (cached)  : ✓");

    // =========================================================================
    // 2. Different label → different key
    // =========================================================================
    println!("\n=== Label Isolation ===\n");

    let key_other = fx.rsa("verifier", RsaSpec::rs256());
    assert_ne!(
        key_a.private_key_pkcs8_pem(),
        key_other.private_key_pkcs8_pem()
    );
    println!("'issuer' vs 'verifier' → different keys : ✓");

    // =========================================================================
    // 3. Order-independent: interleaving calls doesn't change results
    // =========================================================================
    println!("\n=== Order Independence ===\n");

    // Create a fresh factory with the same seed.
    let fx2 = Factory::deterministic(Seed::from_env_value("my-test-seed-v1").unwrap());

    // Call in reverse order.
    let key_verifier = fx2.rsa("verifier", RsaSpec::rs256());
    let key_issuer = fx2.rsa("issuer", RsaSpec::rs256());

    assert_eq!(
        key_a.private_key_pkcs8_pem(),
        key_issuer.private_key_pkcs8_pem()
    );
    assert_eq!(
        key_other.private_key_pkcs8_pem(),
        key_verifier.private_key_pkcs8_pem()
    );
    println!("Reversed call order → same keys          : ✓");

    // =========================================================================
    // 4. Different seed → different keys
    // =========================================================================
    println!("\n=== Seed Isolation ===\n");

    let fx3 = Factory::deterministic(Seed::from_env_value("different-seed").unwrap());
    let key_diff = fx3.rsa("issuer", RsaSpec::rs256());
    assert_ne!(
        key_a.private_key_pkcs8_pem(),
        key_diff.private_key_pkcs8_pem()
    );
    println!("Different seed → different key            : ✓");

    // =========================================================================
    // 5. Cross-key-type independence
    // =========================================================================
    #[cfg(feature = "ecdsa")]
    {
        use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

        println!("\n=== Cross-Key-Type Independence ===\n");

        // Generating an ECDSA key with the same label doesn't affect the RSA key.
        let ec = fx.ecdsa("issuer", EcdsaSpec::es256());
        let rsa_again = fx.rsa("issuer", RsaSpec::rs256());
        assert_eq!(
            key_a.private_key_pkcs8_pem(),
            rsa_again.private_key_pkcs8_pem()
        );
        println!("ECDSA 'issuer' doesn't perturb RSA 'issuer' : ✓");
        println!(
            "ECDSA key DER length : {} bytes",
            ec.private_key_pkcs8_der().len()
        );
    }

    // =========================================================================
    // 6. Raw byte seed (e.g. from a CI hash)
    // =========================================================================
    println!("\n=== Raw Byte Seed ===\n");

    let byte_seed = Seed::new([42u8; 32]);
    let fx4 = Factory::deterministic(byte_seed);
    let key_bytes = fx4.rsa("from-bytes", RsaSpec::rs256());
    println!(
        "Byte-seed key DER length : {} bytes",
        key_bytes.private_key_pkcs8_der().len()
    );

    println!("\n=== All deterministic checks passed ===");
}

#[cfg(not(feature = "rsa"))]
fn main() {
    eprintln!("Enable 'rsa' feature:");
    eprintln!("  cargo run -p uselesskey --example deterministic --features full");
}
