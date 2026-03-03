//! Order-independent deterministic mode with seeds.
//!
//! Demonstrates the core deterministic derivation guarantee: the same seed,
//! label, and spec always produce the same key — regardless of the order in
//! which fixtures are requested.
//!
//! Run with: cargo run -p uselesskey --example deterministic_mode --features full

#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
fn main() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, RsaFactoryExt,
        RsaSpec, Seed,
    };

    // =========================================================================
    // 1. Deterministic factory from a string seed
    // =========================================================================
    println!("=== Deterministic Mode ===\n");

    let seed = Seed::from_env_value("demo-seed-v1").unwrap();
    let fx = Factory::deterministic(seed);

    // Generate three different key types.
    let rsa_key = fx.rsa("issuer", RsaSpec::rs256());
    let ec_key = fx.ecdsa("issuer", EcdsaSpec::es256());
    let ed_key = fx.ed25519("issuer", Ed25519Spec::default());

    println!(
        "RSA     private DER : {} bytes",
        rsa_key.private_key_pkcs8_der().len()
    );
    println!(
        "ECDSA   private DER : {} bytes",
        ec_key.private_key_pkcs8_der().len()
    );
    println!(
        "Ed25519 private DER : {} bytes",
        ed_key.private_key_pkcs8_der().len()
    );

    // =========================================================================
    // 2. Same label + spec → cache hit
    // =========================================================================
    println!("\n=== Cache Identity ===\n");

    let rsa_again = fx.rsa("issuer", RsaSpec::rs256());
    assert_eq!(
        rsa_key.private_key_pkcs8_pem(),
        rsa_again.private_key_pkcs8_pem()
    );
    println!("Same label + spec → identical key : ✓");

    // =========================================================================
    // 3. Different label → different key
    // =========================================================================
    println!("\n=== Label Isolation ===\n");

    let rsa_other = fx.rsa("verifier", RsaSpec::rs256());
    assert_ne!(
        rsa_key.private_key_pkcs8_pem(),
        rsa_other.private_key_pkcs8_pem()
    );
    println!("'issuer' vs 'verifier' → different keys : ✓");

    // =========================================================================
    // 4. Order independence: reversed call order → same results
    // =========================================================================
    println!("\n=== Order Independence ===\n");

    // Create a fresh factory with the same seed.
    let fx2 = Factory::deterministic(Seed::from_env_value("demo-seed-v1").unwrap());

    // Request keys in reverse order.
    let ed_rev = fx2.ed25519("issuer", Ed25519Spec::default());
    let ec_rev = fx2.ecdsa("issuer", EcdsaSpec::es256());
    let rsa_rev = fx2.rsa("issuer", RsaSpec::rs256());

    assert_eq!(
        rsa_key.private_key_pkcs8_pem(),
        rsa_rev.private_key_pkcs8_pem()
    );
    assert_eq!(
        ec_key.private_key_pkcs8_pem(),
        ec_rev.private_key_pkcs8_pem()
    );
    assert_eq!(
        ed_key.private_key_pkcs8_pem(),
        ed_rev.private_key_pkcs8_pem()
    );
    println!("Reversed call order → same RSA key     : ✓");
    println!("Reversed call order → same ECDSA key   : ✓");
    println!("Reversed call order → same Ed25519 key : ✓");

    // =========================================================================
    // 5. Cross-key-type independence
    // =========================================================================
    println!("\n=== Cross-Key-Type Independence ===\n");

    // An ECDSA key with the same label does not affect the RSA key's derivation.
    let fx3 = Factory::deterministic(Seed::from_env_value("demo-seed-v1").unwrap());
    let rsa_only = fx3.rsa("issuer", RsaSpec::rs256());
    assert_eq!(
        rsa_key.private_key_pkcs8_pem(),
        rsa_only.private_key_pkcs8_pem()
    );
    println!("ECDSA 'issuer' doesn't perturb RSA 'issuer' : ✓");

    // =========================================================================
    // 6. Different seed → different keys
    // =========================================================================
    println!("\n=== Seed Isolation ===\n");

    let fx_other = Factory::deterministic(Seed::from_env_value("different-seed").unwrap());
    let rsa_diff = fx_other.rsa("issuer", RsaSpec::rs256());
    assert_ne!(
        rsa_key.private_key_pkcs8_pem(),
        rsa_diff.private_key_pkcs8_pem()
    );
    println!("Different seed → different key : ✓");

    // =========================================================================
    // 7. Raw byte seed (e.g. from a CI hash or HMAC)
    // =========================================================================
    println!("\n=== Raw Byte Seed ===\n");

    let byte_seed = Seed::new([42u8; 32]);
    let fx_bytes = Factory::deterministic(byte_seed);
    let rsa_bytes = fx_bytes.rsa("from-bytes", RsaSpec::rs256());
    println!(
        "Byte-seed key DER length : {} bytes",
        rsa_bytes.private_key_pkcs8_der().len()
    );

    println!("\n=== All deterministic mode checks passed ===");
}

#[cfg(not(all(feature = "rsa", feature = "ecdsa", feature = "ed25519")))]
fn main() {
    eprintln!("Enable required features:");
    eprintln!("  cargo run -p uselesskey --example deterministic_mode --features full");
}
