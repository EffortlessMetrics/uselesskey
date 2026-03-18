//! Basic fixture generation for RSA, ECDSA, and Ed25519.
//!
//! Shows how to create a deterministic factory and generate keypairs for
//! all three asymmetric key types, accessing PEM, DER, and JWK outputs.
//!
//! Run with: cargo run -p uselesskey --example basic_usage --features "ecdsa,ed25519,rsa,jwk"

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn main() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, RsaFactoryExt,
        RsaSpec, Seed,
    };

    // Create a deterministic factory so output is reproducible across runs.
    let seed = Seed::from_env_value("basic-usage-demo").unwrap();
    let fx = Factory::deterministic(seed);

    // =========================================================================
    // 1. RSA (RS256) — 2048-bit keypair
    // =========================================================================
    println!("=== RSA (RS256) ===\n");

    let rsa = fx.rsa("auth-service", RsaSpec::rs256());

    println!(
        "  Private PEM header : {}",
        rsa.private_key_pkcs8_pem().lines().next().unwrap_or("")
    );
    println!(
        "  Private PEM length : {} bytes",
        rsa.private_key_pkcs8_pem().len()
    );
    println!(
        "  Private DER length : {} bytes",
        rsa.private_key_pkcs8_der().len()
    );
    println!(
        "  Public PEM header  : {}",
        rsa.public_key_spki_pem().lines().next().unwrap_or("")
    );
    println!(
        "  Public DER length  : {} bytes",
        rsa.public_key_spki_der().len()
    );

    let rsa_jwk = rsa.public_jwk().to_value();
    println!("  JWK kty={}, alg={}", rsa_jwk["kty"], rsa_jwk["alg"]);
    println!("  kid={}", rsa.kid());

    // =========================================================================
    // 2. ECDSA — P-256 (ES256) and P-384 (ES384)
    // =========================================================================
    println!("\n=== ECDSA P-256 (ES256) ===\n");

    let ec256 = fx.ecdsa("token-signer", EcdsaSpec::es256());

    println!(
        "  Private PEM length : {} bytes",
        ec256.private_key_pkcs8_pem().len()
    );
    println!(
        "  Private DER length : {} bytes",
        ec256.private_key_pkcs8_der().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        ec256.public_key_spki_der().len()
    );

    let ec_jwk = ec256.public_jwk().to_value();
    println!(
        "  JWK kty={}, crv={}, alg={}",
        ec_jwk["kty"], ec_jwk["crv"], ec_jwk["alg"]
    );
    println!("  kid={}", ec256.kid());

    println!("\n=== ECDSA P-384 (ES384) ===\n");

    let ec384 = fx.ecdsa("token-signer-384", EcdsaSpec::es384());

    println!(
        "  Private DER length : {} bytes",
        ec384.private_key_pkcs8_der().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        ec384.public_key_spki_der().len()
    );

    let ec384_jwk = ec384.public_jwk().to_value();
    println!(
        "  JWK kty={}, crv={}, alg={}",
        ec384_jwk["kty"], ec384_jwk["crv"], ec384_jwk["alg"]
    );

    // =========================================================================
    // 3. Ed25519 (EdDSA) — compact keys
    // =========================================================================
    println!("\n=== Ed25519 (EdDSA) ===\n");

    let ed = fx.ed25519("signing-key", Ed25519Spec::default());

    println!(
        "  Private PEM length : {} bytes",
        ed.private_key_pkcs8_pem().len()
    );
    println!(
        "  Private DER length : {} bytes",
        ed.private_key_pkcs8_der().len()
    );
    println!(
        "  Public DER length  : {} bytes",
        ed.public_key_spki_der().len()
    );

    let ed_jwk = ed.public_jwk().to_value();
    println!(
        "  JWK kty={}, crv={}, alg={}",
        ed_jwk["kty"], ed_jwk["crv"], ed_jwk["alg"]
    );
    println!("  kid={}", ed.kid());

    // =========================================================================
    // 4. Caching: same label + spec → same key
    // =========================================================================
    println!("\n=== Cache Verification ===\n");

    let rsa_again = fx.rsa("auth-service", RsaSpec::rs256());
    assert_eq!(
        rsa.private_key_pkcs8_pem(),
        rsa_again.private_key_pkcs8_pem()
    );
    println!("  RSA cache hit     : ✓");

    let ec_again = fx.ecdsa("token-signer", EcdsaSpec::es256());
    assert_eq!(
        ec256.private_key_pkcs8_pem(),
        ec_again.private_key_pkcs8_pem()
    );
    println!("  ECDSA cache hit   : ✓");

    let ed_again = fx.ed25519("signing-key", Ed25519Spec::default());
    assert_eq!(ed.private_key_pkcs8_pem(), ed_again.private_key_pkcs8_pem());
    println!("  Ed25519 cache hit : ✓");

    // =========================================================================
    // 5. Tempfile output (auto-cleaned on drop)
    // =========================================================================
    println!("\n=== Tempfile Output ===\n");

    let temp = rsa.write_private_key_pkcs8_pem().expect("write tempfile");
    println!("  Tempfile path   : {}", temp.path().display());
    println!("  Tempfile exists : {}", temp.path().exists());

    println!("\n=== All basic usage checks passed ===");
}

#[cfg(not(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
)))]
fn main() {
    eprintln!("Enable required features:");
    eprintln!(
        "  cargo run -p uselesskey --example basic_usage --features \"ecdsa,ed25519,rsa,jwk\""
    );
}
