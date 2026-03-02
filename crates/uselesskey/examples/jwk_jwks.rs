//! JWK and JWKS generation across all key types.
//!
//! Demonstrates building JWK Sets from multiple key types using JwksBuilder,
//! and inspecting individual JWK metadata without printing key material.
//!
//! Run with: cargo run -p uselesskey --example jwk_jwks --features full

#[cfg(all(
    feature = "jwk",
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
fn main() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
        HmacSpec, RsaFactoryExt, RsaSpec, Seed,
    };

    let fx = Factory::deterministic(Seed::from_env_value("jwk-demo").unwrap());

    // =========================================================================
    // 1. Individual JWKs from each key type
    // =========================================================================
    println!("=== Individual JWKs ===\n");

    let rsa = fx.rsa("auth", RsaSpec::rs256());
    let rsa_jwk = rsa.public_jwk().to_value();
    println!("RSA (RS256):");
    println!(
        "  kty={}, alg={}, kid={}",
        rsa_jwk["kty"],
        rsa_jwk["alg"],
        rsa.kid()
    );

    let ec256 = fx.ecdsa("auth-ec", EcdsaSpec::es256());
    let ec_jwk = ec256.public_jwk().to_value();
    println!("ECDSA (ES256):");
    println!(
        "  kty={}, crv={}, alg={}, kid={}",
        ec_jwk["kty"],
        ec_jwk["crv"],
        ec_jwk["alg"],
        ec256.kid()
    );

    let ec384 = fx.ecdsa("auth-ec384", EcdsaSpec::es384());
    let ec384_jwk = ec384.public_jwk().to_value();
    println!("ECDSA (ES384):");
    println!(
        "  kty={}, crv={}, alg={}, kid={}",
        ec384_jwk["kty"],
        ec384_jwk["crv"],
        ec384_jwk["alg"],
        ec384.kid()
    );

    let ed = fx.ed25519("auth-ed", Ed25519Spec::default());
    let ed_jwk = ed.public_jwk().to_value();
    println!("Ed25519 (EdDSA):");
    println!(
        "  kty={}, crv={}, alg={}, kid={}",
        ed_jwk["kty"],
        ed_jwk["crv"],
        ed_jwk["alg"],
        ed.kid()
    );

    let hmac = fx.hmac("auth-hmac", HmacSpec::hs256());
    let hmac_jwk = hmac.jwk().to_value();
    println!("HMAC (HS256):");
    println!(
        "  kty={}, alg={}, kid={}",
        hmac_jwk["kty"],
        hmac_jwk["alg"],
        hmac.kid()
    );

    // =========================================================================
    // 2. Build a multi-key JWKS with JwksBuilder
    // =========================================================================
    println!("\n=== Multi-Key JWKS (public keys only) ===\n");

    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(ec256.public_jwk())
        .add_public(ec384.public_jwk())
        .add_public(ed.public_jwk())
        .build();

    let jwks_val = jwks.to_value();
    let keys = jwks_val["keys"].as_array().unwrap();
    println!("JWKS contains {} public keys:", keys.len());
    for key in keys {
        println!(
            "  kid={:<20} kty={:<4} alg={}",
            key["kid"].as_str().unwrap_or("?"),
            key["kty"].as_str().unwrap_or("?"),
            key["alg"].as_str().unwrap_or("?"),
        );
    }

    // JwksBuilder sorts keys by kid for deterministic output.
    let kids: Vec<&str> = keys.iter().filter_map(|k| k["kid"].as_str()).collect();
    let mut sorted_kids = kids.clone();
    sorted_kids.sort();
    assert_eq!(kids, sorted_kids, "JWKS keys should be sorted by kid");
    println!("\n✓ Keys are sorted by kid (deterministic ordering)");

    // =========================================================================
    // 3. Per-key JWKS (single-key sets)
    // =========================================================================
    println!("\n=== Per-Key JWKS ===\n");

    let rsa_jwks = rsa.public_jwks().to_value();
    let ec_jwks = ec256.public_jwks().to_value();
    let ed_jwks = ed.public_jwks().to_value();
    let hmac_jwks = hmac.jwks().to_value();

    println!(
        "RSA JWKS     : {} key(s)",
        rsa_jwks["keys"].as_array().unwrap().len()
    );
    println!(
        "ECDSA JWKS   : {} key(s)",
        ec_jwks["keys"].as_array().unwrap().len()
    );
    println!(
        "Ed25519 JWKS : {} key(s)",
        ed_jwks["keys"].as_array().unwrap().len()
    );
    println!(
        "HMAC JWKS    : {} key(s)",
        hmac_jwks["keys"].as_array().unwrap().len()
    );

    // =========================================================================
    // 4. JWKS as a JSON string (for mock servers)
    // =========================================================================
    println!("\n=== JWKS JSON for Mock Servers ===\n");

    let json_str = jwks.to_string();
    println!("JSON length: {} bytes", json_str.len());
    println!("Content-Type: application/json");
    println!("Serve at: GET /.well-known/jwks.json");

    println!("\n=== All JWK/JWKS examples passed ===");
}

#[cfg(not(all(
    feature = "jwk",
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
)))]
fn main() {
    eprintln!("Enable all key features + jwk:");
    eprintln!("  cargo run -p uselesskey --example jwk_jwks --features full");
}
